mod cli;
mod docker;
mod error;
mod manifest;
mod output;
mod state;

use std::net::Ipv4Addr;

use clap::Parser;

use cli::{Cli, Commands};
use docker::DockerManager;
use error::{Result, VulnPkgError};
use manifest::{Manifest, PackageType};
use output::Output;
use state::{ImageSource, StateManager};

/// Generate a sslip.io domain from an IP address for zero-config DNS resolution
/// e.g., 127.0.0.1 -> "127.0.0.1.sslip.io"
fn sslip_domain(ip: Ipv4Addr) -> String {
    format!("{}.sslip.io", ip)
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();
    let output = Output::new(cli.json);

    if let Err(e) = run(cli, &output).await {
        output.error(&e.to_string());
        std::process::exit(1);
    }
}

async fn run(cli: Cli, output: &Output) -> Result<()> {
    // Initialize state directory
    let state_mgr = StateManager::new()?;
    state_mgr.init()?;

    // Resolve domain: use provided domain or generate sslip.io domain for zero-config
    let domain = cli.domain.unwrap_or_else(|| sslip_domain(cli.resolve_address));

    match cli.command {
        Commands::List => cmd_list(&cli.manifest_url, &state_mgr, output).await,
        Commands::Install { app } => cmd_install(&app, &cli.manifest_url, &state_mgr, output).await,
        Commands::Run { app } => {
            cmd_run(&app, &cli.manifest_url, &state_mgr, output, &domain, cli.https).await
        }
        Commands::Stop { app } => cmd_stop(&app, &state_mgr, output).await,
        Commands::Remove { app, purge } => {
            cmd_remove(&app, &state_mgr, output, purge).await
        }
        Commands::Rebuild { app } => {
            cmd_rebuild(&app, &cli.manifest_url, &state_mgr, output).await
        }
        Commands::Status => cmd_status(&state_mgr, output).await,
    }
}

async fn fetch_manifest(url: &str, state_mgr: &StateManager, output: &Output) -> Result<Manifest> {
    output.info(&format!("Fetching manifest from {}", url));

    let manifest = Manifest::fetch(url).await?;

    // Warn if unsigned
    if !manifest.is_signed() {
        output.warning("Manifest is unsigned. In production, only use signed manifests.");
    }

    // Cache the manifest
    let yaml = serde_yaml::to_string(&manifest)?;
    state_mgr.cache_manifest(url, &yaml)?;

    output.success(&format!("Loaded {} applications", manifest.apps.len()));
    Ok(manifest)
}

async fn cmd_list(manifest_url: &str, state_mgr: &StateManager, output: &Output) -> Result<()> {
    let manifest = fetch_manifest(manifest_url, state_mgr, output).await?;
    let state = state_mgr.load_state()?;

    output.list_apps(&manifest.apps, &state.apps);
    Ok(())
}

async fn cmd_install(
    app_name: &str,
    manifest_url: &str,
    state_mgr: &StateManager,
    output: &Output,
) -> Result<()> {
    let manifest = fetch_manifest(manifest_url, state_mgr, output).await?;

    let app = manifest
        .find_app(app_name)
        .ok_or_else(|| VulnPkgError::AppNotFound(app_name.to_string()))?;

    let docker = DockerManager::new()?;
    let effective_image = app.effective_image();

    // Handle different package types
    let (image_source, git_commit) = match app.package_type {
        PackageType::Prebuilt => {
            // Pull image if needed
            if !docker.image_exists(&effective_image).await? {
                docker.pull_image(&effective_image, output).await?;
            } else {
                output.info(&format!("Image {} already exists", effective_image));
            }
            (ImageSource::Prebuilt, None)
        }
        PackageType::Dockerfile => {
            // Build from Dockerfile
            if let Some(ref dockerfile) = app.dockerfile {
                // Inline Dockerfile
                docker
                    .build_from_dockerfile(dockerfile, &effective_image, output)
                    .await?;
            } else if let Some(ref url) = app.dockerfile_url {
                // Remote Dockerfile
                docker
                    .build_from_dockerfile_url(
                        url,
                        app.context_url.as_deref(),
                        &effective_image,
                        output,
                    )
                    .await?;
            }
            (ImageSource::Dockerfile, None)
        }
        PackageType::Git => {
            // Build from git repository
            let repo = app
                .repo
                .as_ref()
                .ok_or_else(|| VulnPkgError::ManifestValidation(
                    format!("Git app '{}' missing repo field", app_name)
                ))?;

            let commit = docker
                .build_from_git(
                    repo,
                    app.git_ref.as_deref(),
                    app.dockerfile_path.as_deref(),
                    &effective_image,
                    state_mgr,
                    output,
                )
                .await?;
            (ImageSource::Git, commit)
        }
    };

    // Update state with build metadata
    let mut state = state_mgr.load_state()?;
    let app_state = state.apps.entry(app.name.clone()).or_default();
    app_state.installed = true;
    app_state.image_source = image_source;
    app_state.image_tag = Some(effective_image);
    app_state.git_commit = git_commit;
    app_state.built_at = Some(chrono::Utc::now().to_rfc3339());
    state_mgr.save_state(&state)?;

    output.app_installed(app);
    Ok(())
}

async fn cmd_run(
    app_name: &str,
    manifest_url: &str,
    state_mgr: &StateManager,
    output: &Output,
    domain: &str,
    https: bool,
) -> Result<()> {
    let manifest = fetch_manifest(manifest_url, state_mgr, output).await?;

    let app = manifest
        .find_app(app_name)
        .ok_or_else(|| VulnPkgError::AppNotFound(app_name.to_string()))?;

    let mut state = state_mgr.load_state()?;

    // Check if already running
    if let Some(app_state) = state.apps.get(&app.name) {
        if app_state.running {
            if let Some(ref container_id) = app_state.container_id {
                let docker = DockerManager::new()?;
                if docker.container_running(container_id).await? {
                    return Err(VulnPkgError::AppAlreadyRunning(app_name.to_string()));
                }
            }
        }
    }

    let docker = DockerManager::new()?;
    let effective_image = app.effective_image();

    // Ensure image exists (install if needed)
    if !docker.image_exists(&effective_image).await? {
        // Delegate to install logic for building/pulling
        cmd_install(app_name, manifest_url, state_mgr, output).await?;
        // Reload state after install
        state = state_mgr.load_state()?;
    }

    // Ensure network exists
    output.info("Ensuring vuln-pkg network exists");
    let network_id = docker.ensure_network().await?;
    state.network_id = Some(network_id.clone());

    // Ensure Traefik is running
    if docker.is_traefik_running().await?.is_none() {
        output.info("Starting Traefik reverse proxy");
        let traefik_id = docker.start_traefik(&network_id, domain, https, output).await?;
        state.traefik_container_id = Some(traefik_id);
        output.success(&format!("Traefik running (dashboard: http://traefik.{})", domain));
    }

    // Create and start container with Traefik labels
    output.info(&format!("Creating container for {}", app.name));
    let (container_id, hostnames) = docker.create_container(app, &network_id, domain, https).await?;

    output.info("Starting container");
    docker.start_container(&container_id).await?;

    // Update state
    let app_state = state.apps.entry(app.name.clone()).or_default();
    app_state.installed = true;
    app_state.running = true;
    app_state.container_id = Some(container_id);
    app_state.hostnames = hostnames.clone();
    state_mgr.save_state(&state)?;

    output.app_running(app, &hostnames, domain, https);

    Ok(())
}

async fn cmd_stop(
    app_name: &str,
    state_mgr: &StateManager,
    output: &Output,
) -> Result<()> {
    let mut state = state_mgr.load_state()?;

    let app_state = state
        .apps
        .get(app_name)
        .ok_or_else(|| VulnPkgError::AppNotInstalled(app_name.to_string()))?;

    if !app_state.running {
        return Err(VulnPkgError::AppNotRunning(app_name.to_string()));
    }

    let container_id = app_state
        .container_id
        .clone()
        .ok_or_else(|| VulnPkgError::AppNotRunning(app_name.to_string()))?;

    let docker = DockerManager::new()?;

    output.info(&format!("Stopping container {}", &container_id[..12.min(container_id.len())]));

    if docker.container_running(&container_id).await? {
        docker.stop_container(&container_id).await?;
    }

    // Update state
    let app_state = state.apps.get_mut(app_name).unwrap();
    app_state.running = false;
    state_mgr.save_state(&state)?;

    output.app_stopped(app_name);
    Ok(())
}

async fn cmd_remove(
    app_name: &str,
    state_mgr: &StateManager,
    output: &Output,
    purge: bool,
) -> Result<()> {
    let mut state = state_mgr.load_state()?;

    let app_state = state
        .apps
        .get(app_name)
        .ok_or_else(|| VulnPkgError::AppNotInstalled(app_name.to_string()))?;

    let docker = DockerManager::new()?;

    // Stop and remove container if exists
    if let Some(ref container_id) = app_state.container_id {
        let short_id = &container_id[..12.min(container_id.len())];
        output.info(&format!("Stopping container {}", short_id));

        if docker.container_running(container_id).await? {
            docker.stop_container(container_id).await?;
        }

        output.info("Removing container");
        docker.remove_container(container_id).await?;
    }

    // Remove image if purge requested
    if purge {
        output.warning("Image removal not implemented yet with --purge");
    }

    // Update state
    state.apps.remove(app_name);

    // Check if this was the last app - if so, stop Traefik
    let running_apps = docker.count_running_apps().await?;
    if running_apps == 0 {
        output.info("No more apps running, stopping Traefik");
        docker.stop_traefik().await?;
        state.traefik_container_id = None;
    }

    state_mgr.save_state(&state)?;

    output.app_removed(app_name);
    Ok(())
}

async fn cmd_rebuild(
    app_name: &str,
    manifest_url: &str,
    state_mgr: &StateManager,
    output: &Output,
) -> Result<()> {
    let manifest = fetch_manifest(manifest_url, state_mgr, output).await?;

    let app = manifest
        .find_app(app_name)
        .ok_or_else(|| VulnPkgError::AppNotFound(app_name.to_string()))?;

    // Only custom packages can be rebuilt
    if app.package_type == PackageType::Prebuilt {
        return Err(VulnPkgError::AppNotRebuildable(app_name.to_string()));
    }

    let docker = DockerManager::new()?;
    let effective_image = app.effective_image();

    output.info(&format!("Rebuilding {}", app_name));

    // Perform the build based on package type
    let git_commit = match app.package_type {
        PackageType::Prebuilt => unreachable!(),
        PackageType::Dockerfile => {
            if let Some(ref dockerfile) = app.dockerfile {
                docker
                    .build_from_dockerfile(dockerfile, &effective_image, output)
                    .await?;
            } else if let Some(ref url) = app.dockerfile_url {
                docker
                    .build_from_dockerfile_url(
                        url,
                        app.context_url.as_deref(),
                        &effective_image,
                        output,
                    )
                    .await?;
            }
            None
        }
        PackageType::Git => {
            let repo = app.repo.as_ref().ok_or_else(|| {
                VulnPkgError::ManifestValidation(format!(
                    "Git app '{}' missing repo field",
                    app_name
                ))
            })?;

            docker
                .build_from_git(
                    repo,
                    app.git_ref.as_deref(),
                    app.dockerfile_path.as_deref(),
                    &effective_image,
                    state_mgr,
                    output,
                )
                .await?
        }
    };

    // Update state with new build timestamp
    let mut state = state_mgr.load_state()?;
    let app_state = state.apps.entry(app.name.clone()).or_default();
    app_state.git_commit = git_commit;
    app_state.built_at = Some(chrono::Utc::now().to_rfc3339());
    state_mgr.save_state(&state)?;

    output.success(&format!("Rebuilt {}", app_name));
    Ok(())
}

async fn cmd_status(state_mgr: &StateManager, output: &Output) -> Result<()> {
    let state = state_mgr.load_state()?;
    let docker = DockerManager::new()?;

    let mut status_info: Vec<(String, bool, Option<String>, Vec<String>)> = Vec::new();

    for (name, app_state) in &state.apps {
        let running = if let Some(ref container_id) = app_state.container_id {
            docker.container_running(container_id).await.unwrap_or(false)
        } else {
            false
        };

        status_info.push((
            name.clone(),
            running,
            app_state.container_id.clone(),
            app_state.hostnames.clone(),
        ));
    }

    output.status(&status_info);
    Ok(())
}
