use std::collections::HashMap;
use std::path::Path;

use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::image::{BuildImageOptions, CreateImageOptions};
use bollard::models::{EndpointSettings, HostConfig, Mount, MountTypeEnum, PortBinding};
use bollard::network::{CreateNetworkOptions, ListNetworksOptions};
use flate2::Compression;
use flate2::write::GzEncoder;
use futures::StreamExt;
use git2::Repository;
use tar::Builder;

use crate::error::{Result, VulnPkgError};
use crate::manifest::App;
use crate::output::Output;
use crate::state::StateManager;

const CONTAINER_LABEL: &str = "vuln-pkg";
const NETWORK_NAME: &str = "vuln-pkg";
const TRAEFIK_IMAGE: &str = "traefik:v3.0";
const TRAEFIK_CONTAINER: &str = "vuln-pkg-traefik";

pub struct DockerManager {
    docker: Docker,
}

impl DockerManager {
    pub fn new() -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        Ok(Self { docker })
    }

    // ==================== Network Management ====================

    pub async fn ensure_network(&self) -> Result<String> {
        // Check if network already exists
        let mut filters = HashMap::new();
        filters.insert("name", vec![NETWORK_NAME]);

        let options = ListNetworksOptions { filters };
        let networks = self.docker.list_networks(Some(options)).await?;

        for network in networks {
            if network.name.as_deref() == Some(NETWORK_NAME)
                && let Some(id) = network.id
            {
                return Ok(id);
            }
        }

        // Create network if it doesn't exist
        self.create_network().await
    }

    pub async fn create_network(&self) -> Result<String> {
        let options = CreateNetworkOptions {
            name: NETWORK_NAME,
            driver: "bridge",
            ..Default::default()
        };

        let response = self.docker.create_network(options).await?;
        Ok(response.id)
    }

    #[allow(dead_code)]
    pub async fn remove_network(&self, network_id: &str) -> Result<()> {
        self.docker.remove_network(network_id).await?;
        Ok(())
    }

    // ==================== Traefik Management ====================

    pub async fn is_traefik_running(&self) -> Result<Option<String>> {
        let mut filters = HashMap::new();
        filters.insert("name", vec![TRAEFIK_CONTAINER]);

        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(options)).await?;

        for container in containers {
            if let Some(names) = &container.names
                && names
                    .iter()
                    .any(|n| n == &format!("/{}", TRAEFIK_CONTAINER))
            {
                let running = container.state.as_deref() == Some("running");
                if running {
                    return Ok(container.id);
                } else {
                    // Container exists but not running - remove and recreate
                    if let Some(id) = &container.id {
                        self.remove_container(id).await?;
                    }
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }

    pub async fn start_traefik(
        &self,
        network_id: &str,
        domain: &str,
        https: bool,
        output: &Output,
    ) -> Result<String> {
        // Check if already running
        if let Some(id) = self.is_traefik_running().await? {
            return Ok(id);
        }

        // Pull image if needed
        if !self.image_exists(TRAEFIK_IMAGE).await? {
            self.pull_image(TRAEFIK_IMAGE, output).await?;
        }

        // Build Traefik command arguments
        let mut cmd = vec![
            "--api.dashboard=true".to_string(),
            "--api.insecure=true".to_string(),
            "--providers.docker=true".to_string(),
            "--providers.docker.exposedbydefault=false".to_string(),
            format!("--providers.docker.network={}", NETWORK_NAME),
            "--entrypoints.web.address=:80".to_string(),
        ];

        if https {
            cmd.push("--entrypoints.websecure.address=:443".to_string());
        }

        // Port bindings
        let mut port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
        port_bindings.insert(
            "80/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some("80".to_string()),
            }]),
        );

        if https {
            port_bindings.insert(
                "443/tcp".to_string(),
                Some(vec![PortBinding {
                    host_ip: Some("0.0.0.0".to_string()),
                    host_port: Some("443".to_string()),
                }]),
            );
        }

        // Mount Docker socket
        let mounts = vec![Mount {
            target: Some("/var/run/docker.sock".to_string()),
            source: Some("/var/run/docker.sock".to_string()),
            typ: Some(MountTypeEnum::BIND),
            read_only: Some(true),
            ..Default::default()
        }];

        let host_config = HostConfig {
            port_bindings: Some(port_bindings),
            mounts: Some(mounts),
            ..Default::default()
        };

        // Labels for dashboard routing
        let mut labels = HashMap::new();
        labels.insert(CONTAINER_LABEL.to_string(), "traefik".to_string());
        labels.insert("traefik.enable".to_string(), "true".to_string());
        labels.insert(
            "traefik.http.routers.traefik-dashboard.rule".to_string(),
            format!("Host(`traefik.{}`)", domain),
        );
        labels.insert(
            "traefik.http.routers.traefik-dashboard.service".to_string(),
            "api@internal".to_string(),
        );

        // Network config
        let mut endpoints_config = HashMap::new();
        endpoints_config.insert(
            NETWORK_NAME.to_string(),
            EndpointSettings {
                network_id: Some(network_id.to_string()),
                ..Default::default()
            },
        );

        let config = Config {
            image: Some(TRAEFIK_IMAGE.to_string()),
            cmd: Some(cmd),
            host_config: Some(host_config),
            labels: Some(labels),
            networking_config: Some(bollard::container::NetworkingConfig { endpoints_config }),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: TRAEFIK_CONTAINER,
            platform: None,
        };

        let response = self.docker.create_container(Some(options), config).await?;
        self.start_container(&response.id).await?;

        Ok(response.id)
    }

    pub async fn stop_traefik(&self) -> Result<()> {
        if let Some(id) = self.is_traefik_running().await? {
            self.stop_container(&id).await?;
            self.remove_container(&id).await?;
        }
        Ok(())
    }

    // ==================== Image Management ====================

    pub async fn pull_image(&self, image: &str, output: &Output) -> Result<()> {
        output.info(&format!("Pulling image: {}", image));

        let options = CreateImageOptions {
            from_image: image,
            ..Default::default()
        };

        let mut stream = self.docker.create_image(Some(options), None, None);

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = info.status {
                        output.debug(&status);
                    }
                }
                Err(e) => return Err(VulnPkgError::Docker(e)),
            }
        }

        output.success(&format!("Image pulled: {}", image));
        Ok(())
    }

    pub async fn image_exists(&self, image: &str) -> Result<bool> {
        match self.docker.inspect_image(image).await {
            Ok(_) => Ok(true),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(VulnPkgError::Docker(e)),
        }
    }

    #[allow(dead_code)]
    pub async fn remove_image(&self, image: &str) -> Result<()> {
        self.docker.remove_image(image, None, None).await?;
        Ok(())
    }

    // ==================== Image Building ====================

    /// Build an image from inline Dockerfile content
    pub async fn build_from_dockerfile(
        &self,
        dockerfile_content: &str,
        image_tag: &str,
        output: &Output,
    ) -> Result<()> {
        output.info(&format!("Building image: {}", image_tag));

        let tar_bytes = Self::create_dockerfile_tarball(dockerfile_content)?;
        self.build_image_from_tarball(&tar_bytes, image_tag, "Dockerfile", output)
            .await
    }

    /// Build an image from a remote Dockerfile URL with optional context
    pub async fn build_from_dockerfile_url(
        &self,
        dockerfile_url: &str,
        context_url: Option<&str>,
        image_tag: &str,
        output: &Output,
    ) -> Result<()> {
        output.info(&format!("Fetching Dockerfile from: {}", dockerfile_url));

        // Fetch the Dockerfile
        let dockerfile_content = reqwest::get(dockerfile_url)
            .await
            .map_err(|e| VulnPkgError::DockerfileFetch {
                url: dockerfile_url.to_string(),
                source: e,
            })?
            .text()
            .await
            .map_err(|e| VulnPkgError::DockerfileFetch {
                url: dockerfile_url.to_string(),
                source: e,
            })?;

        let tar_bytes = if let Some(ctx_url) = context_url {
            output.info(&format!("Fetching build context from: {}", ctx_url));
            Self::fetch_and_merge_context(&dockerfile_content, ctx_url).await?
        } else {
            Self::create_dockerfile_tarball(&dockerfile_content)?
        };

        output.info(&format!("Building image: {}", image_tag));
        self.build_image_from_tarball(&tar_bytes, image_tag, "Dockerfile", output)
            .await
    }

    /// Build an image from a cloned Git repository
    pub async fn build_from_git(
        &self,
        repo_url: &str,
        git_ref: Option<&str>,
        dockerfile_path: Option<&str>,
        image_tag: &str,
        state_mgr: &StateManager,
        output: &Output,
    ) -> Result<Option<String>> {
        output.info(&format!("Cloning repository: {}", repo_url));

        // Clone to a directory under ~/.vuln-pkg/repos/
        let repo_name = Self::sanitize_repo_name(repo_url);
        let clone_dir = state_mgr.repos_dir().join(&repo_name);

        // Clone or open existing repository
        let repo = Self::clone_or_open_repo(repo_url, &clone_dir)?;

        // Checkout the specified ref if provided
        if let Some(ref_name) = git_ref {
            output.info(&format!("Checking out: {}", ref_name));
            Self::checkout_ref(&repo, ref_name)?;
        }

        // Get current commit SHA
        let commit_sha = repo
            .head()
            .ok()
            .and_then(|h| h.target())
            .map(|oid| oid.to_string());

        let dockerfile_path = dockerfile_path.unwrap_or("Dockerfile");
        output.info(&format!("Building from {}", dockerfile_path));

        // Create tarball from the repo directory
        let tar_bytes = Self::create_context_tarball(&clone_dir, dockerfile_path)?;

        output.info(&format!("Building image: {}", image_tag));
        self.build_image_from_tarball(&tar_bytes, image_tag, dockerfile_path, output)
            .await?;

        Ok(commit_sha)
    }

    /// Core build method using bollard
    async fn build_image_from_tarball(
        &self,
        tar_bytes: &[u8],
        image_tag: &str,
        dockerfile_path: &str,
        output: &Output,
    ) -> Result<()> {
        let options = BuildImageOptions {
            dockerfile: dockerfile_path,
            t: image_tag,
            rm: true,
            forcerm: true,
            ..Default::default()
        };

        let mut stream = self
            .docker
            .build_image(options, None, Some(tar_bytes.to_vec().into()));

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(stream_text) = info.stream {
                        let text = stream_text.trim();
                        if !text.is_empty() {
                            output.debug(text);
                        }
                    }
                    if let Some(error) = info.error {
                        return Err(VulnPkgError::ImageBuild {
                            image: image_tag.to_string(),
                            message: error,
                        });
                    }
                }
                Err(e) => return Err(VulnPkgError::Docker(e)),
            }
        }

        output.success(&format!("Image built: {}", image_tag));
        Ok(())
    }

    // ==================== Build Helpers ====================

    /// Create a tarball containing just a Dockerfile
    fn create_dockerfile_tarball(dockerfile_content: &str) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        {
            let encoder = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = Builder::new(encoder);

            let dockerfile_bytes = dockerfile_content.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(dockerfile_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "Dockerfile", dockerfile_bytes)?;

            tar.finish()?;
        }
        Ok(buf)
    }

    /// Create a tarball from a directory (for Git repos)
    fn create_context_tarball(dir: &Path, _dockerfile_path: &str) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        {
            let encoder = GzEncoder::new(&mut buf, Compression::default());
            let mut tar = Builder::new(encoder);

            // Recursively add all files from the directory
            tar.append_dir_all(".", dir)?;
            tar.finish()?;
        }
        Ok(buf)
    }

    /// Fetch remote context tarball and merge with Dockerfile
    async fn fetch_and_merge_context(
        dockerfile_content: &str,
        context_url: &str,
    ) -> Result<Vec<u8>> {
        let response = reqwest::get(context_url)
            .await
            .map_err(|e| VulnPkgError::ContextFetch {
                url: context_url.to_string(),
                source: e,
            })?;

        let context_bytes = response
            .bytes()
            .await
            .map_err(|e| VulnPkgError::ContextFetch {
                url: context_url.to_string(),
                source: e,
            })?;

        // For now, we'll extract the context and add/replace the Dockerfile
        // This is a simplified implementation that assumes the context is a tar.gz
        use flate2::read::GzDecoder;
        use std::io::Read;

        let decoder = GzDecoder::new(&context_bytes[..]);
        let mut archive = tar::Archive::new(decoder);

        // Create a new tarball with the context + our Dockerfile
        let mut buf = Vec::new();
        {
            let encoder = GzEncoder::new(&mut buf, Compression::default());
            let mut new_tar = Builder::new(encoder);

            // Add all files from the original context except Dockerfile
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?.into_owned();
                if path.to_string_lossy() != "Dockerfile" {
                    let mut header = entry.header().clone();
                    let mut data = Vec::new();
                    entry.read_to_end(&mut data)?;
                    new_tar.append_data(&mut header, &path, &data[..])?;
                }
            }

            // Add our Dockerfile
            let dockerfile_bytes = dockerfile_content.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(dockerfile_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            new_tar.append_data(&mut header, "Dockerfile", dockerfile_bytes)?;

            new_tar.finish()?;
        }

        Ok(buf)
    }

    // ==================== Git Helpers ====================

    fn clone_or_open_repo(repo_url: &str, clone_dir: &Path) -> Result<Repository> {
        if clone_dir.exists() {
            // Open existing and fetch updates
            let repo = Repository::open(clone_dir).map_err(|e| VulnPkgError::GitClone {
                repo: repo_url.to_string(),
                message: e.to_string(),
            })?;

            // Fetch latest from origin (scope to drop remote before returning repo)
            {
                let mut remote =
                    repo.find_remote("origin")
                        .map_err(|e| VulnPkgError::GitClone {
                            repo: repo_url.to_string(),
                            message: e.to_string(),
                        })?;

                remote
                    .fetch(&["refs/heads/*:refs/remotes/origin/*"], None, None)
                    .map_err(|e| VulnPkgError::GitClone {
                        repo: repo_url.to_string(),
                        message: format!("Failed to fetch: {}", e),
                    })?;
            }

            Ok(repo)
        } else {
            // Fresh clone
            Repository::clone(repo_url, clone_dir).map_err(|e| VulnPkgError::GitClone {
                repo: repo_url.to_string(),
                message: e.to_string(),
            })
        }
    }

    fn checkout_ref(repo: &Repository, ref_name: &str) -> Result<()> {
        // Try to find the ref (could be branch, tag, or commit)
        let object = repo
            .revparse_single(ref_name)
            .or_else(|_| repo.revparse_single(&format!("origin/{}", ref_name)))
            .map_err(|e| VulnPkgError::GitCheckout {
                ref_name: ref_name.to_string(),
                message: e.to_string(),
            })?;

        repo.checkout_tree(&object, None)
            .map_err(|e| VulnPkgError::GitCheckout {
                ref_name: ref_name.to_string(),
                message: e.to_string(),
            })?;

        // Set HEAD to point to the commit
        repo.set_head_detached(object.id())
            .map_err(|e| VulnPkgError::GitCheckout {
                ref_name: ref_name.to_string(),
                message: e.to_string(),
            })?;

        Ok(())
    }

    fn sanitize_repo_name(url: &str) -> String {
        url.replace(['/', ':', '@', '.'], "_")
    }

    // ==================== Container Management ====================

    pub async fn create_container(
        &self,
        app: &App,
        network_id: &str,
        domain: &str,
        https: bool,
    ) -> Result<(String, Vec<String>)> {
        let container_name = format!("vuln-pkg-{}", app.name);

        // Build Traefik labels for each port
        let mut labels = HashMap::new();
        labels.insert(CONTAINER_LABEL.to_string(), app.name.clone());
        labels.insert("traefik.enable".to_string(), "true".to_string());

        let mut hostnames = Vec::new();

        for (i, &port) in app.ports.iter().enumerate() {
            let (router_name, subdomain) = if i == 0 {
                // First port gets the app name
                (app.name.clone(), app.name.clone())
            } else {
                // Additional ports get app-port suffix
                (
                    format!("{}-{}", app.name, port),
                    format!("{}-{}", app.name, port),
                )
            };

            let hostname = format!("{}.{}", subdomain, domain);
            hostnames.push(hostname.clone());

            // HTTP router
            labels.insert(
                format!("traefik.http.routers.{}.rule", router_name),
                format!("Host(`{}`)", hostname),
            );
            labels.insert(
                format!("traefik.http.routers.{}.entrypoints", router_name),
                "web".to_string(),
            );
            labels.insert(
                format!("traefik.http.routers.{}.service", router_name),
                router_name.clone(),
            );
            labels.insert(
                format!(
                    "traefik.http.services.{}.loadbalancer.server.port",
                    router_name
                ),
                port.to_string(),
            );

            // HTTPS router if enabled
            if https {
                let secure_router = format!("{}-secure", router_name);
                labels.insert(
                    format!("traefik.http.routers.{}.rule", secure_router),
                    format!("Host(`{}`)", hostname),
                );
                labels.insert(
                    format!("traefik.http.routers.{}.entrypoints", secure_router),
                    "websecure".to_string(),
                );
                labels.insert(
                    format!("traefik.http.routers.{}.tls", secure_router),
                    "true".to_string(),
                );
                labels.insert(
                    format!("traefik.http.routers.{}.service", secure_router),
                    router_name.clone(),
                );
            }
        }

        // Network config - connect to vuln-pkg network
        let mut endpoints_config = HashMap::new();
        endpoints_config.insert(
            NETWORK_NAME.to_string(),
            EndpointSettings {
                network_id: Some(network_id.to_string()),
                ..Default::default()
            },
        );

        let host_config = HostConfig {
            ..Default::default()
        };

        let config = Config {
            image: Some(app.effective_image()),
            host_config: Some(host_config),
            labels: Some(labels),
            env: if app.env.is_empty() {
                None
            } else {
                Some(app.env.clone())
            },
            networking_config: Some(bollard::container::NetworkingConfig { endpoints_config }),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: &container_name,
            platform: None,
        };

        let response = self.docker.create_container(Some(options), config).await?;
        Ok((response.id, hostnames))
    }

    pub async fn start_container(&self, container_id: &str) -> Result<()> {
        self.docker
            .start_container(container_id, None::<StartContainerOptions<String>>)
            .await?;
        Ok(())
    }

    pub async fn stop_container(&self, container_id: &str) -> Result<()> {
        let options = StopContainerOptions { t: 10 };
        self.docker
            .stop_container(container_id, Some(options))
            .await?;
        Ok(())
    }

    pub async fn remove_container(&self, container_id: &str) -> Result<()> {
        let options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        self.docker
            .remove_container(container_id, Some(options))
            .await?;
        Ok(())
    }

    pub async fn list_vuln_pkg_containers(&self) -> Result<Vec<(String, String, bool)>> {
        let mut filters = HashMap::new();
        filters.insert("label", vec![CONTAINER_LABEL]);

        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(options)).await?;

        let result: Vec<(String, String, bool)> = containers
            .into_iter()
            .filter_map(|c| {
                let id = c.id?;
                let name = c
                    .labels?
                    .get(CONTAINER_LABEL)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                // Skip traefik container
                if name == "traefik" {
                    return None;
                }
                let running = c.state.map(|s| s == "running").unwrap_or(false);
                Some((id, name, running))
            })
            .collect();

        Ok(result)
    }

    pub async fn container_running(&self, container_id: &str) -> Result<bool> {
        match self.docker.inspect_container(container_id, None).await {
            Ok(info) => Ok(info.state.and_then(|s| s.running).unwrap_or(false)),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(VulnPkgError::Docker(e)),
        }
    }

    pub async fn count_running_apps(&self) -> Result<usize> {
        let containers = self.list_vuln_pkg_containers().await?;
        Ok(containers
            .into_iter()
            .filter(|(_, _, running)| *running)
            .count())
    }

    /// Check if a container exists for the given app name
    /// Returns (container_id, is_running) if found, None if not found
    pub async fn find_app_container(&self, app_name: &str) -> Result<Option<(String, bool)>> {
        let container_name = format!("vuln-pkg-{}", app_name);

        let mut filters = HashMap::new();
        filters.insert("name", vec![container_name.as_str()]);

        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(options)).await?;

        for container in containers {
            if let Some(names) = &container.names {
                // Container names have a leading slash
                if names.iter().any(|n| n == &format!("/{}", container_name)) {
                    let running = container.state.as_deref() == Some("running");
                    if let Some(id) = container.id {
                        return Ok(Some((id, running)));
                    }
                }
            }
        }

        Ok(None)
    }
}
