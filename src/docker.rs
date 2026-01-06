use std::collections::HashMap;

use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{EndpointSettings, HostConfig, Mount, MountTypeEnum, PortBinding};
use bollard::network::{CreateNetworkOptions, ListNetworksOptions};
use bollard::Docker;
use futures::StreamExt;

use crate::error::{Result, VulnPkgError};
use crate::manifest::App;
use crate::output::Output;

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
            if network.name.as_deref() == Some(NETWORK_NAME) {
                if let Some(id) = network.id {
                    return Ok(id);
                }
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
            if let Some(names) = &container.names {
                if names.iter().any(|n| n == &format!("/{}", TRAEFIK_CONTAINER)) {
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
            networking_config: Some(bollard::container::NetworkingConfig {
                endpoints_config,
            }),
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

    pub async fn remove_image(&self, image: &str) -> Result<()> {
        self.docker.remove_image(image, None, None).await?;
        Ok(())
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
                (format!("{}-{}", app.name, port), format!("{}-{}", app.name, port))
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
                format!("traefik.http.services.{}.loadbalancer.server.port", router_name),
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
            image: Some(app.image.clone()),
            host_config: Some(host_config),
            labels: Some(labels),
            env: if app.env.is_empty() {
                None
            } else {
                Some(app.env.clone())
            },
            networking_config: Some(bollard::container::NetworkingConfig {
                endpoints_config,
            }),
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
        self.docker.stop_container(container_id, Some(options)).await?;
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
        Ok(containers.into_iter().filter(|(_, _, running)| *running).count())
    }
}
