use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{Result, VulnPkgError};
use crate::manifest::Protocol;

const STATE_DIR: &str = ".vuln-pkg";
const MANIFESTS_DIR: &str = "manifests";
const IMAGES_DIR: &str = "images";
const REPOS_DIR: &str = "repos";
const STATE_FILE: &str = "state.json";
const ACCEPTED_MANIFESTS_FILE: &str = "accepted-manifests.json";

/// Port allocation range for TCP/UDP direct mappings
const PORT_RANGE_START: u16 = 40000;
const PORT_RANGE_END: u16 = 49999;

/// Information about an accepted manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptedManifest {
    /// When the manifest was accepted (ISO 8601)
    pub accepted_at: String,
    /// Author name from manifest metadata
    #[serde(default)]
    pub author: Option<String>,
    /// Email from manifest metadata
    #[serde(default)]
    pub email: Option<String>,
    /// URL from manifest metadata
    #[serde(default)]
    pub url: Option<String>,
    /// Description from manifest metadata
    #[serde(default)]
    pub description: Option<String>,
}

/// Tracks accepted manifests by URL
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcceptedManifests {
    pub manifests: HashMap<String, AcceptedManifest>,
}

/// Tracks how the Docker image was obtained
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ImageSource {
    /// Pulled from a registry
    #[default]
    Prebuilt,
    /// Built from a Dockerfile
    Dockerfile,
    /// Built from a git repository
    Git,
}

/// Represents an allocated port mapping for TCP/UDP protocols
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllocatedPort {
    /// Container port
    pub container_port: u16,
    /// Host port (from allocation range)
    pub host_port: u16,
    /// Protocol (tcp/udp)
    pub protocol: Protocol,
    /// Optional label for this port
    #[serde(default)]
    pub label: Option<String>,
}

/// Endpoint information for display
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Endpoint {
    /// The URL or connection string
    pub url: String,
    /// Protocol type
    pub protocol: Protocol,
    /// Optional label
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppState {
    pub installed: bool,
    pub running: bool,
    pub container_id: Option<String>,
    /// HTTP hostnames (for Traefik-routed ports)
    pub hostnames: Vec<String>,

    /// How the image was obtained
    #[serde(default)]
    pub image_source: ImageSource,

    /// The Docker image tag used
    #[serde(default)]
    pub image_tag: Option<String>,

    /// Git commit SHA (for git-based builds)
    #[serde(default)]
    pub git_commit: Option<String>,

    /// Timestamp of last build (ISO 8601 format)
    #[serde(default)]
    pub built_at: Option<String>,

    /// Allocated ports for TCP/UDP direct mappings
    #[serde(default)]
    pub allocated_ports: Vec<AllocatedPort>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub apps: HashMap<String, AppState>,
    pub network_id: Option<String>,
    pub traefik_container_id: Option<String>,
}

impl State {
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
            network_id: None,
            traefik_container_id: None,
        }
    }

    /// Get all currently allocated host ports across all apps
    pub fn allocated_host_ports(&self) -> Vec<u16> {
        self.apps
            .values()
            .flat_map(|app| app.allocated_ports.iter().map(|p| p.host_port))
            .collect()
    }

    /// Allocate a new host port from the range
    /// Returns None if no ports are available
    #[allow(dead_code)]
    pub fn allocate_port(&self) -> Option<u16> {
        let used_ports = self.allocated_host_ports();
        (PORT_RANGE_START..=PORT_RANGE_END).find(|port| !used_ports.contains(port))
    }

    /// Allocate multiple ports from the range
    /// Returns None if not enough ports are available
    pub fn allocate_ports(&self, count: usize) -> Option<Vec<u16>> {
        let used_ports = self.allocated_host_ports();
        let available: Vec<u16> = (PORT_RANGE_START..=PORT_RANGE_END)
            .filter(|port| !used_ports.contains(port))
            .take(count)
            .collect();

        if available.len() == count {
            Some(available)
        } else {
            None
        }
    }
}

pub struct StateManager {
    base_dir: PathBuf,
}

impl StateManager {
    pub fn new() -> Result<Self> {
        let home = dirs_home()
            .ok_or_else(|| VulnPkgError::State("Could not determine home directory".to_string()))?;
        let base_dir = home.join(STATE_DIR);
        Ok(Self { base_dir })
    }

    pub fn init(&self) -> Result<()> {
        std::fs::create_dir_all(self.manifests_dir())?;
        std::fs::create_dir_all(self.images_dir())?;
        std::fs::create_dir_all(self.repos_dir())?;

        // Create state file if it doesn't exist
        if !self.state_file().exists() {
            self.save_state(&State::new())?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    pub fn manifests_dir(&self) -> PathBuf {
        self.base_dir.join(MANIFESTS_DIR)
    }

    pub fn images_dir(&self) -> PathBuf {
        self.base_dir.join(IMAGES_DIR)
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.base_dir.join(REPOS_DIR)
    }

    pub fn state_file(&self) -> PathBuf {
        self.base_dir.join(STATE_FILE)
    }

    pub fn load_state(&self) -> Result<State> {
        if !self.state_file().exists() {
            return Ok(State::new());
        }
        let content = std::fs::read_to_string(self.state_file())?;
        let state: State = serde_json::from_str(&content)
            .map_err(|e| VulnPkgError::State(format!("Failed to parse state: {}", e)))?;
        Ok(state)
    }

    pub fn save_state(&self, state: &State) -> Result<()> {
        let content = serde_json::to_string_pretty(state)
            .map_err(|e| VulnPkgError::State(format!("Failed to serialize state: {}", e)))?;
        std::fs::write(self.state_file(), content)?;
        Ok(())
    }

    pub fn cache_manifest(&self, url: &str, content: &str) -> Result<PathBuf> {
        let filename = url_to_filename(url);
        let path = self.manifests_dir().join(filename);
        std::fs::write(&path, content)?;
        Ok(path)
    }

    #[allow(dead_code)]
    pub fn get_cached_manifest(&self, url: &str) -> Option<PathBuf> {
        let filename = url_to_filename(url);
        let path = self.manifests_dir().join(filename);
        if path.exists() { Some(path) } else { None }
    }

    fn accepted_manifests_file(&self) -> PathBuf {
        self.base_dir.join(ACCEPTED_MANIFESTS_FILE)
    }

    pub fn load_accepted_manifests(&self) -> Result<AcceptedManifests> {
        if !self.accepted_manifests_file().exists() {
            return Ok(AcceptedManifests::default());
        }
        let content = std::fs::read_to_string(self.accepted_manifests_file())?;
        let accepted: AcceptedManifests = serde_json::from_str(&content).map_err(|e| {
            VulnPkgError::State(format!("Failed to parse accepted manifests: {}", e))
        })?;
        Ok(accepted)
    }

    pub fn save_accepted_manifests(&self, accepted: &AcceptedManifests) -> Result<()> {
        let content = serde_json::to_string_pretty(accepted).map_err(|e| {
            VulnPkgError::State(format!("Failed to serialize accepted manifests: {}", e))
        })?;
        std::fs::write(self.accepted_manifests_file(), content)?;
        Ok(())
    }

    pub fn is_manifest_accepted(&self, url: &str) -> Result<bool> {
        let accepted = self.load_accepted_manifests()?;
        Ok(accepted.manifests.contains_key(url))
    }

    pub fn accept_manifest(
        &self,
        url: &str,
        manifest_meta: &crate::manifest::ManifestMeta,
    ) -> Result<()> {
        let mut accepted = self.load_accepted_manifests()?;
        accepted.manifests.insert(
            url.to_string(),
            AcceptedManifest {
                accepted_at: chrono::Utc::now().to_rfc3339(),
                author: manifest_meta.author.clone(),
                email: manifest_meta.email.clone(),
                url: manifest_meta.url.clone(),
                description: manifest_meta.description.clone(),
            },
        );
        self.save_accepted_manifests(&accepted)
    }

    pub fn forget_manifest(&self, url: &str) -> Result<bool> {
        let mut accepted = self.load_accepted_manifests()?;
        let removed = accepted.manifests.remove(url).is_some();
        if removed {
            self.save_accepted_manifests(&accepted)?;
        }
        Ok(removed)
    }
}

fn dirs_home() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf())
}

fn url_to_filename(url: &str) -> String {
    url.replace(['/', ':', '.'], "_") + ".yml"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_to_filename() {
        assert_eq!(
            url_to_filename("https://vulns.io/apps.yml"),
            "https___vulns_io_apps_yml.yml"
        );
    }
}
