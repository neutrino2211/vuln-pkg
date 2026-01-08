use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Result, VulnPkgError};

/// Protocol for exposing a port
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP protocol - routed through Traefik reverse proxy
    #[default]
    Http,
    /// Raw TCP protocol - direct port mapping
    Tcp,
    /// UDP protocol - direct port mapping
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Http => write!(f, "http"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// Port configuration with protocol and optional label
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortConfig {
    /// Container port number
    pub port: u16,
    /// Protocol (http, tcp, udp) - defaults to http
    #[serde(default)]
    pub protocol: Protocol,
    /// Optional human-readable label for this port
    #[serde(default)]
    pub label: Option<String>,
}

impl PortConfig {
    /// Create a new HTTP port config (default)
    pub fn http(port: u16) -> Self {
        Self {
            port,
            protocol: Protocol::Http,
            label: None,
        }
    }

    /// Create a new TCP port config
    #[allow(dead_code)]
    pub fn tcp(port: u16) -> Self {
        Self {
            port,
            protocol: Protocol::Tcp,
            label: None,
        }
    }

    /// Create a new UDP port config
    #[allow(dead_code)]
    pub fn udp(port: u16) -> Self {
        Self {
            port,
            protocol: Protocol::Udp,
            label: None,
        }
    }

    /// Check if this port uses HTTP protocol (routed through Traefik)
    pub fn is_http(&self) -> bool {
        self.protocol == Protocol::Http
    }

    /// Check if this port needs direct port mapping (TCP/UDP)
    pub fn needs_direct_mapping(&self) -> bool {
        matches!(self.protocol, Protocol::Tcp | Protocol::Udp)
    }
}

/// Wrapper to support both simple port numbers and full PortConfig objects
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum PortEntry {
    Simple(u16),
    Config(PortConfig),
}

impl<'de> Deserialize<'de> for PortEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct PortEntryVisitor;

        impl<'de> Visitor<'de> for PortEntryVisitor {
            type Value = PortEntry;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a port number or port configuration object")
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PortEntry::Simple(value as u16))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PortEntry::Simple(value as u16))
            }

            fn visit_map<M>(self, map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let config = PortConfig::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(PortEntry::Config(config))
            }
        }

        deserializer.deserialize_any(PortEntryVisitor)
    }
}

impl PortEntry {
    /// Convert to PortConfig
    pub fn to_config(&self) -> PortConfig {
        match self {
            PortEntry::Simple(port) => PortConfig::http(*port),
            PortEntry::Config(config) => config.clone(),
        }
    }

    /// Get the port number
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        match self {
            PortEntry::Simple(port) => *port,
            PortEntry::Config(config) => config.port,
        }
    }
}

/// Package type determines how the Docker image is obtained
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PackageType {
    /// Pull a pre-built image from a registry (default)
    #[default]
    Prebuilt,
    /// Build from an inline or remote Dockerfile
    Dockerfile,
    /// Clone a git repository and build from its Dockerfile
    Git,
}

/// Metadata about the manifest author/maintainer
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestMeta {
    /// Name of the manifest author or organization
    #[serde(default)]
    pub author: Option<String>,
    /// Contact email for the manifest maintainer
    #[serde(default)]
    pub email: Option<String>,
    /// URL for more information (website, repo, etc.)
    #[serde(default)]
    pub url: Option<String>,
    /// Description of what this manifest provides
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Metadata about the manifest author
    #[serde(default)]
    pub meta: ManifestMeta,
    pub apps: Vec<App>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub name: String,
    pub version: String,
    /// Docker image (required for prebuilt, ignored for dockerfile/git)
    #[serde(default)]
    pub image: Option<String>,
    /// Ports exposed by this application (can be simple numbers or full config)
    pub ports: Vec<PortEntry>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub env: Vec<String>,

    // Package type (defaults to prebuilt for backward compatibility)
    #[serde(default, rename = "type")]
    pub package_type: PackageType,

    // Dockerfile package fields
    /// Inline Dockerfile content
    #[serde(default)]
    pub dockerfile: Option<String>,
    /// URL to fetch Dockerfile from
    #[serde(default)]
    pub dockerfile_url: Option<String>,
    /// URL to fetch build context tarball from
    #[serde(default)]
    pub context_url: Option<String>,

    // Git package fields
    /// Git repository URL
    #[serde(default)]
    pub repo: Option<String>,
    /// Git ref (branch, tag, or commit)
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
    /// Path to Dockerfile within the repository
    #[serde(default)]
    pub dockerfile_path: Option<String>,
}

impl App {
    /// Returns the effective Docker image name/tag for this app.
    /// For prebuilt packages, returns the image field.
    /// For custom packages, returns a generated tag: vuln-pkg/<name>:<version>
    pub fn effective_image(&self) -> String {
        match self.package_type {
            PackageType::Prebuilt => self.image.clone().unwrap_or_default(),
            PackageType::Dockerfile | PackageType::Git => {
                format!("vuln-pkg/{}:{}", self.name, self.version)
            }
        }
    }

    /// Get all port configurations (converts simple ports to PortConfig)
    pub fn port_configs(&self) -> Vec<PortConfig> {
        self.ports.iter().map(|p| p.to_config()).collect()
    }

    /// Get only HTTP ports (routed through Traefik)
    pub fn http_ports(&self) -> Vec<PortConfig> {
        self.port_configs()
            .into_iter()
            .filter(|p| p.is_http())
            .collect()
    }

    /// Get only TCP/UDP ports (direct port mapping)
    pub fn direct_ports(&self) -> Vec<PortConfig> {
        self.port_configs()
            .into_iter()
            .filter(|p| p.needs_direct_mapping())
            .collect()
    }

    /// Check if this app has any TCP/UDP ports that need direct mapping
    #[allow(dead_code)]
    pub fn has_direct_ports(&self) -> bool {
        self.ports
            .iter()
            .any(|p| p.to_config().needs_direct_mapping())
    }

    /// Get simple list of port numbers (for backward compatibility)
    #[allow(dead_code)]
    pub fn port_numbers(&self) -> Vec<u16> {
        self.ports.iter().map(|p| p.port()).collect()
    }

    /// Validates that required fields are present for the package type
    pub fn validate(&self) -> Result<()> {
        match self.package_type {
            PackageType::Prebuilt => {
                if self.image.is_none() {
                    return Err(VulnPkgError::ManifestValidation(format!(
                        "Prebuilt app '{}' requires 'image' field",
                        self.name
                    )));
                }
            }
            PackageType::Dockerfile => {
                let has_inline = self.dockerfile.is_some();
                let has_url = self.dockerfile_url.is_some();

                if !has_inline && !has_url {
                    return Err(VulnPkgError::ManifestValidation(format!(
                        "Dockerfile app '{}' requires 'dockerfile' or 'dockerfile_url' field",
                        self.name
                    )));
                }
            }
            PackageType::Git => {
                if self.repo.is_none() {
                    return Err(VulnPkgError::ManifestValidation(format!(
                        "Git app '{}' requires 'repo' field",
                        self.name
                    )));
                }
            }
        }
        Ok(())
    }
}

impl Manifest {
    pub async fn fetch(url: &str) -> Result<Self> {
        // Handle local file paths
        if url.starts_with("file://") {
            let path = url.strip_prefix("file://").unwrap();
            return Self::from_file(std::path::Path::new(path));
        }
        if url.starts_with('/') || url.starts_with('.') {
            return Self::from_file(std::path::Path::new(url));
        }

        let response = reqwest::get(url)
            .await
            .map_err(|e| VulnPkgError::ManifestFetch {
                url: url.to_string(),
                source: e,
            })?;

        let text = response
            .text()
            .await
            .map_err(|e| VulnPkgError::ManifestFetch {
                url: url.to_string(),
                source: e,
            })?;

        Self::parse(&text)
    }

    pub fn parse(yaml: &str) -> Result<Self> {
        let manifest: Manifest = serde_yaml::from_str(yaml)?;

        // Validate each app
        for app in &manifest.apps {
            app.validate()?;
        }

        Ok(manifest)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    pub fn find_app(&self, name: &str) -> Option<&App> {
        self.apps.iter().find(|app| app.name == name)
    }

    #[allow(dead_code)]
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prebuilt_manifest() {
        let yaml = r#"
apps:
  - name: dvwa
    version: "1.0"
    image: vulnerables/web-dvwa
    ports: [80]
    tags: [CVE-2021-1234]
    description: "Damn Vulnerable Web Application"
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        assert_eq!(manifest.apps.len(), 1);
        assert_eq!(manifest.apps[0].name, "dvwa");
        assert_eq!(manifest.apps[0].port_numbers(), vec![80]);
        assert_eq!(manifest.apps[0].package_type, PackageType::Prebuilt);
        assert_eq!(manifest.apps[0].effective_image(), "vulnerables/web-dvwa");
    }

    #[test]
    fn test_parse_dockerfile_inline_manifest() {
        let yaml = r#"
apps:
  - name: custom-sqli
    version: "1.0"
    type: dockerfile
    dockerfile: |
      FROM ubuntu:22.04
      RUN apt-get update
    ports: [80]
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        assert_eq!(manifest.apps[0].package_type, PackageType::Dockerfile);
        assert!(manifest.apps[0].dockerfile.is_some());
        assert_eq!(
            manifest.apps[0].effective_image(),
            "vuln-pkg/custom-sqli:1.0"
        );
    }

    #[test]
    fn test_parse_dockerfile_url_manifest() {
        let yaml = r#"
apps:
  - name: remote-app
    version: "2.0"
    type: dockerfile
    dockerfile_url: https://example.com/Dockerfile
    context_url: https://example.com/context.tar.gz
    ports: [8080]
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        assert_eq!(manifest.apps[0].package_type, PackageType::Dockerfile);
        assert_eq!(
            manifest.apps[0].dockerfile_url.as_deref(),
            Some("https://example.com/Dockerfile")
        );
        assert_eq!(
            manifest.apps[0].context_url.as_deref(),
            Some("https://example.com/context.tar.gz")
        );
    }

    #[test]
    fn test_parse_git_manifest() {
        let yaml = r#"
apps:
  - name: git-vuln-app
    version: "1.0"
    type: git
    repo: https://github.com/user/vuln-app.git
    ref: main
    dockerfile_path: ./docker/Dockerfile
    ports: [3000]
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        assert_eq!(manifest.apps[0].package_type, PackageType::Git);
        assert_eq!(
            manifest.apps[0].repo.as_deref(),
            Some("https://github.com/user/vuln-app.git")
        );
        assert_eq!(manifest.apps[0].git_ref.as_deref(), Some("main"));
        assert_eq!(
            manifest.apps[0].dockerfile_path.as_deref(),
            Some("./docker/Dockerfile")
        );
        assert_eq!(
            manifest.apps[0].effective_image(),
            "vuln-pkg/git-vuln-app:1.0"
        );
    }

    #[test]
    fn test_backward_compatibility() {
        // Existing manifests without 'type' field should default to prebuilt
        let yaml = r#"
apps:
  - name: dvwa
    version: "1.0"
    image: vulnerables/web-dvwa
    ports: [80]
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        assert_eq!(manifest.apps[0].package_type, PackageType::Prebuilt);
        // Simple ports should default to HTTP protocol
        let configs = manifest.apps[0].port_configs();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].port, 80);
        assert_eq!(configs[0].protocol, Protocol::Http);
    }

    #[test]
    fn test_validation_prebuilt_missing_image() {
        let yaml = r#"
apps:
  - name: bad-app
    version: "1.0"
    ports: [80]
"#;
        let result = Manifest::parse(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("requires 'image' field"));
    }

    #[test]
    fn test_validation_dockerfile_missing_source() {
        let yaml = r#"
apps:
  - name: bad-dockerfile
    version: "1.0"
    type: dockerfile
    ports: [80]
"#;
        let result = Manifest::parse(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("requires 'dockerfile' or 'dockerfile_url'"));
    }

    #[test]
    fn test_validation_git_missing_repo() {
        let yaml = r#"
apps:
  - name: bad-git
    version: "1.0"
    type: git
    ports: [80]
"#;
        let result = Manifest::parse(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("requires 'repo' field"));
    }

    #[test]
    fn test_port_config_with_protocol() {
        let yaml = r#"
apps:
  - name: mongobleed
    version: "8.0.16"
    image: mongo:8.0.16
    ports:
      - port: 27017
        protocol: tcp
        label: MongoDB
    description: "MongoDB with MongoBleed vulnerability"
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        let app = &manifest.apps[0];
        assert_eq!(app.port_numbers(), vec![27017]);

        let configs = app.port_configs();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].port, 27017);
        assert_eq!(configs[0].protocol, Protocol::Tcp);
        assert_eq!(configs[0].label.as_deref(), Some("MongoDB"));

        assert!(app.has_direct_ports());
        assert!(app.http_ports().is_empty());
        assert_eq!(app.direct_ports().len(), 1);
    }

    #[test]
    fn test_mixed_port_protocols() {
        let yaml = r#"
apps:
  - name: multi-port-app
    version: "1.0"
    image: example/multi
    ports:
      - port: 80
        protocol: http
        label: Web Admin
      - port: 27017
        protocol: tcp
        label: MongoDB
      - 8080
    description: "App with mixed protocols"
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        let app = &manifest.apps[0];

        assert_eq!(app.port_numbers(), vec![80, 27017, 8080]);

        let http_ports = app.http_ports();
        assert_eq!(http_ports.len(), 2); // port 80 and 8080 (default)
        assert_eq!(http_ports[0].port, 80);
        assert_eq!(http_ports[1].port, 8080);

        let direct_ports = app.direct_ports();
        assert_eq!(direct_ports.len(), 1);
        assert_eq!(direct_ports[0].port, 27017);
        assert_eq!(direct_ports[0].protocol, Protocol::Tcp);

        assert!(app.has_direct_ports());
    }

    #[test]
    fn test_udp_protocol() {
        let yaml = r#"
apps:
  - name: dns-vuln
    version: "1.0"
    image: example/dns
    ports:
      - port: 53
        protocol: udp
        label: DNS
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        let app = &manifest.apps[0];

        let configs = app.port_configs();
        assert_eq!(configs[0].protocol, Protocol::Udp);
        assert!(configs[0].needs_direct_mapping());
        assert!(!configs[0].is_http());
    }
}
