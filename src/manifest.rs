use serde::{Deserialize, Serialize};

use crate::error::{Result, VulnPkgError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub apps: Vec<App>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub name: String,
    pub version: String,
    pub image: String,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub cve_tags: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub env: Vec<String>,
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
        Ok(manifest)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    pub fn find_app(&self, name: &str) -> Option<&App> {
        self.apps.iter().find(|app| app.name == name)
    }

    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest() {
        let yaml = r#"
apps:
  - name: dvwa
    version: "1.0"
    image: vulnerables/web-dvwa
    ports: [80]
    cve_tags: [CVE-2021-1234]
    description: "Damn Vulnerable Web Application"
"#;
        let manifest = Manifest::parse(yaml).unwrap();
        assert_eq!(manifest.apps.len(), 1);
        assert_eq!(manifest.apps[0].name, "dvwa");
        assert_eq!(manifest.apps[0].ports, vec![80]);
    }
}
