use thiserror::Error;

#[derive(Error, Debug)]
pub enum VulnPkgError {
    #[error("Failed to fetch manifest from {url}: {source}")]
    ManifestFetch {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Failed to parse manifest: {0}")]
    ManifestParse(#[from] serde_yaml::Error),

    #[error("Application '{0}' not found in manifest")]
    AppNotFound(String),

    #[error("Application '{0}' is not installed")]
    AppNotInstalled(String),

    #[error("Application '{0}' is already running")]
    AppAlreadyRunning(String),

    #[error("Application '{0}' is not running")]
    AppNotRunning(String),

    #[error("Application '{0}' is a prebuilt package and cannot be rebuilt")]
    AppNotRebuildable(String),

    #[error("Manifest validation error: {0}")]
    ManifestValidation(String),

    #[error("Failed to fetch Dockerfile from {url}: {source}")]
    DockerfileFetch {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Failed to fetch build context from {url}: {source}")]
    ContextFetch {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Failed to build image '{image}': {message}")]
    ImageBuild { image: String, message: String },

    #[error("Failed to clone repository '{repo}': {message}")]
    GitClone { repo: String, message: String },

    #[error("Failed to checkout ref '{ref_name}': {message}")]
    GitCheckout { ref_name: String, message: String },

    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("State error: {0}")]
    State(String),
}

pub type Result<T> = std::result::Result<T, VulnPkgError>;
