use colored::Colorize;
use serde::Serialize;

use crate::manifest::{App, Manifest};
use crate::state::{AcceptedManifests, AppState};

pub struct Output {
    json: bool,
}

impl Output {
    pub fn new(json: bool) -> Self {
        Self { json }
    }

    pub fn info(&self, msg: &str) {
        if !self.json {
            println!("{} {}", "[*]".blue(), msg);
        }
    }

    pub fn success(&self, msg: &str) {
        if !self.json {
            println!("{} {}", "[+]".green(), msg);
        }
    }

    pub fn warning(&self, msg: &str) {
        if !self.json {
            println!("{} {}", "[!]".yellow(), msg);
        }
    }

    pub fn error(&self, msg: &str) {
        if !self.json {
            eprintln!("{} {}", "[-]".red(), msg);
        }
    }

    pub fn debug(&self, msg: &str) {
        if !self.json && tracing::enabled!(tracing::Level::DEBUG) {
            println!("{} {}", "[D]".dimmed(), msg.dimmed());
        }
    }

    pub fn json<T: Serialize>(&self, data: &T) {
        if self.json
            && let Ok(json) = serde_json::to_string_pretty(data)
        {
            println!("{}", json);
        }
    }

    pub fn list_apps(&self, apps: &[App], states: &std::collections::HashMap<String, AppState>) {
        if self.json {
            #[derive(Serialize)]
            struct AppInfo {
                name: String,
                version: String,
                image: String,
                description: String,
                tags: Vec<String>,
                ports: Vec<u16>,
                installed: bool,
                running: bool,
            }

            let info: Vec<AppInfo> = apps
                .iter()
                .map(|app| {
                    let state = states.get(&app.name);
                    AppInfo {
                        name: app.name.clone(),
                        version: app.version.clone(),
                        image: app.effective_image(),
                        description: app.description.clone(),
                        tags: app.tags.clone(),
                        ports: app.ports.clone(),
                        installed: state.map(|s| s.installed).unwrap_or(false),
                        running: state.map(|s| s.running).unwrap_or(false),
                    }
                })
                .collect();

            self.json(&info);
        } else {
            println!(
                "\n{}",
                "Available Vulnerable Applications".bold().underline()
            );
            println!();

            for app in apps {
                let state = states.get(&app.name);
                let status = match state {
                    Some(s) if s.running => "[RUNNING]".green().bold(),
                    Some(s) if s.installed => "[INSTALLED]".blue(),
                    _ => "[AVAILABLE]".dimmed(),
                };

                println!(
                    "  {} {} {}",
                    app.name.bold(),
                    format!("v{}", app.version).dimmed(),
                    status
                );

                if !app.description.is_empty() {
                    println!("    {}", app.description);
                }

                println!("    Image: {}", app.effective_image().cyan());
                println!(
                    "    Ports: {}",
                    app.ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                if !app.tags.is_empty() {
                    println!("    Tags:  {}", app.tags.join(", ").yellow());
                }

                // Show hostnames if running
                if let Some(s) = state
                    && s.running
                    && !s.hostnames.is_empty()
                {
                    for hostname in &s.hostnames {
                        println!("    URL: {}", format!("http://{}", hostname).cyan());
                    }
                }

                println!();
            }
        }
    }

    pub fn status(&self, apps: &[(String, bool, Option<String>, Vec<String>)]) {
        if self.json {
            #[derive(Serialize)]
            struct StatusInfo {
                name: String,
                running: bool,
                container_id: Option<String>,
                hostnames: Vec<String>,
            }

            let info: Vec<StatusInfo> = apps
                .iter()
                .map(|(name, running, container_id, hostnames)| StatusInfo {
                    name: name.clone(),
                    running: *running,
                    container_id: container_id.clone(),
                    hostnames: hostnames.clone(),
                })
                .collect();

            self.json(&info);
        } else {
            if apps.is_empty() {
                println!("No vuln-pkg applications are currently managed.");
                return;
            }

            println!("\n{}", "Application Status".bold().underline());
            println!();

            for (name, running, container_id, hostnames) in apps {
                let status = if *running {
                    "RUNNING".green().bold()
                } else {
                    "STOPPED".red()
                };

                println!("  {} [{}]", name.bold(), status);

                if let Some(id) = container_id {
                    let short_id = &id[..12.min(id.len())];
                    println!("    Container: {}", short_id);
                }

                if !hostnames.is_empty() {
                    for hostname in hostnames {
                        println!("    URL: {}", format!("http://{}", hostname).cyan());
                    }
                }

                println!();
            }
        }
    }

    pub fn app_installed(&self, app: &App) {
        if self.json {
            #[derive(Serialize)]
            struct InstallResult {
                status: &'static str,
                app: String,
                image: String,
            }
            self.json(&InstallResult {
                status: "installed",
                app: app.name.clone(),
                image: app.effective_image(),
            });
        } else {
            self.success(&format!(
                "Installed {} ({})",
                app.name.bold(),
                app.effective_image()
            ));
        }
    }

    pub fn app_running(&self, app: &App, hostnames: &[String], domain: &str, https: bool) {
        if self.json {
            #[derive(Serialize)]
            struct RunResult<'a> {
                status: &'static str,
                app: &'a str,
                hostnames: &'a [String],
                domain: &'a str,
                https: bool,
            }
            self.json(&RunResult {
                status: "running",
                app: &app.name,
                hostnames,
                domain,
                https,
            });
        } else {
            self.success(&format!("Started {}", app.name.bold()));
            println!();
            let scheme = if https { "https" } else { "http" };
            for hostname in hostnames {
                println!(
                    "  {} {}",
                    "->".green(),
                    format!("{}://{}", scheme, hostname).cyan()
                );
            }
            println!();
        }
    }

    pub fn app_stopped(&self, app_name: &str) {
        if self.json {
            #[derive(Serialize)]
            struct StopResult<'a> {
                status: &'static str,
                app: &'a str,
            }
            self.json(&StopResult {
                status: "stopped",
                app: app_name,
            });
        } else {
            self.success(&format!("Stopped {}", app_name.bold()));
        }
    }

    pub fn app_removed(&self, app_name: &str) {
        if self.json {
            #[derive(Serialize)]
            struct RemoveResult<'a> {
                status: &'static str,
                app: &'a str,
            }
            self.json(&RemoveResult {
                status: "removed",
                app: app_name,
            });
        } else {
            self.success(&format!("Removed {}", app_name.bold()));
        }
    }

    pub fn search_results(
        &self,
        query: &str,
        apps: &[&App],
        states: &std::collections::HashMap<String, AppState>,
    ) {
        if self.json {
            #[derive(Serialize)]
            struct SearchResult {
                query: String,
                count: usize,
                results: Vec<AppInfo>,
            }

            #[derive(Serialize)]
            struct AppInfo {
                name: String,
                version: String,
                image: String,
                description: String,
                tags: Vec<String>,
                ports: Vec<u16>,
                installed: bool,
                running: bool,
            }

            let results: Vec<AppInfo> = apps
                .iter()
                .map(|app| {
                    let state = states.get(&app.name);
                    AppInfo {
                        name: app.name.clone(),
                        version: app.version.clone(),
                        image: app.effective_image(),
                        description: app.description.clone(),
                        tags: app.tags.clone(),
                        ports: app.ports.clone(),
                        installed: state.map(|s| s.installed).unwrap_or(false),
                        running: state.map(|s| s.running).unwrap_or(false),
                    }
                })
                .collect();

            self.json(&SearchResult {
                query: query.to_string(),
                count: results.len(),
                results,
            });
        } else {
            println!("\n{} \"{}\"", "Search Results for".bold(), query.cyan());
            println!();

            if apps.is_empty() {
                println!("  No applications found matching \"{}\"", query);
                println!();
                return;
            }

            println!("  Found {} application(s):\n", apps.len());

            for app in apps {
                let state = states.get(&app.name);
                let status = match state {
                    Some(s) if s.running => "[RUNNING]".green().bold(),
                    Some(s) if s.installed => "[INSTALLED]".blue(),
                    _ => "[AVAILABLE]".dimmed(),
                };

                println!(
                    "  {} {} {}",
                    app.name.bold(),
                    format!("v{}", app.version).dimmed(),
                    status
                );

                if !app.description.is_empty() {
                    println!("    {}", app.description);
                }

                println!("    Image: {}", app.effective_image().cyan());
                println!(
                    "    Ports: {}",
                    app.ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                if !app.tags.is_empty() {
                    println!("    Tags:  {}", app.tags.join(", ").yellow());
                }

                // Show hostnames if running
                if let Some(s) = state
                    && s.running
                    && !s.hostnames.is_empty()
                {
                    for hostname in &s.hostnames {
                        println!("    URL: {}", format!("http://{}", hostname).cyan());
                    }
                }

                println!();
            }
        }
    }

    /// Display manifest information for acceptance prompt
    pub fn manifest_info(&self, url: &str, manifest: &Manifest) {
        if self.json {
            #[derive(Serialize)]
            struct ManifestInfo<'a> {
                url: &'a str,
                author: Option<&'a str>,
                email: Option<&'a str>,
                manifest_url: Option<&'a str>,
                description: Option<&'a str>,
                app_count: usize,
                apps: Vec<&'a str>,
            }

            self.json(&ManifestInfo {
                url,
                author: manifest.meta.author.as_deref(),
                email: manifest.meta.email.as_deref(),
                manifest_url: manifest.meta.url.as_deref(),
                description: manifest.meta.description.as_deref(),
                app_count: manifest.apps.len(),
                apps: manifest.apps.iter().map(|a| a.name.as_str()).collect(),
            });
        } else {
            println!("\n{}", "═".repeat(60).dimmed());
            println!("{}", "  NEW MANIFEST".bold().yellow());
            println!("{}", "═".repeat(60).dimmed());
            println!();
            println!("  {}  {}", "URL:".bold(), url.cyan());

            if let Some(ref author) = manifest.meta.author {
                println!("  {}  {}", "Author:".bold(), author);
            }
            if let Some(ref email) = manifest.meta.email {
                println!("  {}  {}", "Email:".bold(), email);
            }
            if let Some(ref murl) = manifest.meta.url {
                println!("  {}  {}", "Website:".bold(), murl.cyan());
            }
            if let Some(ref desc) = manifest.meta.description {
                println!("  {}  {}", "About:".bold(), desc);
            }

            println!();
            println!(
                "  {} {} application(s) available:",
                "Contains".bold(),
                manifest.apps.len()
            );
            for app in &manifest.apps {
                println!("    - {}", app.name);
            }
            println!();
            println!("{}", "═".repeat(60).dimmed());
        }
    }

    /// Display acceptance prompt and return true if accepted
    #[allow(dead_code)]
    pub fn prompt_manifest_acceptance(&self) -> bool {
        if self.json {
            return false; // In JSON mode, require -y flag
        }

        println!();
        println!(
            "  {} This manifest has not been accepted before.",
            "⚠".yellow()
        );
        println!("  Review the information above and decide whether to trust it.");
        println!();
        print!("  {} ", "Accept this manifest? [y/N/show]:".bold());

        use std::io::{self, Write};
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return false;
        }

        let input = input.trim().to_lowercase();
        input == "y" || input == "yes"
    }

    /// Check if user wants to see the full manifest
    #[allow(dead_code)]
    pub fn user_wants_manifest_contents(input: &str) -> bool {
        let input = input.trim().to_lowercase();
        input == "show" || input == "s" || input == "view"
    }

    /// Display the raw manifest YAML content
    pub fn show_manifest_yaml(&self, yaml: &str) {
        if self.json {
            println!("{}", serde_json::json!({ "yaml": yaml }));
        } else {
            println!("\n{}", "Manifest Contents:".bold().underline());
            println!("{}", "─".repeat(60).dimmed());
            for line in yaml.lines() {
                println!("{}", line);
            }
            println!("{}", "─".repeat(60).dimmed());
            println!();
        }
    }

    /// Display list of accepted manifests
    pub fn list_accepted_manifests(&self, accepted: &AcceptedManifests) {
        if self.json {
            self.json(accepted);
        } else {
            if accepted.manifests.is_empty() {
                println!("No manifests have been accepted yet.");
                return;
            }

            println!("\n{}", "Accepted Manifests".bold().underline());
            println!();

            for (url, info) in &accepted.manifests {
                println!("  {}", url.cyan());
                if let Some(ref author) = info.author {
                    println!("    Author: {}", author);
                }
                if let Some(ref email) = info.email {
                    println!("    Email: {}", email);
                }
                println!("    Accepted: {}", info.accepted_at.dimmed());
                println!();
            }
        }
    }

    /// Display message when manifest is forgotten
    pub fn manifest_forgotten(&self, url: &str) {
        if self.json {
            self.json(&serde_json::json!({
                "status": "forgotten",
                "url": url
            }));
        } else {
            self.success(&format!("Forgot manifest: {}", url));
        }
    }

    /// Display message when manifest was not found in accepted list
    pub fn manifest_not_accepted(&self, url: &str) {
        if self.json {
            self.json(&serde_json::json!({
                "status": "not_found",
                "url": url
            }));
        } else {
            self.warning(&format!("Manifest not in accepted list: {}", url));
        }
    }
}
