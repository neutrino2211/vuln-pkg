use colored::Colorize;
use serde::Serialize;

use crate::manifest::App;
use crate::state::AppState;

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
        if !self.json {
            if tracing::enabled!(tracing::Level::DEBUG) {
                println!("{} {}", "[D]".dimmed(), msg.dimmed());
            }
        }
    }

    pub fn json<T: Serialize>(&self, data: &T) {
        if self.json {
            if let Ok(json) = serde_json::to_string_pretty(data) {
                println!("{}", json);
            }
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
                cve_tags: Vec<String>,
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
                        cve_tags: app.cve_tags.clone(),
                        ports: app.ports.clone(),
                        installed: state.map(|s| s.installed).unwrap_or(false),
                        running: state.map(|s| s.running).unwrap_or(false),
                    }
                })
                .collect();

            self.json(&info);
        } else {
            println!("\n{}", "Available Vulnerable Applications".bold().underline());
            println!();

            for app in apps {
                let state = states.get(&app.name);
                let status = match state {
                    Some(s) if s.running => "[RUNNING]".green().bold(),
                    Some(s) if s.installed => "[INSTALLED]".blue(),
                    _ => "[AVAILABLE]".dimmed(),
                };

                println!("  {} {} {}", app.name.bold(), format!("v{}", app.version).dimmed(), status);

                if !app.description.is_empty() {
                    println!("    {}", app.description);
                }

                println!("    Image: {}", app.effective_image().cyan());
                println!("    Ports: {}", app.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "));

                if !app.cve_tags.is_empty() {
                    println!("    CVEs:  {}", app.cve_tags.join(", ").red());
                }

                // Show hostnames if running
                if let Some(s) = state {
                    if s.running && !s.hostnames.is_empty() {
                        for hostname in &s.hostnames {
                            println!("    URL: {}", format!("http://{}", hostname).cyan());
                        }
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
            self.success(&format!("Installed {} ({})", app.name.bold(), app.effective_image()));
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
}
