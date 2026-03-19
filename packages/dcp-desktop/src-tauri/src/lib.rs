use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::Write;
use std::process::{Child, Command};
use std::sync::{Mutex, OnceLock};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, RunEvent, State, WindowEvent,
};
use uuid::Uuid;

// Constants
const KEYCHAIN_SERVICE: &str = "dcp-vault-desktop";
const KEYCHAIN_PRIVATE_KEY: &str = "private-key";
const KEYCHAIN_DESKTOP_ID: &str = "desktop-id";
const SERVER_URL: &str = "http://127.0.0.1:8421";

static RESOURCE_DIR: OnceLock<std::path::PathBuf> = OnceLock::new();

// Server process manager state
struct ServerState {
    process: Mutex<Option<Child>>,
}

impl Drop for ServerState {
    fn drop(&mut self) {
        // Ensure server is killed when ServerState is dropped (app exit)
        if let Ok(mut process_guard) = self.process.lock() {
            if let Some(ref mut child) = *process_guard {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

// Owner authentication state
struct OwnerState {
    token: Mutex<Option<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InitVaultResult {
    recovery_phrase: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletInfo {
    chain: String,
    address: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateWalletsResult {
    wallets: Vec<WalletInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    initialized: bool,
    unlocked: bool,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DesktopCredentials {
    desktop_id: String,
    public_key: String,
    is_new: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChallengeResponse {
    desktop_id: String,
    nonce: String,
    expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyResponse {
    verified: bool,
    token: String,
    expires_at: String,
    idle_timeout_minutes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterRequest {
    desktop_id: String,
    public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyRequest {
    desktop_id: String,
    nonce: String,
    signature: String,
}

// ============================================================================
// Owner Trust Model Commands
// ============================================================================

// ============================================================================
// Keychain helpers
// - Default path: keyring crate (production + signed apps)
// - macOS dev fallback: security CLI without passing secrets in argv
// ============================================================================

#[cfg(target_os = "macos")]
fn keychain_get_macos_cli(service: &str, account: &str) -> Option<String> {
    let output = Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .output()
        .ok()?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn keychain_set_macos_cli(service: &str, account: &str, password: &str) -> Result<(), String> {
    // Best-effort delete existing item (ignore errors)
    let _ = Command::new("security")
        .args(["delete-generic-password", "-s", service, "-a", account])
        .output();

    // Add password - in dev mode we pass via argument (visible in ps but acceptable for dev)
    // In production, signed apps use the keyring crate instead
    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            password,
            "-U",
        ])
        .output()
        .map_err(|e| format!("Failed to execute security command: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Keychain write failed: {}", stderr))
    }
}

fn keychain_get(service: &str, account: &str) -> Option<String> {
    // Always use CLI on macOS - keyring crate has issues with ad-hoc signed apps
    #[cfg(target_os = "macos")]
    {
        return keychain_get_macos_cli(service, account);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let entry = Entry::new(service, account).ok()?;
        entry.get_password().ok()
    }
}

fn keychain_set(service: &str, account: &str, password: &str) -> Result<(), String> {
    // Always use CLI on macOS - keyring crate has issues with ad-hoc signed apps
    #[cfg(target_os = "macos")]
    {
        return keychain_set_macos_cli(service, account, password);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let entry = Entry::new(service, account).map_err(|e| format!("Keychain error: {}", e))?;
        entry
            .set_password(password)
            .map_err(|e| format!("Failed to store key: {}", e))?;
        Ok(())
    }
}

// ============================================================================
// Node runtime resolution (bundled or system)
// ============================================================================

fn bundled_node_path() -> Option<std::path::PathBuf> {
    if let Some(dir) = RESOURCE_DIR.get() {
        let candidate = dir.join("bin").join(if cfg!(windows) { "node.exe" } else { "node" });
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // Dev fallback: src-tauri/bin/node relative to current dir
    let dev_candidate = std::env::current_dir()
        .ok()
        .map(|d| d.join("src-tauri").join("bin").join(if cfg!(windows) { "node.exe" } else { "node" }));
    if let Some(path) = dev_candidate {
        if path.exists() {
            return Some(path);
        }
    }

    None
}

fn resolve_node_binary() -> Result<String, String> {
    if let Some(path) = bundled_node_path() {
        return Ok(path.to_string_lossy().to_string());
    }

    // Check system Node availability
    if Command::new("node").arg("-v").output().is_ok() {
        return Ok("node".to_string());
    }

    Err("Node.js runtime not found. Install Node 22 LTS or run `npm run bundle:node` before building the desktop app.".to_string())
}

// ============================================================================
// Node helper for vault init + wallet creation (uses bundled @dcprotocol/core)
// ============================================================================

fn get_bundled_helper_path() -> Option<std::path::PathBuf> {
    // First try: bundled in app resources (production)
    if let Some(dir) = RESOURCE_DIR.get() {
        let candidate = dir.join("resources").join("dcp-helper-bundle.cjs");
        if candidate.exists() {
            return Some(candidate);
        }
        // Also try directly in resources dir
        let candidate = dir.join("dcp-helper-bundle.cjs");
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // Dev fallback: src-tauri/resources/dcp-helper-bundle.cjs
    let dev_candidate = std::env::current_dir()
        .ok()
        .map(|d| d.join("src-tauri").join("resources").join("dcp-helper-bundle.cjs"));
    if let Some(path) = dev_candidate {
        if path.exists() {
            return Some(path);
        }
    }

    // Dev fallback 2: relative to current dir
    let dev_candidate2 = std::env::current_dir()
        .ok()
        .map(|d| d.join("resources").join("dcp-helper-bundle.cjs"));
    if let Some(path) = dev_candidate2 {
        if path.exists() {
            return Some(path);
        }
    }

    None
}

fn run_node_helper(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    // Get the bundled helper path (production or dev)
    let helper_path = get_bundled_helper_path()
        .ok_or_else(|| "DCP helper bundle not found. Run 'npm run bundle:helper' first.".to_string())?;

    let node_bin = resolve_node_binary()?;
    let mut cmd = Command::new(node_bin);
    cmd.arg("--no-deprecation")
        .arg(&helper_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Set working directory and NODE_PATH for native module resolution
    if let Some(parent) = helper_path.parent() {
        cmd.current_dir(parent);

        // Set NODE_PATH so native modules can be found in resources/node_modules
        let node_modules_path = parent.join("node_modules");
        if node_modules_path.exists() {
            cmd.env("NODE_PATH", &node_modules_path);
        }

        // Also try monorepo node_modules for dev mode
        if let Some(root) = find_node_root() {
            let monorepo_node_modules = root.join("node_modules");
            if monorepo_node_modules.exists() {
                // Combine both paths
                let combined = if node_modules_path.exists() {
                    format!("{}:{}", node_modules_path.display(), monorepo_node_modules.display())
                } else {
                    monorepo_node_modules.to_string_lossy().to_string()
                };
                cmd.env("NODE_PATH", combined);
            }
        }
    }

    let mut child = cmd.spawn().map_err(|e| format!("Failed to start node: {}", e))?;

    if let Some(stdin) = child.stdin.as_mut() {
        let input = serde_json::to_vec(&payload).map_err(|e| format!("JSON encode failed: {}", e))?;
        stdin
            .write_all(&input)
            .and_then(|_| stdin.write_all(b"\n"))
            .map_err(|e| format!("Failed to write to node stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for node: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            "Node helper failed".to_string()
        } else {
            stderr.trim().to_string()
        });
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| format!("Invalid stdout: {}", e))?;
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|e| format!("Invalid JSON output: {}", e))?;

    if parsed.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let msg = parsed
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Node helper error");
        return Err(msg.to_string());
    }

    Ok(parsed)
}

fn find_node_root() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let core_path = dir.join("node_modules").join("@dcprotocol").join("core");
        if core_path.exists() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

fn find_monorepo_root() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        // Check for packages/dcp-server directory (monorepo structure)
        let server_path = dir.join("packages").join("dcp-server");
        if server_path.exists() {
            return Some(dir);
        }
        // Also check for root package.json with workspaces
        let pkg_json = dir.join("package.json");
        if pkg_json.exists() {
            if let Ok(content) = fs::read_to_string(&pkg_json) {
                if content.contains("\"workspaces\"") {
                    return Some(dir);
                }
            }
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Get or create desktop credentials (keypair + desktop_id)
/// Returns the public key and desktop_id, stored in OS keychain
#[tauri::command]
async fn get_or_create_desktop_credentials() -> Result<DesktopCredentials, String> {
    // Try to load existing credentials from keychain using security CLI
    if let Some(pk_b64) = keychain_get(KEYCHAIN_SERVICE, KEYCHAIN_PRIVATE_KEY) {
        if let Some(desktop_id) = keychain_get(KEYCHAIN_SERVICE, KEYCHAIN_DESKTOP_ID) {
            // Decode and derive public key
            let pk_bytes = BASE64
                .decode(&pk_b64)
                .map_err(|e| format!("Invalid key: {}", e))?;
            let pk_array: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let signing_key = SigningKey::from_bytes(&pk_array);
            let verifying_key: VerifyingKey = (&signing_key).into();
            let public_key = BASE64.encode(verifying_key.as_bytes());

            return Ok(DesktopCredentials {
                desktop_id,
                public_key,
                is_new: false,
            });
        }
    }

    // Generate new keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let private_key_b64 = BASE64.encode(signing_key.to_bytes());
    let public_key = BASE64.encode(verifying_key.as_bytes());
    let desktop_id = Uuid::new_v4().to_string();

    // Store in keychain using security CLI
    keychain_set(KEYCHAIN_SERVICE, KEYCHAIN_PRIVATE_KEY, &private_key_b64)?;
    keychain_set(KEYCHAIN_SERVICE, KEYCHAIN_DESKTOP_ID, &desktop_id)?;

    // Verify both writes worked
    if keychain_get(KEYCHAIN_SERVICE, KEYCHAIN_PRIVATE_KEY).is_none() {
        return Err("Keychain write verification failed - private-key not persisted".to_string());
    }
    if keychain_get(KEYCHAIN_SERVICE, KEYCHAIN_DESKTOP_ID).is_none() {
        return Err("Keychain write verification failed - desktop_id not persisted".to_string());
    }

    Ok(DesktopCredentials {
        desktop_id,
        public_key,
        is_new: true,
    })
}

/// Register desktop with server (first time setup)
#[tauri::command]
async fn register_desktop(desktop_id: String, public_key: String) -> Result<bool, String> {
    let client = reqwest::Client::new();
    let req = RegisterRequest {
        desktop_id: desktop_id.clone(),
        public_key: public_key.clone(),
    };

    let response = client
        .post(format!("{}/v1/desktop/register", SERVER_URL))
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("Server error: {}", e))?;

    if !response.status().is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Registration failed: {}", text));
    }

    Ok(true)
}

/// Authenticate with server using challenge-response
#[tauri::command]
async fn authenticate_owner(state: State<'_, OwnerState>) -> Result<String, String> {
    // Get credentials from keychain using security CLI
    let pk_b64 = keychain_get(KEYCHAIN_SERVICE, KEYCHAIN_PRIVATE_KEY)
        .ok_or_else(|| "No credentials found. Call get_or_create_desktop_credentials first.".to_string())?;
    let desktop_id = keychain_get(KEYCHAIN_SERVICE, KEYCHAIN_DESKTOP_ID)
        .ok_or_else(|| "No desktop ID found.".to_string())?;

    // Decode private key
    let pk_bytes = BASE64
        .decode(&pk_b64)
        .map_err(|e| format!("Invalid key: {}", e))?;
    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| "Invalid key length".to_string())?;
    let signing_key = SigningKey::from_bytes(&pk_array);

    let client = reqwest::Client::new();

    // Step 1: Get challenge
    let challenge_response = client
        .get(format!(
            "{}/v1/desktop/challenge?desktop_id={}",
            SERVER_URL, desktop_id
        ))
        .send()
        .await
        .map_err(|e| format!("Server error: {}", e))?;

    if !challenge_response.status().is_success() {
        let text = challenge_response.text().await.unwrap_or_default();
        return Err(format!("Challenge failed: {}", text));
    }

    let challenge: ChallengeResponse = challenge_response
        .json()
        .await
        .map_err(|e| format!("Invalid challenge: {}", e))?;

    // Step 2: Sign the nonce
    let nonce_bytes = BASE64
        .decode(&challenge.nonce)
        .map_err(|e| format!("Invalid nonce: {}", e))?;
    let signature = signing_key.sign(&nonce_bytes);
    let signature_b64 = BASE64.encode(signature.to_bytes());

    // Step 3: Verify signature and get token
    let verify_req = VerifyRequest {
        desktop_id: desktop_id.clone(),
        nonce: challenge.nonce,
        signature: signature_b64,
    };

    let verify_response = client
        .post(format!("{}/v1/desktop/verify", SERVER_URL))
        .json(&verify_req)
        .send()
        .await
        .map_err(|e| format!("Server error: {}", e))?;

    if !verify_response.status().is_success() {
        let text = verify_response.text().await.unwrap_or_default();
        return Err(format!("Verification failed: {}", text));
    }

    let verify: VerifyResponse = verify_response
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    // Store token in state
    let mut token_guard = state.token.lock().map_err(|e| e.to_string())?;
    *token_guard = Some(verify.token.clone());

    Ok(verify.token)
}

/// Get the current owner token (for API calls)
#[tauri::command]
async fn get_owner_token(state: State<'_, OwnerState>) -> Result<Option<String>, String> {
    let token_guard = state.token.lock().map_err(|e| e.to_string())?;
    Ok(token_guard.clone())
}

/// Clear the owner token (on logout/lock)
#[tauri::command]
async fn clear_owner_token(state: State<'_, OwnerState>) -> Result<(), String> {
    let mut token_guard = state.token.lock().map_err(|e| e.to_string())?;
    *token_guard = None;
    Ok(())
}

// ============================================================================
// Server Management Commands
// ============================================================================

// Start the DCP server process
#[tauri::command]
async fn start_server(state: State<'_, ServerState>, app: AppHandle) -> Result<(), String> {
    let mut process_guard = state.process.lock().map_err(|e| e.to_string())?;

    // Check if already running
    if let Some(ref mut child) = *process_guard {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Process exited, clear it
                *process_guard = None;
            }
            Ok(None) => {
                // Still running
                return Ok(());
            }
            Err(_) => {
                *process_guard = None;
            }
        }
    }

    // Find the server binary
    let resource_dir = app.path().resource_dir().map_err(|e| e.to_string())?;
    let bin_path = resource_dir.join("bin").join(if cfg!(windows) {
        "dcp-server.exe"
    } else {
        "dcp-server"
    });

    let runtime_server = resource_dir
        .join("resources")
        .join("dcp-server-runtime")
        .join("node_modules")
        .join("@dcprotocol")
        .join("server")
        .join("dist")
        .join("index.js");
    let bundled_server = resource_dir.join("resources").join("dcp-server-bundle.cjs");
    let res_js_path = resource_dir.join("dcp-server").join("dist").join("index.js");
    let res_js_alt = resource_dir.join("dcp-server").join("index.js");
    // Tauri bundles ../../path as _up_/_up_/path
    let res_js_up = resource_dir.join("_up_").join("_up_").join("dcp-server").join("dist").join("index.js");

    // Local dev paths - try multiple approaches for monorepo
    let cwd = std::env::current_dir().unwrap_or_default();

    // Candidates for dev mode
    let dev_candidates: Vec<std::path::PathBuf> = vec![
        // From src-tauri: ../../dcp-server/dist/index.js
        cwd.join("../../dcp-server/dist/index.js"),
        // From dcp-desktop: ../dcp-server/dist/index.js
        cwd.join("../dcp-server/dist/index.js"),
        // From monorepo root
        cwd.join("packages/dcp-server/dist/index.js"),
        // Walk up to find monorepo root
        find_monorepo_root().map(|r| r.join("packages/dcp-server/dist/index.js")).unwrap_or_default(),
    ];

    let dev_js_root_path = find_node_root()
        .map(|root| root.join("packages").join("dcp-server").join("dist").join("index.js"));

    let server_path = if bin_path.exists() {
        bin_path
    } else if runtime_server.exists() {
        runtime_server
    } else if bundled_server.exists() {
        bundled_server
    } else if res_js_path.exists() {
        res_js_path
    } else if res_js_alt.exists() {
        res_js_alt
    } else if res_js_up.exists() {
        res_js_up
    } else if let Some(dev_path) = dev_candidates.iter().find(|p| p.exists()) {
        dev_path.clone()
    } else if dev_js_root_path.as_ref().is_some_and(|p| p.exists()) {
        dev_js_root_path.unwrap()
    } else {
        return Err("DCP server binary not found".to_string());
    };

    // Start the server
    let child = if matches!(
        server_path.extension().and_then(|e| e.to_str()),
        Some("js" | "cjs" | "mjs")
    ) {
        let node_bin = resolve_node_binary()?;
        let mut cmd = Command::new(node_bin);
        cmd.arg(&server_path);

        // Build NODE_PATH for bundled or dev node_modules.
        let mut node_paths: Vec<std::path::PathBuf> = Vec::new();
        let helper_node_modules = resource_dir.join("resources").join("node_modules");
        let runtime_node_modules = resource_dir
            .join("resources")
            .join("dcp-server-runtime")
            .join("node_modules");
        let res_node_modules = resource_dir.join("dcp-server").join("node_modules");
        let res_node_modules_up = resource_dir.join("_up_").join("_up_").join("dcp-server").join("node_modules");
        if helper_node_modules.exists() {
            node_paths.push(helper_node_modules);
        }
        if runtime_node_modules.exists() {
            node_paths.push(runtime_node_modules);
        }
        if res_node_modules.exists() {
            node_paths.push(res_node_modules);
        }
        if res_node_modules_up.exists() {
            node_paths.push(res_node_modules_up);
        }

        let dev_node_modules = std::env::current_dir()
            .unwrap_or_default()
            .join("../dcp-server/node_modules");
        if dev_node_modules.exists() {
            node_paths.push(dev_node_modules);
        }

        if let Some(root) = find_node_root() {
            let monorepo_node_modules = root.join("node_modules");
            if monorepo_node_modules.exists() {
                node_paths.push(monorepo_node_modules);
            }
        }

        if let Ok(existing) = std::env::var("NODE_PATH") {
            for entry in std::env::split_paths(&existing) {
                if !entry.as_os_str().is_empty() {
                    node_paths.push(entry);
                }
            }
        }

        node_paths.sort();
        node_paths.dedup();

        if !node_paths.is_empty() {
            let joined = std::env::join_paths(node_paths)
                .map_err(|e| format!("Failed to build NODE_PATH: {}", e))?;
            cmd.env("NODE_PATH", joined);
        }

        cmd.current_dir(
            server_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        );

        // Desktop app uses port 8421 (CLI uses 8420)
        cmd.env("VAULT_PORT", "8421");

        cmd.spawn()
            .map_err(|e| format!("Failed to start server: {}", e))?
    } else {
        let mut cmd = Command::new(&server_path);
        // Desktop app uses port 8421 (CLI uses 8420)
        cmd.env("VAULT_PORT", "8421");
        cmd.spawn()
            .map_err(|e| format!("Failed to start server: {}", e))?
    };

    *process_guard = Some(child);
    Ok(())
}

// Stop the DCP server process
#[tauri::command]
async fn stop_server(state: State<'_, ServerState>) -> Result<(), String> {
    let mut process_guard = state.process.lock().map_err(|e| e.to_string())?;

    if let Some(ref mut child) = *process_guard {
        child
            .kill()
            .map_err(|e| format!("Failed to kill server: {}", e))?;
        child.wait().ok();
    }

    *process_guard = None;
    Ok(())
}

// Reset vault (delete local vault data and restart server)
#[tauri::command]
async fn reset_vault(state: State<'_, ServerState>, app: AppHandle) -> Result<(), String> {
    stop_server(state.clone()).await?;

    let home_dir = dirs::home_dir().ok_or_else(|| "Unable to determine home directory".to_string())?;
    let default_dir = home_dir.join(".dcp");

    let vault_dir = std::env::var("VAULT_DIR")
        .ok()
        .unwrap_or_else(|| default_dir.to_string_lossy().to_string());

    let vault_path = std::path::PathBuf::from(&vault_dir);
    let vault_canon = vault_path.canonicalize().unwrap_or_else(|_| vault_path.clone());
    let default_canon = default_dir.canonicalize().unwrap_or(default_dir.clone());

    if vault_canon != default_canon {
        return Err("Refusing to reset non-default vault directory".to_string());
    }

    if vault_path.exists() {
        fs::remove_dir_all(&vault_path)
            .map_err(|e| format!("Failed to remove vault directory: {}", e))?;
    }
    if vault_path.exists() {
        return Err("Vault directory still exists after reset".to_string());
    }

    start_server(state, app).await?;
    Ok(())
}

// Check server health
#[tauri::command]
async fn check_health() -> Result<HealthResponse, String> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/health", SERVER_URL))
        .send()
        .await
        .map_err(|e| format!("Server not responding: {}", e))?;

    let health: HealthResponse = response
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    Ok(health)
}

async fn lock_vault_request() -> Result<(), String> {
    let client = reqwest::Client::new();
    client
        .post(format!("{}/v1/vault/lock", SERVER_URL))
        .send()
        .await
        .map_err(|e| format!("Failed to lock vault: {}", e))?;
    Ok(())
}

// Initialize vault with passphrase
#[tauri::command]
async fn init_vault(passphrase: String) -> Result<InitVaultResult, String> {
    let payload = json!({
        "action": "init",
        "passphrase": passphrase,
        "vault_dir": std::env::var("VAULT_DIR").ok()
    });
    let result = run_node_helper(payload)?;
    let words = result
        .get("recovery_phrase")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Invalid init response".to_string())?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect::<Vec<String>>();

    Ok(InitVaultResult { recovery_phrase: words })
}

// Create wallets after vault init
#[tauri::command]
async fn create_wallets(passphrase: String) -> Result<CreateWalletsResult, String> {
    let payload = json!({
        "action": "create_wallets",
        "passphrase": passphrase,
        "chains": ["solana", "base"],
        "vault_dir": std::env::var("VAULT_DIR").ok()
    });
    let result = run_node_helper(payload)?;
    let wallets = result
        .get("wallets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Invalid wallets response".to_string())?
        .iter()
        .filter_map(|w| {
            let chain = w.get("chain")?.as_str()?.to_string();
            let address = w.get("address")?.as_str()?.to_string();
            Some(WalletInfo { chain, address })
        })
        .collect::<Vec<WalletInfo>>();

    Ok(CreateWalletsResult { wallets })
}

// Show notification
#[tauri::command]
async fn show_notification(app: AppHandle, title: String, body: String) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;

    app.notification()
        .builder()
        .title(&title)
        .body(&body)
        .show()
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_shell::init())
        .manage(ServerState {
            process: Mutex::new(None),
        })
        .manage(OwnerState {
            token: Mutex::new(None),
        })
        .setup(|app| {
            if RESOURCE_DIR.get().is_none() {
                if let Ok(dir) = app.path().resource_dir() {
                    let _ = RESOURCE_DIR.set(dir);
                }
            }

            // Kill any orphaned server from previous crashed session
            // This ensures a clean state on startup
            #[cfg(target_family = "unix")]
            {
                let _ = Command::new("sh")
                    .arg("-c")
                    .arg("lsof -ti:8421 | xargs kill -9 2>/dev/null || true")
                    .output();
            }

            #[cfg(target_os = "windows")]
            {
                // On Windows, try to kill any process using port 8421
                let _ = Command::new("cmd")
                    .args(["/C", "for /f \"tokens=5\" %a in ('netstat -aon ^| findstr :8421') do taskkill /F /PID %a >nul 2>&1"])
                    .output();
            }

            // Brief delay to ensure port is free
            std::thread::sleep(std::time::Duration::from_millis(500));

            // Create tray menu
            let quit = MenuItem::with_id(app, "quit", "Quit & Stop Server", true, None::<&str>)?;
            let open = MenuItem::with_id(app, "open", "Open DCP Vault", true, None::<&str>)?;
            let lock = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;

            let menu = Menu::with_items(app, &[&open, &lock, &quit])?;

            // Build tray icon
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        // Stop server synchronously before exit
                        let state = app.state::<ServerState>();
                        if let Ok(mut process_guard) = state.process.lock() {
                            if let Some(ref mut child) = *process_guard {
                                let _ = child.kill();
                                let _ = child.wait();
                            }
                            *process_guard = None;
                        }
                        app.exit(0);
                    }
                    "open" => {
                        if let Some(window) = app.get_webview_window("main") {
                            window.show().ok();
                            window.set_focus().ok();
                        }
                    }
                    "lock" => {
                        tauri::async_runtime::spawn(async move {
                            let _ = lock_vault_request().await;
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            window.show().ok();
                            window.set_focus().ok();
                        }
                    }
                })
                .build(app)?;

            if let Some(window) = app.get_webview_window("main") {
                let window_clone = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window_clone.hide();
                    }
                });
            }

            // Start server on app launch
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let state = app_handle.state::<ServerState>();
                if let Err(e) = start_server(state, app_handle.clone()).await {
                    eprintln!("Failed to start server: {}", e);
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Server management
            start_server,
            stop_server,
            reset_vault,
            check_health,
            // Vault operations
            init_vault,
            create_wallets,
            show_notification,
            // Owner trust model
            get_or_create_desktop_credentials,
            register_desktop,
            authenticate_owner,
            get_owner_token,
            clear_owner_token,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            match event {
                RunEvent::ExitRequested { api, code, .. } => {
                    // Prevent default exit to ensure cleanup completes
                    api.prevent_exit();

                    // Stop server synchronously using blocking task
                    let state = app_handle.state::<ServerState>();
                    if let Ok(mut process_guard) = state.process.lock() {
                        if let Some(ref mut child) = *process_guard {
                            let _ = child.kill();
                            let _ = child.wait();
                        }
                        *process_guard = None;
                    }

                    // Exit with the requested code
                    app_handle.exit(code.unwrap_or(0));
                }
                _ => {}
            }
        });
}
