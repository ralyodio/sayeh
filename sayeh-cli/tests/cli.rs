use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
#[test]
fn password_commands_round_trip_scan_strip_and_analyse() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let cover = directory.path().join("cover.txt");
    let secret = directory.path().join("secret.txt");
    let password = directory.path().join("password.txt");
    let hidden = directory.path().join("hidden.txt");
    let revealed = directory.path().join("revealed.txt");
    let clean = directory.path().join("clean.txt");
    fs::write(&cover, ". ".repeat(5_000))?;
    fs::write(&secret, "پیام آزمایشی 👨‍👩‍👧")?;
    fs::write(&password, "test password\n")?;

    success(run(
        directory.path(),
        [
            "hide",
            "--cover-file",
            path(&cover),
            "--secret-file",
            path(&secret),
            "--password-file",
            path(&password),
            "--output",
            path(&hidden),
        ],
    )?)?;
    let scan = success(run(
        directory.path(),
        ["--json", "scan", "--input", path(&hidden)],
    )?)?;
    let scan: Value = serde_json::from_slice(&scan.stdout)?;
    assert_eq!(scan["wire_version"], 4);
    assert_eq!(scan["mode"], "password");

    success(run(
        directory.path(),
        [
            "reveal",
            "--input",
            path(&hidden),
            "--password-file",
            path(&password),
            "--output",
            path(&revealed),
        ],
    )?)?;
    assert_eq!(fs::read(&revealed)?, fs::read(&secret)?);

    success(run(
        directory.path(),
        ["strip", "--input", path(&hidden), "--output", path(&clean)],
    )?)?;
    assert_eq!(fs::read(&clean)?, fs::read(&cover)?);
    success(run(
        directory.path(),
        ["analyse", "--input", path(&hidden)],
    )?)?;
    success(run(directory.path(), ["capacity", "--cover", "two words"])?)?;
    Ok(())
}

#[test]
fn encrypted_contact_store_probe_preference_and_replay_work_end_to_end()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let alice_vault = directory.path().join("alice.syk");
    let bob_vault = directory.path().join("bob.syk");
    let alice = identity(directory.path(), &alice_vault)?;
    let bob = identity(directory.path(), &bob_vault)?;

    success(run_with_vault(
        directory.path(),
        &alice_vault,
        [
            "contact",
            "add",
            "Bob",
            "--public",
            json_string(&bob, "public_key_hex")?,
        ],
    )?)?;
    success(run_with_vault(
        directory.path(),
        &bob_vault,
        [
            "contact",
            "add",
            "Alice",
            "--public",
            json_string(&alice, "public_key_hex")?,
        ],
    )?)?;

    let probe = directory.path().join("probe.txt");
    success(run(
        directory.path(),
        ["probe", "generate", "--output", path(&probe)],
    )?)?;
    let probe_report = success(run_with_vault(
        directory.path(),
        &alice_vault,
        [
            "--json",
            "probe",
            "analyse",
            "--input",
            path(&probe),
            "--app",
            "test-chat",
            "--contact",
            "Bob",
        ],
    )?)?;
    let probe_report: Value = serde_json::from_slice(&probe_report.stdout)?;
    assert_eq!(probe_report["recommendation"], "unicode-tags");

    let cover = directory.path().join("contact-cover.txt");
    let secret = directory.path().join("contact-secret.txt");
    let hidden = directory.path().join("contact-hidden.txt");
    let revealed = directory.path().join("contact-revealed.txt");
    fs::write(&cover, ". ".repeat(5_000))?;
    fs::write(&secret, "authenticated contact message")?;
    success(run_with_vault(
        directory.path(),
        &alice_vault,
        [
            "hide",
            "--cover-file",
            path(&cover),
            "--secret-file",
            path(&secret),
            "--contact",
            "Bob",
            "--app",
            "test-chat",
            "--output",
            path(&hidden),
        ],
    )?)?;
    let scan = success(run(
        directory.path(),
        ["--json", "scan", "--input", path(&hidden)],
    )?)?;
    let scan: Value = serde_json::from_slice(&scan.stdout)?;
    assert_eq!(scan["mode"], "contact");
    assert_eq!(scan["carrier"], "unicode-tags");

    success(run_with_vault(
        directory.path(),
        &bob_vault,
        [
            "reveal",
            "--input",
            path(&hidden),
            "--output",
            path(&revealed),
        ],
    )?)?;
    assert_eq!(fs::read(&revealed)?, fs::read(&secret)?);
    let replay = run_with_vault(
        directory.path(),
        &bob_vault,
        [
            "reveal",
            "--input",
            path(&hidden),
            "--output",
            path(&revealed),
        ],
    )?;
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("already seen"));

    let encrypted = fs::read(&alice_vault)?;
    assert!(!contains(&encrypted, b"Bob"));
    assert!(!contains(
        &encrypted,
        json_string(&bob, "public_key_hex")?.as_bytes()
    ));
    Ok(())
}

fn identity(directory: &Path, vault: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let output = success(run_with_vault(
        directory,
        vault,
        ["--json", "identity", "init"],
    )?)?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn run<const N: usize>(directory: &Path, args: [&str; N]) -> std::io::Result<Output> {
    command(directory).args(args).output()
}

fn run_with_vault<const N: usize>(
    directory: &Path,
    vault: &Path,
    args: [&str; N],
) -> std::io::Result<Output> {
    command(directory)
        .arg("--vault")
        .arg(vault)
        .args(args)
        .output()
}

fn command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sayeh"));
    command
        .current_dir(directory)
        .env("SAYEH_PASSWORD", "test password")
        .env("SAYEH_VAULT_PASSWORD", "vault test password");
    command
}

fn success(output: Output) -> Result<Output, Box<dyn std::error::Error>> {
    if output.status.success() {
        return Ok(output);
    }
    Err(format!(
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap_or("")
}

fn json_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing JSON string {key}").into())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
