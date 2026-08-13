use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use qrcode::QrCode;
use qrcode::render::unicode;
use sayeh_core::carrier::{CarrierKind, strip_aggressive};
use sayeh_core::contact::{
    ContactCandidate, ContactOptions, IdentityPublic, IdentitySecret, fingerprint, hide_contact,
    reveal_contact,
};
use sayeh_core::container::ModeHeader;
use sayeh_core::crypto::Argon2Params;
use sayeh_core::pipeline::{
    CapacityMode, PasswordOptions, capacity, clean_safe, hide_password, reveal_password, scan,
};
use sayeh_core::{probe, steganalysis};
use serde_json::json;

use crate::args::{
    AnalyseArgs, CapacityArgs, Cli, Command, ContactCommand, HideArgs, IdentityCommand, InputArgs,
    ModeChoice, ProbeCommand, RevealArgs, StripArgs,
};
use crate::io::{
    new_vault_password, now, password, read_content, read_cover, read_text, write_output,
};
use crate::store::{ContactRecord, Vault};

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Hide(args) => hide(args, cli.vault, cli.json),
        Command::Reveal(args) => reveal(args, cli.vault, cli.json),
        Command::Scan(args) => scan_command(args, cli.json),
        Command::Strip(args) => strip(args),
        Command::Analyse(args) => analyse(args, cli.json),
        Command::Capacity(args) => estimate(args, cli.json),
        Command::Probe(args) => probe_command(args.command, cli.vault, cli.json),
        Command::Identity(args) => identity(args.command, cli.vault, cli.json),
        Command::Contact(args) => contact(args.command, cli.vault, cli.json),
    }
}

fn hide(args: HideArgs, vault_override: Option<PathBuf>, json_output: bool) -> Result<()> {
    let cover = read_cover(args.cover, args.cover_file)?;
    let content = read_content(args.secret_file, args.file)?;
    let created_at = now()?;

    let hidden = if let Some(contact_name) = args.contact {
        if args.password_file.is_some()
            || args.argon_memory_kib.is_some()
            || args.argon_passes.is_some()
            || args.argon_lanes.is_some()
        {
            bail!("password and Argon2 options do not apply to contact mode");
        }
        let path = crate::store::path(vault_override)?;
        let vault_password = vault_password()?;
        let mut vault = Vault::load(&path, &vault_password)?;
        let index = vault
            .contact_index(&contact_name)
            .with_context(|| format!("contact {contact_name:?} was not found"))?;
        let (recipient, carrier, counter) = {
            let record = vault
                .contacts
                .get(index)
                .context("contact index changed unexpectedly")?;
            let carrier = match args.carrier {
                Some(carrier) => carrier,
                None => record.preferred_carrier(args.app.as_deref(), &args.path)?,
            };
            (
                record.public()?,
                carrier,
                record
                    .send_counter
                    .checked_add(1)
                    .context("contact send counter exhausted")?,
            )
        };
        let identity = vault.identity();
        let hidden = hide_contact(
            &cover,
            content.as_content(),
            &identity,
            recipient,
            ContactOptions {
                carrier,
                counter,
                created_at,
            },
        )?;
        if let Some(record) = vault.contacts.get_mut(index) {
            record.send_counter = counter;
        }
        vault.save(&path, &vault_password)?;
        hidden
    } else {
        let secret = password(
            args.password_file.as_deref(),
            "SAYEH_PASSWORD",
            "Message password: ",
        )?;
        let defaults = Argon2Params::DEFAULT;
        let parameters = Argon2Params::new(
            args.argon_memory_kib.unwrap_or(defaults.memory_kib()),
            args.argon_passes.unwrap_or(defaults.passes()),
            args.argon_lanes.unwrap_or(defaults.lanes()),
        )?;
        hide_password(
            &cover,
            content.as_content(),
            &secret,
            PasswordOptions {
                carrier: args.carrier.unwrap_or(CarrierKind::ZeroWidth),
                parameters,
                created_at,
            },
        )?
    };

    write_output(args.output.as_deref(), hidden.text.as_bytes())?;
    if json_output {
        eprintln!(
            "{}",
            serde_json::to_string(&json!({
                "carrier": hidden.report.carrier.name(),
                "content_bytes": hidden.report.content_bytes,
                "container_bytes": hidden.report.container_bytes,
                "carrier_symbols": hidden.report.carrier_symbols,
                "safe_slots": hidden.report.safe_slots,
                "compressed": hidden.report.compressed,
                "suspicion_score": hidden.report.analysis.suspicion_score,
                "likely_detectable": hidden.report.analysis.likely_detectable()
            }))?
        );
    } else {
        eprintln!(
            "hidden: {} bytes, {} / {} safe symbols, detector {}/100{}",
            hidden.report.content_bytes,
            hidden.report.carrier_symbols,
            hidden.report.safe_slots,
            hidden.report.analysis.suspicion_score,
            if hidden.report.analysis.likely_detectable() {
                " (warning: likely detectable)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn reveal(args: RevealArgs, vault_override: Option<PathBuf>, json_output: bool) -> Result<()> {
    let text = read_text(args.input.as_deref())?;
    let scanned = scan(&text)?;
    match scanned.container().header().mode() {
        ModeHeader::Password(_) => {
            let secret = password(
                args.password_file.as_deref(),
                "SAYEH_PASSWORD",
                "Message password: ",
            )?;
            let opened = reveal_password(&text, &secret)?;
            require_file_output(opened.is_text(), args.output.as_deref())?;
            write_output(args.output.as_deref(), opened.bytes())?;
            reveal_report(
                opened.file_name(),
                opened.bytes().len(),
                None,
                opened.counter(),
                json_output,
            )
        }
        ModeHeader::Contact(_) => {
            if args.password_file.is_some() {
                bail!("--password-file does not apply to contact-mode payloads");
            }
            let path = crate::store::path(vault_override)?;
            let vault_password = vault_password()?;
            let mut vault = Vault::load(&path, &vault_password)?;
            let candidates: Vec<ContactCandidate> = vault
                .contacts
                .iter()
                .map(|contact| {
                    Ok(ContactCandidate {
                        public: contact.public()?,
                        last_seen_counter: contact.last_seen_counter,
                    })
                })
                .collect::<Result<_>>()?;
            let opened = reveal_contact(&text, &vault.identity(), &candidates)?;
            require_file_output(opened.payload.is_text(), args.output.as_deref())?;
            let record = vault
                .contacts
                .get_mut(opened.candidate_index)
                .context("authenticated contact index is missing")?;
            record.last_seen_counter = opened.payload.counter();
            let contact_name = record.name.clone();
            vault.save(&path, &vault_password)?;
            write_output(args.output.as_deref(), opened.payload.bytes())?;
            reveal_report(
                opened.payload.file_name(),
                opened.payload.bytes().len(),
                Some(&contact_name),
                opened.payload.counter(),
                json_output,
            )
        }
    }
}

fn scan_command(args: InputArgs, json_output: bool) -> Result<()> {
    let text = read_text(args.input.as_deref())?;
    let scanned = scan(&text)?;
    let container = scanned.container();
    let container_bytes = container.marshal()?.len();
    let (mode, kdf) = match container.header().mode() {
        ModeHeader::Password(header) => (
            "password",
            Some(json!({
                "algorithm": "Argon2id",
                "memory_kib": header.parameters().memory_kib(),
                "passes": header.parameters().passes(),
                "lanes": header.parameters().lanes()
            })),
        ),
        ModeHeader::Contact(_) => ("contact", None),
    };
    let value = json!({
        "wire_version": 4,
        "mode": mode,
        "carrier": scanned.carrier().name(),
        "compressed": container.header().compressed(),
        "error_correction": container.header().error_correction(),
        "correction_budget_symbols": 0,
        "container_bytes": container_bytes,
        "carrier_symbols": scanned.symbols(),
        "kdf": kdf
    });
    if json_output {
        println!("{}", serde_json::to_string(&value)?);
    } else {
        println!("Sayeh v4 {mode} payload");
        println!("carrier: {}", scanned.carrier().name());
        println!(
            "container: {container_bytes} bytes, {} symbols",
            scanned.symbols()
        );
        println!("compressed: {}", container.header().compressed());
        println!("error correction: no");
        if let Some(kdf) = kdf {
            println!("KDF: {kdf}");
        }
    }
    Ok(())
}

fn strip(args: StripArgs) -> Result<()> {
    let text = read_text(args.input.as_deref())?;
    let clean = if args.aggressive {
        eprintln!("warning: aggressive cleaning can change Persian spelling and split emoji");
        strip_aggressive(&text)
    } else {
        clean_safe(&text)
    };
    write_output(args.output.as_deref(), clean.as_bytes())
}

fn analyse(args: AnalyseArgs, json_output: bool) -> Result<()> {
    let text = read_text(args.input.as_deref())?;
    let carriers: Vec<CarrierKind> = args
        .carrier
        .map_or_else(|| CarrierKind::ALL.to_vec(), |carrier| vec![carrier]);
    let reports: Vec<_> = carriers
        .into_iter()
        .map(|carrier| steganalysis::analyse(&text, carrier))
        .filter(|report| report.symbols > 0 || args.carrier.is_some())
        .collect();
    if json_output {
        let values: Vec<_> = reports.iter().map(analysis_json).collect();
        println!("{}", serde_json::to_string(&values)?);
    } else if reports.is_empty() {
        println!("no v4 carrier characters found");
    } else {
        for report in reports {
            println!(
                "{}: {} symbols, density {:.6}, chi-square {:.3}, longest run {}, entropy {:.3}, score {}/100",
                report.carrier.name(),
                report.symbols,
                report.density,
                report.chi_square,
                report.longest_run,
                report.positional_entropy,
                report.suspicion_score
            );
        }
    }
    Ok(())
}

fn estimate(args: CapacityArgs, json_output: bool) -> Result<()> {
    let cover = read_cover(args.cover, args.cover_file)?;
    let mode = match args.mode {
        ModeChoice::Password => CapacityMode::Password,
        ModeChoice::Contact => CapacityMode::Contact,
    };
    let estimate = capacity(
        &cover,
        args.carrier,
        mode,
        args.file_name.as_deref().map_or(0, str::len),
    )?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "carrier": args.carrier.name(),
                "safe_slots": estimate.safe_slots,
                "container_bytes": estimate.container_bytes,
                "max_incompressible_content_bytes": estimate.content_bytes
            }))?
        );
    } else {
        println!("safe carrier slots: {}", estimate.safe_slots);
        println!(
            "maximum incompressible content: {} bytes",
            estimate.content_bytes
        );
        println!(
            "container at that limit: {} bytes",
            estimate.container_bytes
        );
    }
    Ok(())
}

fn probe_command(
    command: ProbeCommand,
    vault_override: Option<PathBuf>,
    json_output: bool,
) -> Result<()> {
    match command {
        ProbeCommand::Generate { output } => {
            let message = probe::generate();
            write_output(output.as_deref(), message.as_bytes())
        }
        ProbeCommand::Analyse {
            input,
            app,
            path,
            contact,
        } => {
            let text = read_text(input.as_deref())?;
            let report = probe::analyse(&text);
            let missing = report
                .scalars
                .iter()
                .filter(|scalar| scalar.survived < 3)
                .count();
            if let (Some(contact), Some(carrier)) = (contact, report.recommendation) {
                let vault_path = crate::store::path(vault_override)?;
                let secret = vault_password()?;
                let mut vault = Vault::load(&vault_path, &secret)?;
                let record = vault
                    .contact_mut(&contact)
                    .with_context(|| format!("contact {contact:?} was not found"))?;
                record.set_probe(app.clone(), path.clone(), carrier, now()?);
                vault.save(&vault_path, &secret)?;
            }
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "app": app,
                        "path": path,
                        "missing_or_changed_scalars": missing,
                        "recommendation": report.recommendation.map(CarrierKind::name)
                    }))?
                );
            } else {
                println!("app/path: {app}/{path}");
                println!("missing or changed scalars: {missing}");
                match report.recommendation {
                    Some(carrier) => println!("recommended carrier: {}", carrier.name()),
                    None => println!("no complete v4 alphabet survived this path"),
                }
            }
            Ok(())
        }
    }
}

fn identity(
    command: IdentityCommand,
    vault_override: Option<PathBuf>,
    json_output: bool,
) -> Result<()> {
    let path = crate::store::path(vault_override)?;
    match command {
        IdentityCommand::Init => {
            if path.exists() {
                bail!(
                    "an identity already exists at {}; refusing to overwrite it",
                    path.display()
                );
            }
            let secret = new_vault_password()?;
            let identity = IdentitySecret::generate()?;
            Vault::new(&identity).save(&path, &secret)?;
            print_identity(identity.public(), Some(&path), json_output)
        }
        IdentityCommand::Show => {
            let secret = vault_password()?;
            let vault = Vault::load(&path, &secret)?;
            print_identity(vault.identity().public(), None, json_output)
        }
    }
}

fn contact(
    command: ContactCommand,
    vault_override: Option<PathBuf>,
    json_output: bool,
) -> Result<()> {
    let path = crate::store::path(vault_override)?;
    let secret = vault_password()?;
    let mut vault = Vault::load(&path, &secret)?;
    match command {
        ContactCommand::Add { name, public } => {
            if name.trim().is_empty() {
                bail!("contact name must not be empty");
            }
            if vault.contact(&name).is_some() {
                bail!("contact {name:?} already exists");
            }
            let public = parse_public(&public)?;
            if vault
                .contacts
                .iter()
                .filter_map(|record| record.public().ok())
                .any(|existing| existing.ct_eq(&public))
            {
                bail!("that public key is already stored under another name");
            }
            vault
                .contacts
                .push(ContactRecord::new(name.clone(), public));
            vault.save(&path, &secret)?;
            let value = fingerprint(&public);
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "name": name,
                        "fingerprint_numeric": value.numeric,
                        "fingerprint_words": value.words
                    }))?
                );
            } else {
                println!("added {name}");
                println!("fingerprint: {}", value.numeric);
                println!("words: {}", value.words);
            }
        }
        ContactCommand::List => {
            if json_output {
                let values: Vec<_> = vault
                    .contacts
                    .iter()
                    .map(|record| {
                        let public = record.public()?;
                        let value = fingerprint(&public);
                        Ok(json!({
                            "name": record.name,
                            "fingerprint_numeric": value.numeric,
                            "fingerprint_words": value.words,
                            "carrier": record.carrier()?.name(),
                            "send_counter": record.send_counter,
                            "last_seen_counter": record.last_seen_counter,
                            "probe_records": record.probes.len()
                        }))
                    })
                    .collect::<Result<_>>()?;
                println!("{}", serde_json::to_string(&values)?);
            } else if vault.contacts.is_empty() {
                println!("no contacts");
            } else {
                for record in &vault.contacts {
                    let value = fingerprint(&record.public()?);
                    println!(
                        "{} | {} | {} | send {} / seen {}",
                        record.name,
                        value.numeric,
                        record.carrier()?.name(),
                        record.send_counter,
                        record.last_seen_counter
                    );
                }
            }
        }
        ContactCommand::Remove { name } => {
            let index = vault
                .contact_index(&name)
                .with_context(|| format!("contact {name:?} was not found"))?;
            vault.contacts.remove(index);
            vault.save(&path, &secret)?;
            println!("removed {name}");
        }
        ContactCommand::SetCarrier { name, carrier } => {
            let record = vault
                .contact_mut(&name)
                .with_context(|| format!("contact {name:?} was not found"))?;
            record.carrier_id = carrier.id();
            vault.save(&path, &secret)?;
            println!("{} now defaults to {}", name, carrier.name());
        }
    }
    Ok(())
}

fn parse_public(value: &str) -> Result<IdentityPublic> {
    let value = value
        .trim()
        .strip_prefix("sayeh:x25519:")
        .unwrap_or(value.trim());
    let compact: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    let bytes: [u8; 32] = hex::decode(compact)
        .context("decode contact public key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("contact public key must be exactly 32 bytes"))?;
    IdentityPublic::validate(bytes).context("reject low-order contact public key")
}

fn print_identity(public: IdentityPublic, created: Option<&Path>, json_output: bool) -> Result<()> {
    let value = fingerprint(&public);
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "public_key_hex": hex::encode(public.as_bytes()),
                "fingerprint_numeric": value.numeric,
                "fingerprint_words": value.words,
                "qr_payload": value.qr_payload,
                "created_vault": created.map(|path| path.display().to_string())
            }))?
        );
        return Ok(());
    }
    if let Some(path) = created {
        println!("created encrypted identity at {}", path.display());
    }
    println!("public key: {}", hex::encode(public.as_bytes()));
    println!("fingerprint: {}", value.numeric);
    println!("words: {}", value.words);
    let code = QrCode::new(value.qr_payload.as_bytes()).context("encode fingerprint QR")?;
    println!("{}", code.render::<unicode::Dense1x2>().build());
    Ok(())
}

fn vault_password() -> Result<zeroize::Zeroizing<Vec<u8>>> {
    password(None, "SAYEH_VAULT_PASSWORD", "Vault password: ")
}

fn require_file_output(text: bool, output: Option<&Path>) -> Result<()> {
    if !text && output.is_none() {
        bail!(
            "this payload is a file; pass --output so binary data is not written to the terminal"
        );
    }
    Ok(())
}

fn reveal_report(
    file_name: Option<&str>,
    bytes: usize,
    contact: Option<&str>,
    counter: u64,
    json_output: bool,
) -> Result<()> {
    if json_output {
        eprintln!(
            "{}",
            serde_json::to_string(&json!({
                "bytes": bytes,
                "file_name": file_name,
                "contact": contact,
                "counter": counter
            }))?
        );
    } else {
        eprintln!("revealed {bytes} bytes");
        if let Some(name) = file_name {
            eprintln!("file name: {name}");
        }
        if let Some(contact) = contact {
            eprintln!("authenticated contact: {contact}, counter {counter}");
        }
    }
    Ok(())
}

fn analysis_json(report: &steganalysis::Analysis) -> serde_json::Value {
    json!({
        "carrier": report.carrier.name(),
        "symbols": report.symbols,
        "visible_scalars": report.visible_scalars,
        "density": report.density,
        "chi_square": report.chi_square,
        "longest_run": report.longest_run,
        "mean_gap": report.mean_gap,
        "gap_coefficient_of_variation": report.gap_coefficient_of_variation,
        "positional_entropy": report.positional_entropy,
        "suspicion_score": report.suspicion_score,
        "likely_detectable": report.likely_detectable()
    })
}
