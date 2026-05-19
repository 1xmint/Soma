use std::path::PathBuf;

use soma::crypto::encode_base64;
use soma::delegation::{create_delegation, Caveat};
use soma::identity::HeartIdentity;
use soma::lineage::{
    create_lineage_certificate, verify_lineage_certificate, verify_lineage_chain, HeartLineage,
    LineageCertificate,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "init" => cmd_init(&args[2..]),
        "issue-lineage" => cmd_issue_lineage(&args[2..]),
        "delegate" => cmd_delegate(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "inspect" => cmd_inspect(&args[2..]),
        "status" => cmd_status(),
        _ => {
            eprintln!("unknown command: {}", args[1]);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!(
        r#"soma-ceremony — HeyVera root heart bootstrap & lineage management

USAGE:
  soma-ceremony init [--path <dir>]
      Create the HeyVera root heart. Generates a new Ed25519 keypair and
      genome commitment. Saves to ~/.heyvera/root-heart.json (or --path).

  soma-ceremony issue-lineage --agent <name> --capabilities <caps> [--budget <credits>] [--ttl <hours>]
      Issue a lineage certificate from the root heart to a child agent.
      The child agent's soma-heart.json must exist (created on first boot).
      Capabilities: comma-separated (e.g. "route:*,chat:*,spend:*").

  soma-ceremony delegate --subject-did <did> --capabilities <caps> [--budget <credits>] [--expires <hours>]
      Issue a delegation token from the root heart to a subject DID.
      Used to grant users or services access through Soma auth.

  soma-ceremony verify --file <path>
      Verify a lineage certificate or delegation token from a JSON file.

  soma-ceremony inspect --file <path>
      Pretty-print a lineage certificate, delegation token, or heart identity.

  soma-ceremony status
      Show the root heart's DID, genome, and issued lineage certificates."#
    );
}

fn root_heart_path() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".heyvera")
        .join("root-heart.json")
}

fn lineage_dir() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".heyvera")
        .join("lineage")
}

fn load_root_heart() -> HeartIdentity {
    let path = root_heart_path();
    match HeartIdentity::load(&path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: cannot load root heart from {}: {e}", path.display());
            eprintln!("Run `soma-ceremony init` first.");
            std::process::exit(1);
        }
    }
}

// ─── Commands ──────────────────────────────────────────────────────────────

fn cmd_init(args: &[String]) {
    let mut path = root_heart_path();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                path = PathBuf::from(&args[i]).join("root-heart.json");
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if path.exists() {
        let existing = HeartIdentity::load(&path).unwrap();
        println!("Root heart already exists at {}", path.display());
        println!("  DID: {}", existing.did);
        println!("  Genome hash: {}", existing.genome.hash);
        println!();
        println!("To create a NEW root heart, delete {} first.", path.display());
        return;
    }

    let heart = HeartIdentity::new("heyvera", "root-heart", "heyvera-v1").unwrap();
    heart.save(&path).unwrap();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          HeyVera Root Heart — Created                   ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  DID:         {}", heart.did);
    println!("  Public Key:  {}", encode_base64(&heart.public_key));
    println!("  Genome Hash: {}", heart.genome.hash);
    println!("  Saved To:    {}", path.display());
    println!();
    println!("  ⚠  The secret key is in this file. Guard it carefully.");
    println!("  ⚠  This identity is the root of trust for all HeyVera agents.");
    println!();
    println!("Next steps:");
    println!("  1. Start Cortex so it creates its own soma-heart.json");
    println!("  2. Run: soma-ceremony issue-lineage --agent cortex --capabilities \"route:*,chat:*,spend:*\"");
}

fn cmd_issue_lineage(args: &[String]) {
    let mut agent_name = String::new();
    let mut capabilities = Vec::new();
    let mut budget: Option<f64> = None;
    let mut ttl_hours: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--agent" => {
                i += 1;
                agent_name = args[i].to_string();
            }
            "--capabilities" => {
                i += 1;
                capabilities = args[i].split(',').map(|s| s.trim().to_string()).collect();
            }
            "--budget" => {
                i += 1;
                budget = Some(args[i].parse().unwrap());
            }
            "--ttl" => {
                i += 1;
                ttl_hours = Some(args[i].parse().unwrap());
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if agent_name.is_empty() || capabilities.is_empty() {
        eprintln!("ERROR: --agent and --capabilities are required");
        std::process::exit(1);
    }

    let root = load_root_heart();

    // Find the child agent's heart
    let child_path = dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".cortex")
        .join("soma-heart.json");

    // Also check agent-specific paths
    let agent_paths = vec![
        child_path.clone(),
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(format!(".{agent_name}"))
            .join("soma-heart.json"),
    ];

    let child = agent_paths
        .iter()
        .find_map(|p| HeartIdentity::load(p).ok())
        .unwrap_or_else(|| {
            eprintln!("ERROR: cannot find soma-heart.json for agent '{agent_name}'");
            eprintln!("Looked in:");
            for p in &agent_paths {
                eprintln!("  {}", p.display());
            }
            eprintln!();
            eprintln!("Start the agent first so it creates its identity.");
            std::process::exit(1);
        });

    let ttl_ms = ttl_hours.map(|h| h * 3600 * 1000);

    let cert = create_lineage_certificate(
        &root.secret_key,
        &root.genome,
        &child.genome,
        capabilities.clone(),
        ttl_ms,
        budget,
    )
    .unwrap();

    // Verify it immediately
    assert!(verify_lineage_certificate(&cert).unwrap());

    // Save the certificate
    let lineage_path = lineage_dir();
    std::fs::create_dir_all(&lineage_path).unwrap();
    let cert_path = lineage_path.join(format!("{agent_name}.json"));

    // Build the full lineage chain
    let lineage = HeartLineage {
        did: child.did.clone(),
        root_did: root.did.clone(),
        chain: vec![cert.clone()],
    };

    let json = serde_json::to_string_pretty(&lineage).unwrap();
    std::fs::write(&cert_path, &json).unwrap();

    // Also save to the agent's directory so it can load on boot
    let agent_lineage_path = dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".cortex")
        .join("lineage.json");
    std::fs::write(&agent_lineage_path, &json).unwrap();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          Lineage Certificate — Issued                   ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Agent:        {agent_name}");
    println!("  Child DID:    {}", child.did);
    println!("  Parent DID:   {}", root.did);
    println!("  Capabilities: {}", capabilities.join(", "));
    if let Some(b) = budget {
        println!("  Budget:       {b} credits");
    }
    if let Some(h) = ttl_hours {
        println!("  TTL:          {h} hours");
    }
    println!("  Cert ID:      {}", cert.id);
    println!();
    println!("  Saved to: {}", cert_path.display());
    println!("  Copied to: {}", agent_lineage_path.display());
    println!();
    println!("  Chain: {} → {}", root.did, child.did);
    println!("  Verified: ✓");
}

fn cmd_delegate(args: &[String]) {
    let mut subject_did = String::new();
    let mut capabilities = Vec::new();
    let mut budget: Option<f64> = None;
    let mut expires_hours: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--subject-did" => {
                i += 1;
                subject_did = args[i].to_string();
            }
            "--capabilities" => {
                i += 1;
                capabilities = args[i].split(',').map(|s| s.trim().to_string()).collect();
            }
            "--budget" => {
                i += 1;
                budget = Some(args[i].parse().unwrap());
            }
            "--expires" => {
                i += 1;
                expires_hours = Some(args[i].parse().unwrap());
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if subject_did.is_empty() || capabilities.is_empty() {
        eprintln!("ERROR: --subject-did and --capabilities are required");
        std::process::exit(1);
    }

    let root = load_root_heart();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let mut caveats = vec![Caveat::Capabilities {
        allow: capabilities.clone(),
    }];
    if let Some(b) = budget {
        caveats.push(Caveat::Budget { credits: b });
    }
    if let Some(h) = expires_hours {
        caveats.push(Caveat::ExpiresAt {
            timestamp: now_ms + h * 3600 * 1000,
        });
    }

    let delegation = create_delegation(
        &root.secret_key,
        &root.public_key,
        &root.did,
        &subject_did,
        capabilities.clone(),
        caveats,
        None,
    )
    .unwrap();

    // Save delegation
    let delegation_dir = dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".heyvera")
        .join("delegations");
    std::fs::create_dir_all(&delegation_dir).unwrap();
    let delegation_path = delegation_dir.join(format!("{}.json", delegation.id));
    let json = serde_json::to_string_pretty(&delegation).unwrap();
    std::fs::write(&delegation_path, &json).unwrap();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          Delegation Token — Issued                      ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Delegation ID: {}", delegation.id);
    println!("  Issuer DID:    {}", root.did);
    println!("  Subject DID:   {subject_did}");
    println!("  Capabilities:  {}", capabilities.join(", "));
    if let Some(b) = budget {
        println!("  Budget:        {b} credits");
    }
    if let Some(h) = expires_hours {
        println!("  Expires:       {h} hours from now");
    }
    println!();
    println!("  Saved to: {}", delegation_path.display());
    println!();
    println!("  Use with: Authorization: Soma <token_json>");
}

fn cmd_verify(args: &[String]) {
    let file = parse_file_arg(args);
    let json = std::fs::read_to_string(&file).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot read {}: {e}", file.display());
        std::process::exit(1);
    });

    // Try as lineage
    if let Ok(lineage) = serde_json::from_str::<HeartLineage>(&json) {
        match verify_lineage_chain(&lineage) {
            Ok(true) => {
                println!("✓ Lineage chain valid");
                println!("  Root:  {}", lineage.root_did);
                println!("  Leaf:  {}", lineage.did);
                println!("  Links: {}", lineage.chain.len());
            }
            Ok(false) => {
                println!("✗ Lineage chain INVALID");
                std::process::exit(1);
            }
            Err(e) => {
                println!("✗ Verification error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Try as single lineage certificate
    if let Ok(cert) = serde_json::from_str::<LineageCertificate>(&json) {
        match verify_lineage_certificate(&cert) {
            Ok(true) => {
                println!("✓ Lineage certificate valid");
                println!("  ID:     {}", cert.id);
                println!("  Parent: {}", cert.parent_did);
                println!("  Child:  {}", cert.child_did);
            }
            Ok(false) => {
                println!("✗ Lineage certificate INVALID");
                std::process::exit(1);
            }
            Err(e) => {
                println!("✗ Verification error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Try as delegation
    if let Ok(delegation) = serde_json::from_str::<soma::delegation::Delegation>(&json) {
        match soma::delegation::verify_delegation_signature(&delegation) {
            Ok(true) => {
                println!("✓ Delegation signature valid");
                println!("  ID:      {}", delegation.id);
                println!("  Issuer:  {}", delegation.issuer_did);
                println!("  Subject: {}", delegation.subject_did);
                println!("  Caps:    {}", delegation.capabilities.join(", "));
            }
            Ok(false) => {
                println!("✗ Delegation signature INVALID");
                std::process::exit(1);
            }
            Err(e) => {
                println!("✗ Verification error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    eprintln!("ERROR: file is not a recognized Soma artifact (lineage, certificate, or delegation)");
    std::process::exit(1);
}

fn cmd_inspect(args: &[String]) {
    let file = parse_file_arg(args);
    let json = std::fs::read_to_string(&file).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot read {}: {e}", file.display());
        std::process::exit(1);
    });

    // Pretty-print whatever it is
    let value: serde_json::Value = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("ERROR: invalid JSON: {e}");
        std::process::exit(1);
    });
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}

fn cmd_status() {
    let path = root_heart_path();
    if !path.exists() {
        println!("No root heart found. Run `soma-ceremony init` first.");
        return;
    }

    let root = load_root_heart();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          HeyVera Root Heart — Status                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  DID:         {}", root.did);
    println!("  Public Key:  {}", encode_base64(&root.public_key));
    println!("  Genome Hash: {}", root.genome.hash);
    println!("  Runtime:     {}", root.genome.genome.runtime_id);
    println!("  Path:        {}", path.display());
    println!();

    // List issued lineage certificates
    let lineage_path = lineage_dir();
    if lineage_path.exists() {
        println!("  Issued Lineage Certificates:");
        let mut found = false;
        for entry in std::fs::read_dir(&lineage_path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().is_some_and(|e| e == "json") {
                let name = entry
                    .path()
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                if let Ok(json) = std::fs::read_to_string(entry.path()) {
                    if let Ok(lineage) = serde_json::from_str::<HeartLineage>(&json) {
                        let caps = lineage
                            .chain
                            .last()
                            .map(|c| c.capabilities.join(", "))
                            .unwrap_or_default();
                        println!("    {name}:");
                        println!("      DID:  {}", lineage.did);
                        println!("      Caps: {caps}");
                        found = true;
                    }
                }
            }
        }
        if !found {
            println!("    (none)");
        }
    } else {
        println!("  Issued Lineage Certificates: (none)");
    }

    // List delegations
    let delegation_dir = dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".heyvera")
        .join("delegations");
    println!();
    if delegation_dir.exists() {
        let count = std::fs::read_dir(&delegation_dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .ok()
                    .is_some_and(|e| e.path().extension().is_some_and(|x| x == "json"))
            })
            .count();
        println!("  Issued Delegations: {count}");
    } else {
        println!("  Issued Delegations: 0");
    }
}

fn parse_file_arg(args: &[String]) -> PathBuf {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--file" {
            i += 1;
            return PathBuf::from(&args[i]);
        }
        i += 1;
    }

    // If no --file flag, treat last arg as the file
    if !args.is_empty() {
        return PathBuf::from(args.last().unwrap());
    }

    eprintln!("ERROR: --file <path> is required");
    std::process::exit(1);
}
