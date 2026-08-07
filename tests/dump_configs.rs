//! Writes generated configs to a directory so the real core binaries can be
//! run against them.
//!
//! Not a test of behaviour — it is the bridge between the host test suite and
//! external validation. A schema model can agree with itself indefinitely;
//! several failure classes in this project surface only when the actual core
//! parses the file (Shadowsocks-2022 key length is checked inside a vendored
//! library, not at parse time), so the authority is execution.
//!
//! Ignored by default because it writes files. Run it with a destination:
//!
//! ```text
//! TRICORE_DUMP_DIR=<dir> cargo test --test dump_configs -- --ignored --nocapture
//! ```
//!
//! The directory comes from the environment and is never a path inside this
//! repository: generated artefacts belong in a temporary directory.

use std::fs;
use std::path::PathBuf;

use tricore_panel::config::model::{
    Endpoint, Flow, Mux, Node, Protocol, Security, SsMethod, TlsSettings, Transport, VmessCipher,
    XhttpMode,
};
use tricore_panel::subscription::bundle::{self, Shape};

fn node(tag: &str, protocol: Protocol, transport: Transport) -> Node {
    Node {
        tag: tag.to_owned(),
        server: Endpoint { address: "example.com".into(), port: 443 },
        protocol,
        transport,
        security: Security::Tls(TlsSettings {
            sni: Some("example.com".into()),
            ..TlsSettings::default()
        }),
        mux: Mux::default(),
        chain_via: None,
        worker_served: false,
    }
}

fn websocket() -> Transport {
    Transport::WebSocket { path: "/ws".into(), host: None, heartbeat_secs: 0 }
}

fn xhttp() -> Transport {
    Transport::Xhttp { mode: XhttpMode::PacketUp, path: "/x".into(), host: None }
}

const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
const SS_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// A realistic multi-protocol set, which is what a subscription actually holds.
fn nodes() -> Vec<Node> {
    vec![
        node("ws-vless", Protocol::Vless { uuid: UUID.into(), flow: Flow::None }, websocket()),
        node("ws-trojan", Protocol::Trojan { password: "hunter2".into() }, websocket()),
        node(
            "ws-vmess",
            Protocol::Vmess { uuid: UUID.into(), cipher: VmessCipher::Auto },
            websocket(),
        ),
        node(
            "ws-ss",
            Protocol::Shadowsocks {
                method: SsMethod::Blake3Aes256Gcm,
                password: SS_KEY.into(),
            },
            websocket(),
        ),
        node("xhttp-vless", Protocol::Vless { uuid: UUID.into(), flow: Flow::None }, xhttp()),
    ]
}

#[test]
#[ignore = "writes files; run explicitly with TRICORE_DUMP_DIR set"]
fn dump_multi_node_configs() {
    let Ok(dir) = std::env::var("TRICORE_DUMP_DIR") else {
        panic!("set TRICORE_DUMP_DIR to a temporary directory");
    };
    let dir = PathBuf::from(dir);
    fs::create_dir_all(&dir).expect("create dump directory");

    let nodes = nodes();
    for target in bundle::all_clients() {
        let slug = bundle::client_slug(target);
        match bundle::render(&nodes, target, Shape::FullConfig) {
            Ok(b) => {
                let path = dir.join(&b.filename);
                fs::write(&path, &b.body).expect("write config");
                println!(
                    "{slug}: wrote {} ({} node(s) in, {} skipped)",
                    b.filename,
                    b.included,
                    b.skipped.len()
                );
                for s in &b.skipped {
                    println!("    skipped {}: {}", s.tag, s.reason);
                }
            }
            Err(e) => println!("{slug}: no config ({e})"),
        }

        if let Ok(b) = bundle::render(&nodes, target, Shape::ShareLinksPlain) {
            let path = dir.join(format!("{slug}-links.txt"));
            fs::write(&path, &b.body).expect("write links");
            println!("{slug}: wrote {} share link(s)", b.included);
        }
    }
}
