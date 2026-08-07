//! What the editor shows for one node: every parameter, what it means in plain
//! language, and which values the chosen client cannot accept.
//!
//! # Why the UI does not decide this
//!
//! [`crate::config::conflicts`] already knows which combinations break. The
//! obvious way to use that is to render the form freely and show the findings
//! underneath — which is what every panel surveyed in the research does, and it
//! leaves the user to discover by reading that the thing they just picked
//! cannot work. This module inverts it: for every value a control could take,
//! it builds the node that would result and asks the conflict engine. A value
//! that would break arrives at the browser already marked unselectable, with
//! the reason attached to it rather than to the form.
//!
//! # Attributing a problem to the right control
//!
//! A node with one fatal problem would otherwise make every option of every
//! control look blocked, because the check reports the same fatal finding
//! whatever else is changed. So a finding only counts against a choice if it
//! does *not* appear for every other choice of the same control. What is left
//! is what that control is actually responsible for.
//!
//! # The three-core view
//!
//! [`Advice::matrix`] answers the question the whole project exists for: this
//! one node, expressed once — what does each of the seven clients do with it?
//! Not a lowest common denominator, and not a silent drop. Every client is
//! listed with its verdict, including the ones that cannot take the node at
//! all, and why.

use serde::Serialize;

use crate::config::conflicts::{self, Finding, Severity};
use crate::config::model::{
    ClientTarget, Endpoint, Flow, Mux, Node, Protocol, RealitySettings, Security, SsMethod,
    TlsSettings, Transport, VmessCipher, XhttpMode,
};
use crate::subscription::bundle;

/// How a control is rendered.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// One of a fixed set of values.
    Select,
    /// Free text.
    Text,
    /// A whole number.
    Number,
    /// On or off.
    Toggle,
}

/// One value a [`Control`] can take.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// What the browser sends back. Matches the stored representation, so the
    /// editor never has to guess at spelling.
    pub value: String,
    /// What the user reads.
    pub label: String,
    /// Selecting this would break the node for the chosen client.
    pub blocked: bool,
    /// Why it is blocked, or a caveat if it merely costs something. Present
    /// whenever `blocked` is true — a disabled control with no explanation is
    /// worse than no control at all.
    pub reason: Option<String>,
    /// The long form of `reason`, shown on expand.
    pub detail: Option<String>,
}

/// One editable parameter.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// Matches [`Finding::field`], so a finding can be attached to its control.
    pub field: &'static str,
    pub label: &'static str,
    /// Plain language, for someone who has never heard of this parameter.
    /// Every control has one; there is no "advanced users will know".
    pub help: &'static str,
    pub kind: Kind,
    /// Empty for text, number and toggle controls.
    pub choices: Vec<Choice>,
    /// The node's current value, in the same spelling as [`Choice::value`].
    pub current: String,
}

/// What one client would do with this node.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct TargetVerdict {
    pub client: &'static str,
    /// URL segment for this client's subscription.
    pub slug: &'static str,
    pub core: &'static str,
    /// Whether a share link can actually be produced.
    pub exportable: bool,
    /// Worst severity found, if any.
    pub severity: Option<Severity>,
    pub findings: Vec<Finding>,
}

/// Everything the editor needs for one node.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Advice {
    pub controls: Vec<Control>,
    pub matrix: Vec<TargetVerdict>,
    /// Findings for the client currently selected in the editor.
    pub findings: Vec<Finding>,
}

/// Build the advice for `node` as seen by `target`.
#[must_use]
pub fn advise(node: &Node, target: ClientTarget) -> Advice {
    Advice {
        controls: controls(node, target),
        matrix: matrix(node),
        findings: conflicts::check(node, target),
    }
}

/// Every client's verdict on this node.
#[must_use]
pub fn matrix(node: &Node) -> Vec<TargetVerdict> {
    bundle::all_clients()
        .into_iter()
        .map(|client| {
            let findings = conflicts::check(node, client);
            TargetVerdict {
                client: client.name(),
                slug: bundle::client_slug(client),
                core: client.core().name(),
                exportable: crate::subscription::to_uri(node, client).is_ok(),
                severity: findings.iter().map(|f| f.severity).max(),
                findings,
            }
        })
        .collect()
}

/// Build a select control, marking the values this target cannot accept.
///
/// Every option is tried through [`apply`] — the same function that applies the
/// user's actual edit — so what the control blocks and what saving produces
/// cannot drift apart, and the blocking decision comes from the same engine
/// that judges the saved node.
fn select(
    node: &Node,
    target: ClientTarget,
    field: &'static str,
    label: &'static str,
    help: &'static str,
    current: String,
    options: &[(&str, &str)],
) -> Control {
    // What each option would produce.
    let per_option: Vec<Vec<Finding>> = options
        .iter()
        .map(|(value, _)| {
            let mut candidate = node.clone();
            apply(&mut candidate, field, value);
            conflicts::check(&candidate, target)
        })
        .collect();

    // Findings every option shares are caused by something else on the node,
    // not by this control, so they must not disable anything here.
    let shared: Vec<Finding> = per_option.first().map_or_else(Vec::new, |first| {
        first
            .iter()
            .filter(|f| per_option.iter().all(|set| set.contains(f)))
            .cloned()
            .collect()
    });

    let choices = options
        .iter()
        .zip(&per_option)
        .map(|((value, label), findings)| {
            let mut attributable =
                findings.iter().filter(|f| !shared.contains(f)).collect::<Vec<_>>();
            attributable.sort_by_key(|f| core::cmp::Reverse(f.severity));
            let worst = attributable.first();
            let blocked = worst.is_some_and(|f| f.severity.blocks_selection());
            Choice {
                value: (*value).to_owned(),
                label: (*label).to_owned(),
                blocked,
                reason: worst.map(|f| f.summary.clone()),
                detail: worst.map(|f| f.detail.clone()),
            }
        })
        .collect();

    Control { field, label, help, kind: Kind::Select, choices, current }
}

/// A control with no fixed value set.
const fn free(
    field: &'static str,
    label: &'static str,
    help: &'static str,
    kind: Kind,
    current: String,
) -> Control {
    Control { field, label, help, kind, choices: Vec::new(), current }
}

/// Every control for this node, in the order the editor shows them.
#[must_use]
#[allow(clippy::too_many_lines)] // A table of parameters. Splitting it would
                                 // only scatter the one list a reader wants.
pub fn controls(node: &Node, target: ClientTarget) -> Vec<Control> {
    let mut out = vec![
        free(
            "tag",
            "Name",
            "What this connection is called in your app's server list. Only a label — \
             changing it cannot break anything.",
            Kind::Text,
            node.tag.clone(),
        ),
        free(
            "address",
            "Server address",
            "What your app connects to. Normally your deployment's hostname. You can also put \
             a Cloudflare IP address here and leave the hostname in the TLS and Host fields \
             below — the connection still works, and it is how you route around an address \
             your network handles badly.",
            Kind::Text,
            node.server.address.clone(),
        ),
        free(
            "port",
            "Port",
            "443 for normal HTTPS. Cloudflare also accepts 2053, 2083, 2087, 2096 and 8443 \
             with TLS, which is occasionally useful when 443 is treated differently.",
            Kind::Number,
            node.server.port.to_string(),
        ),
        protocol_control(node, target),
    ];

    match &node.protocol {
        Protocol::Vless { uuid, flow } => {
            out.push(free(
                "uuid",
                "User ID",
                "The UUID that identifies you to the server. It must match one the deployment \
                 was given; the panel cannot change it, because credentials live in the \
                 deployment's own settings rather than in this editor.",
                Kind::Text,
                uuid.clone(),
            ));
            out.push(select(
                node,
                target,
                "flow",
                "Flow",
                "XTLS Vision splices traffic at the TLS record layer to avoid encrypting \
                 twice. It needs the app's own TLS session end to end, so it cannot work \
                 through a CDN or inside any framed transport. Leave it off for anything \
                 served through Cloudflare.",
                flow_value(*flow).to_owned(),
                &[
                    ("none", "Off (required behind Cloudflare)"),
                    ("vision", "xtls-rprx-vision"),
                    ("vision-udp443", "xtls-rprx-vision-udp443"),
                ],
            ));
        }
        Protocol::Vmess { uuid, cipher } => {
            out.push(free(
                "uuid",
                "User ID",
                "The UUID that identifies you to the server, matching one the deployment was \
                 given.",
                Kind::Text,
                uuid.clone(),
            ));
            out.push(select(
                node,
                target,
                "cipher",
                "Encryption",
                "How the payload is encrypted inside VMess. auto is right for almost everyone: \
                 it picks AES on processors with hardware AES and ChaCha20 elsewhere. This \
                 server implements both, and refuses the unencrypted modes rather than \
                 pretending to carry them.",
                cipher_value(*cipher).to_owned(),
                &[
                    ("auto", "auto (recommended)"),
                    ("aes128-gcm", "aes-128-gcm"),
                    ("chacha20-poly1305", "chacha20-poly1305"),
                    ("zero", "zero (no encryption)"),
                ],
            ));
        }
        Protocol::Trojan { password } => out.push(free(
            "password",
            "Password",
            "The password the deployment was given for Trojan.",
            Kind::Text,
            password.clone(),
        )),
        Protocol::Shadowsocks { method, password } => {
            out.push(select(
                node,
                target,
                "method",
                "Cipher",
                "The 2022 ciphers use a pre-shared key rather than a passphrase and are the \
                 only ones this server implements. The older ciphers are listed because \
                 imported configs use them, not because this deployment serves them.",
                method_value(*method).to_owned(),
                &[
                    ("blake3-aes128-gcm", "2022-blake3-aes-128-gcm"),
                    ("blake3-aes256-gcm", "2022-blake3-aes-256-gcm"),
                    ("blake3-chacha20-poly1305", "2022-blake3-chacha20-poly1305"),
                    ("aes128-gcm", "aes-128-gcm (legacy)"),
                    ("aes256-gcm", "aes-256-gcm (legacy)"),
                    ("chacha20-poly1305", "chacha20-ietf-poly1305 (legacy)"),
                    ("xchacha20-poly1305", "xchacha20-ietf-poly1305 (legacy)"),
                ],
            ));
            out.push(free(
                "password",
                "Key",
                "For a 2022 cipher this is base64 of exactly 16 or 32 random bytes, depending \
                 on the cipher — not a password you invent. The wrong length produces a config \
                 that looks valid and then refuses to start.",
                Kind::Text,
                password.clone(),
            ));
        }
    }

    out.push(transport_control(node, target));

    match &node.transport {
        Transport::Xhttp { mode, path, host } => {
            out.push(select(
                node,
                target,
                "xhttp_mode",
                "XHTTP mode",
                "packet-up sends the upload as a series of ordinary POSTs, so nothing in the \
                 path has to support streaming in both directions at once. stream-up and \
                 stream-one are faster where full duplex works, and simply hang where it does \
                 not. Use the deployment's duplex self-test before choosing one.",
                mode_value(*mode).to_owned(),
                &[
                    ("packet-up", "packet-up (always works)"),
                    ("stream-up", "stream-up (needs duplex)"),
                    ("stream-one", "stream-one (needs duplex)"),
                ],
            ));
            out.push(free(
                "path",
                "Path",
                "The URL path the transport hides behind. It must match the deployment's \
                 setting exactly. Keep it random: a guessable path is the cheapest thing for a \
                 scanner to find.",
                Kind::Text,
                path.clone(),
            ));
            out.push(free(
                "host",
                "Host header",
                "The hostname sent in the request. Leave it as your deployment's hostname \
                 unless you are pointing the address field at a raw IP, in which case this is \
                 what still routes the request correctly.",
                Kind::Text,
                host.clone().unwrap_or_default(),
            ));
        }
        Transport::WebSocket { path, host, heartbeat_secs } => {
            out.push(free(
                "path",
                "Path",
                "The URL path the WebSocket connects to, matching the deployment's setting.",
                Kind::Text,
                path.clone(),
            ));
            out.push(free(
                "host",
                "Host header",
                "The hostname sent in the request. Normally your deployment's hostname.",
                Kind::Text,
                host.clone().unwrap_or_default(),
            ));
            out.push(free(
                "heartbeat",
                "Heartbeat (seconds)",
                "How often to send a keepalive ping. Cloudflare closes idle WebSockets after a \
                 period it does not publish, and its own documentation recommends a \
                 client-side heartbeat. 0 disables it.",
                Kind::Number,
                heartbeat_secs.to_string(),
            ));
        }
        Transport::Grpc { service_name, .. } => out.push(free(
            "service_name",
            "Service name",
            "The gRPC service path. This deployment cannot serve gRPC — it needs a duplex \
             HTTP/2 stream the runtime does not provide — so this is only meaningful for an \
             external hop.",
            Kind::Text,
            service_name.clone(),
        )),
        Transport::HttpUpgrade { path, .. } => out.push(free(
            "path",
            "Path",
            "The path to upgrade on. This deployment cannot serve HTTPUpgrade: the runtime \
             never hands back the raw socket after the upgrade.",
            Kind::Text,
            path.clone(),
        )),
        Transport::Raw => {}
    }

    out.push(security_control(node, target));

    match &node.security {
        Security::Tls(tls) => {
            out.push(free(
                "sni",
                "TLS server name",
                "The hostname presented in the TLS handshake, and the name the certificate is \
                 checked against. It must be your deployment's real hostname even when the \
                 address field holds an IP.",
                Kind::Text,
                tls.sni.clone().unwrap_or_default(),
            ));
            out.push(free(
                "alpn",
                "ALPN",
                "Which HTTP version to negotiate, comma separated. Leave it empty unless you \
                 have a reason: forcing h2 or http/1.1 makes the handshake stand out from \
                 ordinary browser traffic to the same host.",
                Kind::Text,
                tls.alpn.join(","),
            ));
            out.push(fingerprint_control(node, target, tls.fingerprint.as_deref()));
            out.push(free(
                "allow_insecure",
                "Skip certificate check",
                "Accepts any certificate, which also accepts anyone who intercepts the \
                 connection. Current Xray refuses to start with this set at all — it was \
                 removed rather than deprecated — so it is here to explain imported configs, \
                 not to be switched on.",
                Kind::Toggle,
                tls.allow_insecure.to_string(),
            ));
        }
        Security::Reality(r) => {
            out.push(free(
                "public_key",
                "REALITY public key",
                "The server's public key. REALITY borrows a real site's TLS handshake, so it \
                 needs to own the TLS session end to end — it cannot work behind Cloudflare.",
                Kind::Text,
                r.public_key.clone(),
            ));
            out.push(free(
                "short_id",
                "Short ID",
                "A short hex string the server uses to recognise its own clients.",
                Kind::Text,
                r.short_id.clone(),
            ));
            out.push(free(
                "server_name",
                "Borrowed server name",
                "The real site whose handshake is imitated. It must be a site that genuinely \
                 answers on 443 with TLS 1.3.",
                Kind::Text,
                r.server_name.clone(),
            ));
            out.push(fingerprint_control(node, target, r.fingerprint.as_deref()));
        }
        Security::None => {}
    }

    out.push(free(
        "mux",
        "Multiplexing",
        "Carries several streams over one connection. It saves handshakes, but every stream \
         then shares one Worker request: a stall on any of them stalls the rest, and they all \
         end together when the runtime cycles. Off is the right default here.",
        Kind::Toggle,
        node.mux.enabled.to_string(),
    ));
    if node.mux.enabled {
        out.push(free(
            "concurrency",
            "Maximum streams",
            "How many streams share one connection. Higher means fewer handshakes and more \
             shared fate.",
            Kind::Number,
            node.mux.concurrency.to_string(),
        ));
    }

    out
}

/// The protocol control, whose options change the credential fields with them.
fn protocol_control(node: &Node, target: ClientTarget) -> Control {
    select(
        node,
        target,
        "protocol",
        "Protocol",
        "How the connection identifies itself and encrypts its payload. VLESS is the lightest \
         and the default. VMess encrypts the payload itself and is the most widely supported. \
         Trojan imitates ordinary HTTPS. Shadowsocks-2022 uses a pre-shared key and has the \
         least distinctive handshake of the four.",
        protocol_value(&node.protocol).to_owned(),
        &[
            ("vless", "VLESS"),
            ("vmess", "VMess"),
            ("trojan", "Trojan"),
            ("shadowsocks", "Shadowsocks-2022"),
        ],
    )
}

fn transport_control(node: &Node, target: ClientTarget) -> Control {
    select(
        node,
        target,
        "transport",
        "Transport",
        "What the traffic is disguised as on the wire. XHTTP looks like ordinary HTTP requests \
         and is what this deployment serves. WebSocket also works but is the single most \
         fingerprinted transport in this space, and sharing a hostname with XHTTP means a \
         classifier that flags one takes down the other. gRPC, HTTPUpgrade and raw TCP cannot \
         be served from a Worker at all and are offered only for external hops.",
        transport_value(&node.transport).to_owned(),
        &[
            ("xhttp", "XHTTP"),
            ("web-socket", "WebSocket"),
            ("grpc", "gRPC"),
            ("http-upgrade", "HTTPUpgrade"),
            ("raw", "Raw TCP"),
        ],
    )
}

fn security_control(node: &Node, target: ClientTarget) -> Control {
    select(
        node,
        target,
        "security",
        "Transport security",
        "TLS is what makes the traffic look like ordinary HTTPS, and is required for anything \
         reaching a public address. REALITY imitates another site's handshake but must own the \
         TLS session end to end, so it cannot be used behind Cloudflare.",
        security_value(&node.security).to_owned(),
        &[("tls", "TLS"), ("reality", "REALITY"), ("none", "None")],
    )
}

/// uTLS fingerprints, which decide what the TLS handshake looks like.
fn fingerprint_control(node: &Node, target: ClientTarget, current: Option<&str>) -> Control {
    select(
        node,
        target,
        "fingerprint",
        "TLS fingerprint",
        "Makes the TLS handshake look like a particular browser's. Without one, the handshake \
         is recognisably a proxy client's even though everything inside it is encrypted. \
         chrome is the safest choice because it is the most common thing on the network.",
        current.unwrap_or("").to_owned(),
        &[
            ("", "Core default"),
            ("chrome", "Chrome"),
            ("firefox", "Firefox"),
            ("safari", "Safari"),
            ("edge", "Edge"),
            ("ios", "iOS"),
            ("android", "Android"),
            ("random", "Random each connection"),
        ],
    )
}

/// Apply one edit, named by the same `field` a [`Control`] carries.
///
/// This is the only place a field name becomes a change to the model, and it
/// is used for three things: building the candidate nodes that decide which
/// choices are blocked, applying the edit the user actually made, and nothing
/// else. Keeping them the same function is what stops the editor from blocking
/// a value on one set of rules and then saving it under another — and it keeps
/// the browser out of the business of knowing how a `Node` is shaped, which is
/// where a second, silently diverging copy of this logic would otherwise live.
///
/// An unknown field or an unparseable value leaves the node untouched. The
/// caller is a browser and the input is untrusted, so refusing quietly is the
/// right failure: the control simply does not move, and the state the user is
/// looking at is still the state that would be saved.
#[allow(clippy::too_many_lines)] // One dispatch table; splitting it would only
                                 // hide which fields are handled.
pub fn apply(node: &mut Node, field: &str, value: &str) {
    let text = value.trim();
    match field {
        "tag" => text.clone_into(&mut node.tag),
        "address" => text.clone_into(&mut node.server.address),
        "port" => {
            if let Ok(port) = text.parse() {
                node.server.port = port;
            }
        }
        "protocol" => {
            // Credentials are carried across where the shape allows, so that
            // trying a protocol out does not silently blank the field that
            // makes it work.
            let secret = match &node.protocol {
                Protocol::Vless { uuid, .. } | Protocol::Vmess { uuid, .. } => uuid.clone(),
                Protocol::Trojan { password } | Protocol::Shadowsocks { password, .. } => {
                    password.clone()
                }
            };
            node.protocol = match text {
                "vmess" => Protocol::Vmess { uuid: secret, cipher: VmessCipher::Auto },
                "trojan" => Protocol::Trojan { password: secret },
                "shadowsocks" => {
                    Protocol::Shadowsocks { method: SsMethod::Blake3Aes256Gcm, password: secret }
                }
                "vless" => Protocol::Vless { uuid: secret, flow: Flow::None },
                _ => return,
            };
        }
        "uuid" => match &mut node.protocol {
            Protocol::Vless { uuid, .. } | Protocol::Vmess { uuid, .. } => {
                text.clone_into(uuid);
            }
            _ => {}
        },
        "password" => match &mut node.protocol {
            Protocol::Trojan { password } | Protocol::Shadowsocks { password, .. } => {
                text.clone_into(password);
            }
            _ => {}
        },
        "flow" => {
            if let Protocol::Vless { flow, .. } = &mut node.protocol {
                *flow = match text {
                    "vision" => Flow::Vision,
                    "vision-udp443" => Flow::VisionUdp443,
                    _ => Flow::None,
                };
            }
        }
        "cipher" => {
            if let Protocol::Vmess { cipher, .. } = &mut node.protocol {
                *cipher = match text {
                    "aes128-gcm" => VmessCipher::Aes128Gcm,
                    "chacha20-poly1305" => VmessCipher::Chacha20Poly1305,
                    "zero" => VmessCipher::Zero,
                    _ => VmessCipher::Auto,
                };
            }
        }
        "method" => {
            if let Protocol::Shadowsocks { method, .. } = &mut node.protocol {
                *method = parse_method(text);
            }
        }
        "transport" => {
            // Path and host survive a transport change where both have them,
            // because retyping a path that must match the deployment exactly
            // is the easiest thing in this editor to get wrong.
            let (path, host) = match &node.transport {
                Transport::Xhttp { path, host, .. }
                | Transport::WebSocket { path, host, .. }
                | Transport::HttpUpgrade { path, host } => (path.clone(), host.clone()),
                Transport::Grpc { .. } | Transport::Raw => (String::from("/"), None),
            };
            node.transport = match text {
                "web-socket" => Transport::WebSocket { path, host, heartbeat_secs: 30 },
                "grpc" => Transport::Grpc { service_name: String::new(), multi_mode: false },
                "http-upgrade" => Transport::HttpUpgrade { path, host },
                "raw" => Transport::Raw,
                "xhttp" => Transport::Xhttp { mode: XhttpMode::PacketUp, path, host },
                _ => return,
            };
        }
        "xhttp_mode" => {
            if let Transport::Xhttp { mode, .. } = &mut node.transport {
                *mode = match text {
                    "stream-up" => XhttpMode::StreamUp,
                    "stream-one" => XhttpMode::StreamOne,
                    _ => XhttpMode::PacketUp,
                };
            }
        }
        "path" => match &mut node.transport {
            Transport::Xhttp { path, .. }
            | Transport::WebSocket { path, .. }
            | Transport::HttpUpgrade { path, .. } => text.clone_into(path),
            _ => {}
        },
        "host" => {
            let value = optional(text);
            match &mut node.transport {
                Transport::Xhttp { host, .. }
                | Transport::WebSocket { host, .. }
                | Transport::HttpUpgrade { host, .. } => *host = value,
                _ => {}
            }
        }
        "heartbeat" => {
            if let Transport::WebSocket { heartbeat_secs, .. } = &mut node.transport {
                if let Ok(secs) = text.parse() {
                    *heartbeat_secs = secs;
                }
            }
        }
        "service_name" => {
            if let Transport::Grpc { service_name, .. } = &mut node.transport {
                text.clone_into(service_name);
            }
        }
        "security" => {
            let sni = match &node.security {
                Security::Tls(t) => t.sni.clone(),
                Security::Reality(r) => Some(r.server_name.clone()),
                Security::None => Some(node.server.address.clone()),
            };
            node.security = match text {
                "reality" => Security::Reality(RealitySettings {
                    server_name: sni.unwrap_or_default(),
                    ..RealitySettings::default()
                }),
                "none" => Security::None,
                "tls" => Security::Tls(TlsSettings { sni, ..TlsSettings::default() }),
                _ => return,
            };
        }
        "sni" => {
            if let Security::Tls(t) = &mut node.security {
                t.sni = optional(text);
            }
        }
        "alpn" => {
            if let Security::Tls(t) = &mut node.security {
                t.alpn = text
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
        }
        "fingerprint" => {
            let value = optional(text);
            match &mut node.security {
                Security::Tls(t) => t.fingerprint = value,
                Security::Reality(r) => r.fingerprint = value,
                Security::None => {}
            }
        }
        "allow_insecure" => {
            if let Security::Tls(t) = &mut node.security {
                t.allow_insecure = truthy(text);
            }
        }
        "public_key" => {
            if let Security::Reality(r) = &mut node.security {
                text.clone_into(&mut r.public_key);
            }
        }
        "short_id" => {
            if let Security::Reality(r) = &mut node.security {
                text.clone_into(&mut r.short_id);
            }
        }
        "server_name" => {
            if let Security::Reality(r) = &mut node.security {
                text.clone_into(&mut r.server_name);
            }
        }
        "mux" => node.mux.enabled = truthy(text),
        "concurrency" => {
            if let Ok(n) = text.parse() {
                node.mux.concurrency = n;
            }
        }
        "chain_via" => node.chain_via = optional(text),
        _ => {}
    }
}

/// An empty string means "not set", not "set to empty".
fn optional(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

/// Checkbox values arrive in more than one spelling depending on how the
/// browser serialised them.
fn truthy(text: &str) -> bool {
    matches!(text, "true" | "1" | "on" | "yes")
}

// Stored spellings. These match the serde representation of the model, so the
// browser can set a field from a choice value without a translation table of
// its own — and a mismatch here would show up as a control that never takes.

const fn protocol_value(p: &Protocol) -> &'static str {
    match p {
        Protocol::Vless { .. } => "vless",
        Protocol::Vmess { .. } => "vmess",
        Protocol::Trojan { .. } => "trojan",
        Protocol::Shadowsocks { .. } => "shadowsocks",
    }
}

const fn transport_value(t: &Transport) -> &'static str {
    match t {
        Transport::Xhttp { .. } => "xhttp",
        Transport::WebSocket { .. } => "web-socket",
        Transport::Grpc { .. } => "grpc",
        Transport::HttpUpgrade { .. } => "http-upgrade",
        Transport::Raw => "raw",
    }
}

const fn security_value(s: &Security) -> &'static str {
    match s {
        Security::None => "none",
        Security::Tls(_) => "tls",
        Security::Reality(_) => "reality",
    }
}

const fn flow_value(f: Flow) -> &'static str {
    match f {
        Flow::None => "none",
        Flow::Vision => "vision",
        Flow::VisionUdp443 => "vision-udp443",
    }
}

const fn mode_value(m: XhttpMode) -> &'static str {
    match m {
        XhttpMode::PacketUp => "packet-up",
        XhttpMode::StreamUp => "stream-up",
        XhttpMode::StreamOne => "stream-one",
    }
}

const fn cipher_value(c: VmessCipher) -> &'static str {
    match c {
        VmessCipher::Auto => "auto",
        VmessCipher::Aes128Gcm => "aes128-gcm",
        VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
        VmessCipher::Zero => "zero",
    }
}

const fn method_value(m: SsMethod) -> &'static str {
    match m {
        SsMethod::Aes128Gcm => "aes128-gcm",
        SsMethod::Aes256Gcm => "aes256-gcm",
        SsMethod::Chacha20Poly1305 => "chacha20-poly1305",
        SsMethod::Xchacha20Poly1305 => "xchacha20-poly1305",
        SsMethod::Blake3Aes128Gcm => "blake3-aes128-gcm",
        SsMethod::Blake3Aes256Gcm => "blake3-aes256-gcm",
        SsMethod::Blake3Chacha20Poly1305 => "blake3-chacha20-poly1305",
    }
}

fn parse_method(v: &str) -> SsMethod {
    match v {
        "aes128-gcm" => SsMethod::Aes128Gcm,
        "aes256-gcm" => SsMethod::Aes256Gcm,
        "chacha20-poly1305" => SsMethod::Chacha20Poly1305,
        "xchacha20-poly1305" => SsMethod::Xchacha20Poly1305,
        "blake3-aes128-gcm" => SsMethod::Blake3Aes128Gcm,
        "blake3-chacha20-poly1305" => SsMethod::Blake3Chacha20Poly1305,
        _ => SsMethod::Blake3Aes256Gcm,
    }
}

/// A node with nothing configured, for building a new one in the editor.
#[must_use]
pub fn blank(host: &str, path: &str) -> Node {
    Node {
        tag: "New connection".to_owned(),
        server: Endpoint { address: host.to_owned(), port: 443 },
        protocol: Protocol::Vless { uuid: String::new(), flow: Flow::None },
        transport: Transport::Xhttp {
            mode: XhttpMode::PacketUp,
            path: path.to_owned(),
            host: Some(host.to_owned()),
        },
        security: Security::Tls(TlsSettings {
            sni: Some(host.to_owned()),
            ..TlsSettings::default()
        }),
        mux: Mux::default(),
        chain_via: None,
        worker_served: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> Node {
        Node {
            tag: "n".into(),
            server: Endpoint { address: "example.com".into(), port: 443 },
            protocol: Protocol::Vless {
                uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
                flow: Flow::None,
            },
            transport: Transport::Xhttp {
                mode: XhttpMode::PacketUp,
                path: "/abc".into(),
                host: Some("example.com".into()),
            },
            security: Security::Tls(TlsSettings {
                sni: Some("example.com".into()),
                ..TlsSettings::default()
            }),
            mux: Mux::default(),
            chain_via: None,
            worker_served: true,
        }
    }

    fn control<'a>(controls: &'a [Control], field: &str) -> &'a Control {
        controls.iter().find(|c| c.field == field).expect("control exists")
    }

    fn choice<'a>(c: &'a Control, value: &str) -> &'a Choice {
        c.choices.iter().find(|ch| ch.value == value).expect("choice exists")
    }

    #[test]
    fn every_control_explains_itself() {
        // The rule the whole advanced surface rests on: no parameter is
        // presented without saying what it does. A form of bare field names is
        // what makes every other panel in this space unusable by a non-expert.
        for protocol in [
            Protocol::Vless { uuid: "u".into(), flow: Flow::None },
            Protocol::Vmess { uuid: "u".into(), cipher: VmessCipher::Auto },
            Protocol::Trojan { password: "p".into() },
            Protocol::Shadowsocks { method: SsMethod::Blake3Aes256Gcm, password: "k".into() },
        ] {
            let mut n = node();
            n.protocol = protocol;
            for c in controls(&n, ClientTarget::V2rayN) {
                assert!(c.help.len() > 40, "{} has no real help text", c.field);
                assert!(!c.label.is_empty(), "{} has no label", c.field);
            }
        }
    }

    #[test]
    fn a_blocked_choice_always_says_why() {
        // A disabled control with no reason is worse than no control: the user
        // cannot tell it from a bug.
        for target in bundle::all_clients() {
            for c in controls(&node(), target) {
                for ch in &c.choices {
                    if ch.blocked {
                        assert!(
                            ch.reason.as_ref().is_some_and(|r| !r.is_empty()),
                            "{}/{} is blocked with no reason for {}",
                            c.field,
                            ch.value,
                            target.name()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn vision_is_blocked_on_a_worker_served_node() {
        // The combination every other panel accepts and then silently fails to
        // apply. Both Vision values must be unselectable, with a reason.
        let controls = controls(&node(), ClientTarget::V2rayN);
        let flow = control(&controls, "flow");
        assert!(!choice(flow, "none").blocked);
        for v in ["vision", "vision-udp443"] {
            let ch = choice(flow, v);
            assert!(ch.blocked, "{v} must be unselectable");
            assert!(ch.detail.as_ref().is_some_and(|d| d.contains("TLS")));
        }
    }

    #[test]
    fn reality_is_blocked_behind_cloudflare_but_offered_for_an_external_hop() {
        let mut n = node();
        let blocked = control(&controls(&n, ClientTarget::V2rayN), "security").clone();
        assert!(choice(&blocked, "reality").blocked);

        // The same value on a hop we do not serve is the user's own business.
        n.worker_served = false;
        let allowed = control(&controls(&n, ClientTarget::V2rayN), "security").clone();
        assert!(!choice(&allowed, "reality").blocked);
    }

    #[test]
    fn an_unrelated_fatal_problem_does_not_disable_every_control() {
        // The attribution rule. A node with one fatal fault would otherwise
        // report every option of every control as blocked, which tells the
        // user nothing and hides the actual fault.
        let mut n = node();
        n.security = Security::None; // Fatal for VLESS to a public address.
        let controls = controls(&n, ClientTarget::V2rayN);

        let tag_like = control(&controls, "protocol");
        assert!(
            tag_like.choices.iter().any(|c| !c.blocked),
            "the protocol control must still offer something"
        );
        // And the control actually responsible still reports it.
        let security = control(&controls, "security");
        assert!(!choice(security, "tls").blocked);
    }

    #[test]
    fn the_matrix_covers_every_client_and_names_the_ones_that_cannot_take_the_node() {
        let m = matrix(&node());
        assert_eq!(m.len(), bundle::all_clients().len());

        let upstream = m
            .iter()
            .find(|v| v.slug == "sing-box")
            .expect("upstream sing-box is listed");
        assert!(!upstream.exportable, "upstream sing-box cannot take an XHTTP node");
        assert!(!upstream.findings.is_empty(), "and must say so");

        let hiddify = m.iter().find(|v| v.slug == "hiddify").expect("hiddify is listed");
        assert!(hiddify.exportable, "Hiddify ships a patched sing-box that can");
    }

    #[test]
    fn shadowsocks_over_xhttp_is_offered_for_xray_and_refused_elsewhere() {
        // Pinned because this exact combination was once refused everywhere,
        // which removed a working protocol from every export without a word.
        let mut n = node();
        n.protocol = Protocol::Shadowsocks {
            method: SsMethod::Blake3Aes256Gcm,
            password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        };
        let xray = control(&controls(&n, ClientTarget::V2rayN), "protocol").clone();
        assert!(!choice(&xray, "shadowsocks").blocked, "Xray carries this");

        let sb = control(&controls(&n, ClientTarget::Hiddify), "protocol").clone();
        assert!(choice(&sb, "shadowsocks").blocked, "sing-box does not");
    }

    #[test]
    fn the_controls_follow_the_protocol_and_transport_in_use() {
        let mut n = node();
        assert!(controls(&n, ClientTarget::V2rayN).iter().any(|c| c.field == "flow"));
        assert!(controls(&n, ClientTarget::V2rayN).iter().any(|c| c.field == "xhttp_mode"));

        n.protocol = Protocol::Trojan { password: "p".into() };
        let c = controls(&n, ClientTarget::V2rayN);
        assert!(!c.iter().any(|x| x.field == "flow"), "flow is a VLESS concept");
        assert!(c.iter().any(|x| x.field == "password"));

        n.transport = Transport::Raw;
        let c = controls(&n, ClientTarget::V2rayN);
        assert!(!c.iter().any(|x| x.field == "xhttp_mode"));
    }

    #[test]
    fn current_values_round_trip_through_their_own_choice_list() {
        // If a stored value has no matching choice, the editor shows an empty
        // dropdown and saving it silently changes the node.
        for c in controls(&node(), ClientTarget::V2rayN) {
            if c.kind == Kind::Select {
                assert!(
                    c.choices.iter().any(|ch| ch.value == c.current),
                    "{} current value {:?} is not among its choices",
                    c.field,
                    c.current
                );
            }
        }
    }

    #[test]
    fn every_control_actually_sets_the_field_it_names() {
        // The drift this guards against is silent and total: a control whose
        // field name `apply` does not handle renders normally, moves normally,
        // and changes nothing. The browser sends field names straight through,
        // so nothing else in the system would notice.
        let sample = |kind: Kind| match kind {
            Kind::Number => "7",
            Kind::Toggle => "true",
            _ => "zz-probe",
        };

        for protocol in [
            Protocol::Vless { uuid: "u".into(), flow: Flow::None },
            Protocol::Vmess { uuid: "u".into(), cipher: VmessCipher::Auto },
            Protocol::Trojan { password: "p".into() },
            Protocol::Shadowsocks { method: SsMethod::Blake3Aes256Gcm, password: "k".into() },
        ] {
            for transport in [
                Transport::Xhttp {
                    mode: XhttpMode::PacketUp,
                    path: "/p".into(),
                    host: Some("example.com".into()),
                },
                Transport::WebSocket {
                    path: "/w".into(),
                    host: None,
                    heartbeat_secs: 30,
                },
            ] {
                let mut base = node();
                base.protocol = protocol.clone();
                base.transport = transport.clone();

                for c in controls(&base, ClientTarget::V2rayN) {
                    let values: Vec<String> = if c.kind == Kind::Select {
                        c.choices.iter().map(|ch| ch.value.clone()).collect()
                    } else {
                        vec![sample(c.kind).to_owned()]
                    };
                    for value in values {
                        let mut edited = base.clone();
                        apply(&mut edited, c.field, &value);
                        let after = controls(&edited, ClientTarget::V2rayN);
                        let found = after
                            .iter()
                            .find(|x| x.field == c.field)
                            .unwrap_or_else(|| panic!("{} vanished after being set", c.field));
                        assert_eq!(
                            found.current, value,
                            "{} did not take the value {value:?}",
                            c.field
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_unknown_field_or_value_leaves_the_node_alone() {
        // The input is a browser's. Refusing quietly is what keeps the state
        // the user is looking at the same as the state that would be saved.
        let before = node();
        for (field, value) in [
            ("nonsense", "x"),
            ("port", "not a number"),
            ("port", "99999999"),
            ("protocol", "carrier-pigeon"),
            ("transport", "smoke-signal"),
            ("security", "hope"),
            ("concurrency", "-1"),
        ] {
            let mut after = before.clone();
            apply(&mut after, field, value);
            assert_eq!(after, before, "{field}={value:?} should have been ignored");
        }
    }

    #[test]
    fn advice_never_panics_across_every_client_and_shape() {
        for target in bundle::all_clients() {
            for protocol in [
                Protocol::Vless { uuid: String::new(), flow: Flow::Vision },
                Protocol::Vmess { uuid: String::new(), cipher: VmessCipher::Zero },
                Protocol::Trojan { password: String::new() },
                Protocol::Shadowsocks { method: SsMethod::Aes128Gcm, password: "!".into() },
            ] {
                for transport in [
                    Transport::Raw,
                    Transport::Grpc { service_name: String::new(), multi_mode: true },
                    Transport::HttpUpgrade { path: String::new(), host: None },
                ] {
                    let mut n = node();
                    n.protocol = protocol.clone();
                    n.transport = transport;
                    n.security = Security::None;
                    let _ = advise(&n, target);
                }
            }
        }
    }
}
