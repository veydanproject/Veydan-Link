# Changelog

## 0.3.2 (2026-10-14): idle clients closed, hubs can be revoked, a probe gets a web page

- A connection of a client with no stream open for 120 seconds is closed
  (`Bridge::set_idle_timeout` changes it, `Status::idle_closed` counts them):
  it held one of the slots of the bridge, and a handshake that said nothing
  could fill them all. The decoy connection of `vlink-hub/1` without a
  certificate follows the same rule.
- **Hubs can be revoked.** The answer of the registry to a report may
  carry `revoked`: the keys of the hubs (SHA-256 of the SubjectPublicKeyInfo
  of their certificates) the root no longer stands behind, signed by the
  list key under the root's delegation, as the lists of bridges are
  (`vlink_proto::revoke`, context `vlink-revoked/1`). The bridge takes the
  newest such list, keeps it in `revoked.json` of its data folder, lets no
  hub of it link and drops at once the links such a hub holds. A list of
  another delegation, dated ahead of the clock or older than the one kept
  changes nothing; the one kept holds after its delegation ran out. A hub
  whose certificate was stolen stopped being one only when the certificate
  ran out (90 days); now within five minutes, at the next report.
- The field is optional both ways: a registry that never revoked a hub
  sends nothing new, a bridge before it reads past it (spec/protocol.md,
  «Отзыв хабов»). A private bridge (`--private`) learns of no revocation.
- `Status::hubs_revoked` and `hubs_revoked=` in the status line of the
  log: hubs turned away or dropped for it.
- `vlink_proto::tls::not_after`: the end of a certificate, for the hub's
  health and the bridge's own chain.
- **A probe without a certificate gets a web page.** Who chose ALPN
  `vlink-hub/1` and showed no certificate was closed on at once, which no
  web server does; now it is served h2 with the SETTINGS a client gets,
  and every request gets the 404 page of the decoy.
- **The bridge's certificate looks like any other.** The chain is issued
  for 90 days (it was 20 years), under names made up for each chain
  (`kesomara.net`, not `localhost`), and issued again over the same two
  keys once less than 30 days are left: at the start, and while the bridge
  runs (looked at every 12 hours; `Handle::set_identity`,
  `vlink_proto::tls::BridgeCert` shows it from the next handshake, links
  stay). A chain of 20 years is issued again at the first start. The id
  stays: clients and hubs pin the bridge's key, not the fields.
- Still told apart by a probe that knows the protocol, as accepted for now
  (spec/protocol.md, «Порт моста»): the bridge selects `vlink-hub/1` when
  it is offered, sends a CertificateRequest to everybody, and its chain is
  signed by no public authority.

## 0.3.1 (2026-10-13): the README says how to install

- README.md: what a bridge needs, both ways to install it (as a service by
  one command, without docker; in docker), what happens after the install
  and how to see it in the log, every setting, update, move and removal.
- Nothing of the bridge, of the client library or of the protocol changed.

## 0.3.0 (2026-10-12): nothing built in but the root key

- `trust/registries.txt` and `trust/seeds.txt` are gone, and with them
  `vlink_client::trust::SEEDS`. The client library builds in the key of
  the VLink root alone. Where a client starts — the registries of bridges
  and of call nodes, the first bridges before any list was fetched — is
  named by the signed manifest of the app's network (`registries`,
  `bridges`), not by the code: a registry or a bridge moves with a new
  manifest, not with a release of every app.
- The bridge reports to `https://hub.veydan.net/vlink`, the registry of
  the Veydan network, when neither `--registry` nor `VLINK_REGISTRY` names
  another (`vlink_client::trust::DEFAULT_REGISTRY`); a network of one's
  own names its own. `vlink watch` and `vlink list` ask the same one by
  default. The registry built in before was the old address
  `eu-1-vpush.veydan.net`. `trust::REGISTRIES` is that one registry as a
  list, for the project's server tools; the app does not read it.
- A bridge reports to the registry directly, and only so: the way around
  through a built-in bridge, when the direct way failed, is removed with
  the built-in bridges. A report is a few hundred bytes and passes a way
  that is throttled past a few kilobytes.
- The protocol is unchanged: bridges, hubs, the registry and clients of
  0.2 and 0.3 work together.

## 0.2.2 (2026-10-11): the image carries the agent of the project's monitoring

- The image `rookbeam/vlink` holds a second, small program beside the
  bridge: the agent of the project's monitoring. It is off unless the one
  who runs the bridge turns it on (`-e VEYDAN_AGENT=on`); without the
  switch it hands the process over to the bridge at once, and the bridge
  runs exactly as it did alone. What it reports once it is on, and what it
  never sees, is in README.md, "Project monitoring".
- `make image VAGENT=<file>` names the agent to put into the image.
- Nothing of the protocol, of the bridge or of the client library changed.

## 0.2.1 (2026-10-10): the bridge for Linux, the image for both architectures

- The bridge is released for Linux alone, x86_64 and aarch64, static: it
  is a server. The Windows and macOS builds of the bridge are gone; the
  client library still builds for every system the apps run on.
- The image `rookbeam/vlink` holds both architectures, linux/amd64 and
  linux/arm64, under the version and `latest`.
- `deploy/docker-compose.yml`: a bridge in one command, with every setting
  as a comment.
- This repository holds the sources; the binaries, their `SHA256SUMS` and
  the image are built and published by the release workflow of the Veydan
  Project. Nothing of the protocol or of the bridge's behaviour changed.

## 0.2.0 (2026-10-08): identity v2, the key apart from the certificate

- A bridge has a permanent Ed25519 key (`bridge.key`) of its own and,
  apart from it, a TLS key (`tls.key`, ECDSA P-256) with a certificate
  over it that the bridge's key signed (`bridge.crt`: that certificate,
  then the one carrying the bridge's key). The id is SHA-256 of the
  bridge's key (its SubjectPublicKeyInfo in DER); it was SHA-256 of the
  certificate. Clients and hubs pin the bridge's key, as HPKP did: any
  TLS certificate it signed is taken, and the TLS 1.3 handshake is signed
  with the TLS key in it. The TLS key is of the kind every browser takes,
  so a passer-by still completes the handshake and gets the nginx page
  rather than an alert that tells the bridge apart. `vlink id
  --renew-cert`, then a restart, replaces the TLS key and the
  certificate; the id stays. The same scheme is to serve the call nodes
  (`vcall`).
- A bridge signs its reports to the registry with its key (`key`, `ts`,
  `sig` in the registration): the registry takes an address for an id
  from that key only, so nobody else can report a bridge at an address
  of their own and have it struck off as unreachable there. A report
  older than five minutes is refused.
- No way back: a bridge made before this (P-256 key, id of the
  certificate) has to start again without `bridge.key`, `tls.key` and
  `bridge.crt`; its id changes,
  and `trust/seeds.txt` with it. The reference `address:port#id` and the
  link `veydan://vlink/…` keep their form.
- `vlink-proto` reads certificates with `rustls-webpki`, the parser rustls
  checks handshake signatures with.

## 0.1.2: the built-in bridge (2026-10-05)

- `trust/seeds.txt` names the bridge that runs now at `45.93.201.244:443`
  (it got a new key when its server was set up again); the two it named
  are gone. The seeds are how a client and a new bridge reach the registry
  when the direct way is closed. The bridge itself is the same as 0.1.1.

## 0.1.1: the image is `rookbeam/vlink` (2026-10-05)

- The Docker image of the bridge is published as `rookbeam/vlink`; the
  namespace `veydan` on Docker Hub is not the project's. The bridge itself
  is the same as 0.1.0.

## The app's link is `veydan://vlink/…` (2026-10-04)

- `vlink link` prints `veydan://vlink/<id>?a=<address:port>`; it printed
  `veydan://bridge/…`. The word "bridge" in the app's links is kept for
  bridges to other networks, and the app does not take the old form (it
  was never released). The reference `address:port#id` is unchanged.
  Nothing on the wire between bridges, hubs and the registry changed.

## One client, no copy (2026-10-02)

VLink is now kept in one repository with the Veydan app, and the app
depends on `vlink-proto` and `vlink-client` by path.

- The app's copy of the client is gone, and with it
  `scripts/export-client.sh`, `make export-client` and
  `make check-client-copy`.
- `vlink_client::trust`: the root's key, the registries and the seeds, read
  from `trust/` when the crate is compiled. The bridge and the app take
  them from there; the bridge no longer reads those files itself.

## Split for release, and hardening (2026-10-02)

The bridge is now separable from the hub for a public release.

- **VLink (this folder, public):** the wire protocol (`vlink-proto`), the
  client (`vlink-client`) and the bridge (`vlink`). No server passwords, no
  hub, no deployment of our own servers.
- **VHub (separate, private):** the hub and the registry, and the
  deployment of the project's servers. It takes `vlink-proto` from VLink by
  path, so the shared code is written once.

Hardening (abuse of a public service):
- The probe target is capped at 1 MiB a command and 4 MiB a stream: it is
  unauthenticated, so it can no longer be used to drain a hub's bandwidth.
- A connection carries at most 1024 streams (was 16384); a hub holds at
  most 4096 connections to the servers at once.
- The registry caps unverified bridges (64 at once, 4 per source /24) and
  forgets one that never shows its certificate (after 4 failed dial-backs,
  or an hour). A flood of made-up addresses no longer fills the pool or
  turns the hub into a port scanner.
- The canary serves POST only; it hands out no bytes on GET.

## 0.1.0 — 2026-10-02

After the first servers went up, for the app:

- `vlink-proto` split into what a client needs and what only the servers
  need; `scripts/export-client.sh` gives the app its copy.
- Client: shorter timeouts, three bridges called at once, a bridge that
  proved useless is called after the others for a minute.
- Registry: the canary (`/vlink/v1/canary`). `vlink link` prints the link
  the app takes.

First version: everything from the tunnel to self-registration.

- `vlink` bridge: one port for hubs, clients and passers-by (told apart by
  ALPN); relays client streams into hub links; shows a bare web server to
  anybody else.
- `vhub` hub: dials bridges, carries streams to the hosts of the app's
  manifest and no others, PROXY protocol v2 towards the servers, manifest
  from a file and from a URL (signed, greater serial only), admin socket.
- A hub backs off (up to 10 minutes) from a bridge that refuses its link.
- A bridge tries every new link with 512 KB each way before putting clients
  on it: a hub on a network that bytes do not reach is refused.
- Registry in `vhub`: bridges report in, a hub checks their certificate, a
  probe inside the country moves bytes through them, clients get a signed
  list of a few. Limits per subnet, address ranges, probation, bans.
- `vlink watch`: the probe. `vlink list`: the client's view of the registry.
- `vlink-client`: streams through a bridge with fail-over, and a local
  SOCKS5 door. Builds for Linux, Windows, macOS, Android.
- Keys: one Ed25519 root signs hub certificates and the delegation of the
  list key.
- Deploy scripts for the test servers, docker image of the bridge.

Measured on the test servers: `spec/measurements.md`.
