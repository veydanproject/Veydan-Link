# Changelog

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
