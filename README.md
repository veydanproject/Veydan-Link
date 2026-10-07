# VLink

A **bridge** that carries Veydan traffic to users whose way to the Veydan
servers is throttled.

```
user in a throttled network ── TLS to a bridge's address ──▶ bridge
                                   │ relays the connection, reads nothing
                                   ▼
                               a Veydan hub outside ──▶ the Veydan servers
```

What travels through a bridge is the user's own end-to-end TLS to the
Veydan server. **A bridge cannot read it, cannot change it, and holds no
keys and no data.** It only passes bytes on. It never connects out to the
Veydan servers itself: a hub, run by the Veydan project, dials in to the
bridge and does that part.

Anybody may run a bridge. The more there are, the harder they are to block.

## Run one

A server with a public IPv4 address and port 443 free, inside the country
whose users you want to help:

```
docker run -d --name vlink --restart=unless-stopped \
  --network=host -v vlink:/data rookbeam/vlink
```

That is all. The bridge makes its own key on the first start, tells the
Veydan registry it exists, and starts carrying traffic once a hub has
reached it. Nothing to configure, no domain, no certificate to get: the
bridge is known by its key, and the TLS key and certificate it makes next
to it may be replaced at any time (`vlink id --renew-cert`, then a
restart).

Or the binary, as a service — see `deploy/vlink.service`.

A bridge that should not be listed publicly (only given to people you
choose) runs with `-e VLINK_PRIVATE=true`; share its reference, which
`docker exec vlink /vlink id --addr <your-ip>:443` prints, or the link the
Veydan app takes, which `docker exec vlink /vlink link --addr <your-ip>:443`
prints (`veydan://vlink/<id>?a=…`). People paste either into Chat settings →
Network → Bridges → Add bridge, or tap the link in a message.

## What it does and does not see

- **Sees:** the IP address a user connects from, and how much they send.
- **Does not see:** who the user is, what they write, whom they write to,
  or any file they send. All of that is encrypted between the user's app
  and the Veydan server, end to end.

Running a bridge carries the usual responsibility of running a public
server. Consider the rules of your hosting provider and your country.

## What is in this folder

```
crates/vlink-proto    the wire protocol: who a bridge is, streams, signed lists
crates/vlink-client   opening a stream through a bridge (the Veydan app uses this)
crates/vlink          the bridge itself
deploy/               the systemd unit and the docker image
trust/                what is built in: the Veydan root (certificate and key),
                      the registries, the first bridges
```

The hub that bridges connect to is run by the Veydan project and is not
here. It uses `vlink-proto` from this folder.

## Build it yourself

```
make release          a static Linux binary in dist/
make image            the docker image
make test             the tests
```

The binary is one static file with no dependencies, so you can read this
source, build it, and run exactly what you built.

## Licence

VLink is under the PolyForm Perimeter License 1.0.1, the licence of every
part of Veydan: [LICENSE](LICENSE) is the text that counts, and
[LICENSE-SUMMARY.md](LICENSE-SUMMARY.md) says it in short. In plain words:
you may run a bridge, for yourself or for anyone, and read, build, change
and share this source, as long as you do not use it to offer a product that
competes with it. Whoever you pass the bridge on to gets the licence with
it: the image carries it as `/LICENSE`, and each release has it next to the
binaries. The crates the bridge is built from are listed with their
licences in [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md), which goes
with the image and the releases too.
