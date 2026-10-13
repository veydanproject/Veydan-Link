# VLink

## Support the Veydan network

You can support the Veydan network by installing **Veydan Link** (a bridge)
and **Veydan Call** (a call node) on a server of yours. One command, as
root, on a server with a public IPv4 address, best of all inside the
country whose people you want to help:

```sh
curl -fsSL https://raw.githubusercontent.com/veydanproject/Veydan-Server/main/install.sh | sudo bash -s -- --volunteer
```

It installs both as services of the system, without docker, and they join
the network by themselves: nothing to configure, no domain, no account.
The bridge gives people in a country that closes the way to Veydan a way
in; the call node makes the calls of people near it fast. Neither can read
anything of anyone. The bridge alone: `--bridge` instead of
`--volunteer`; the call node is [Veydan-Call](https://github.com/veydanproject/Veydan-Call).
What each of them needs, what the command does to the server and how to
see that it works is below.

## What it is

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

## What you need

- A server with a public IPv4 address **inside the country whose users you
  want to help**. A bridge anywhere else helps nobody: its whole point is to
  be reachable where the direct way is closed. A small VPS is enough.
- One free TCP port. 443 is best: it looks like any web server and is
  blocked least.
- Linux, and the right to run a command as root. No domain, no certificate,
  no account anywhere.

## Install

Two ways. Both give the same bridge; take the one you are used to.

### As a service of the system (no docker)

One command, as root:

```sh
curl -fsSL https://raw.githubusercontent.com/veydanproject/Veydan-Server/main/install.sh | sudo bash -s -- --bridge
```

It asks two things: the port (Enter keeps 443) and whether the bridge is
open to anybody or private (Enter keeps open). Without questions:
`… | sudo bash -s -- --bridge --yes`.

What it does to the server, all of it:

1. installs a few small packages it needs itself (`curl`, `jq`,
   `openssl`, `ufw` and the like);
2. downloads `vlink` for this machine (x86_64 or aarch64) from the
   [releases](https://github.com/veydanproject/Veydan-Link/releases) of this
   repository and checks it against `SHA256SUMS`;
3. puts it in `/opt/vlink` under a user of its own, `vlink`, with the
   systemd unit of this repository (`deploy/vlink.service`: the bridge may
   touch the network and its one directory, nothing else of the machine);
4. turns the firewall `ufw` on with ssh and the port of the bridge open
   and the rest closed. If the server already serves something else, keep
   the firewall as it is: put a file `server.conf` with the line
   `FIREWALL=none` in the directory you run the command from;
5. keeps its answers in `/opt/veydan/server.conf`, so that the same
   command, run again, asks nothing;
6. starts the bridge and prints its reference and its link:

```
Bridge  203.0.113.7:443#300d0089…
  veydan://vlink/300d0089…?a=203.0.113.7%3A443
```

It is tested on Debian 13; any Linux with systemd should do. The installer
is the kit [Veydan-Server](https://github.com/veydanproject/Veydan-Server),
which you can read before you run it.

A call node on the same server, so that calls of people near you are fast
too: the same command with `--volunteer` instead of `--bridge`
([Veydan-Call](https://github.com/veydanproject/Veydan-Call) says what a
call node is).

By hand, if you would rather not run an installer: take
`vlink-linux-x86_64` (or `-aarch64`) and `SHA256SUMS` from the releases,
check the sum, then

```sh
useradd --system --user-group --home /opt/vlink --shell /usr/sbin/nologin vlink
install -d -m 0755 /opt/vlink /opt/vlink/bin /opt/vlink/etc
install -d -m 0700 -o vlink -g vlink /opt/vlink/data
install -m 0755 vlink-linux-x86_64 /opt/vlink/bin/vlink
install -m 0644 deploy/vlink.service /etc/systemd/system/vlink.service
systemctl daemon-reload && systemctl enable --now vlink
```

### In docker

```sh
docker run -d --name vlink --restart=unless-stopped --network=host -v vlink:/data rookbeam/vlink
```

or with compose (`deploy/docker-compose.yml`: the image, the volume, host
networking and every setting as a comment):

```sh
curl -fsSLO https://raw.githubusercontent.com/veydanproject/Veydan-Link/main/deploy/docker-compose.yml
docker compose up -d
```

The image is built for amd64 and arm64. The bridge's key lives in the
volume `vlink`.

### The firewall of your provider

Whichever way you took: the port of the bridge (443/tcp) must be open from
the Internet. Many providers have a firewall of their own in their panel,
besides the one on the server.

## What happens after the install

Nothing more is asked of you. In order:

1. On its first start the bridge makes its own key. The key *is* the
   bridge: its id is in the reference above.
2. It tells the registry of the Veydan network that it exists, and says so
   again every five minutes.
3. The registry connects back to the address the report came from and
   checks the key. A bridge behind a closed port stops here.
4. The network may hold a new bridge until its owner approves it.
5. A hub of the network, outside the country, connects **to the bridge**
   and sends test bytes through the link both ways. A link that stalls is
   dropped: such a bridge would be of no use to anybody.
6. The bridge is given to the apps of people who need one. From here it
   carries traffic.

This takes ten to fifteen minutes. To see where your bridge is:

```sh
journalctl -u vlink -f          # a service
docker logs -f vlink            # docker
```

| The log says | It means |
|---|---|
| `bridge is up` | it runs and listens |
| `registry knows this bridge state=New` | reported; the registry has not reached it yet |
| `… state=Verified` | the key is checked; waiting for approval, for a hub, or for the first ten minutes to pass |
| `… state=Active` | given to apps: it works |
| `… state=Degraded`, `Dead` | the hubs lost their link to it, or it went silent; it comes back by itself when the link does |
| `… state=Banned` | the owner of the network refused it |
| `status hubs=1 clients=… streams=…`, every minute | the hubs connected now, and what the bridge carries |
| `registry was not told` | this server cannot reach the registry; it tries again by itself |
| `hub refused: its link does not carry bytes` | the way between this server and that hub is throttled; the bridge is used through other hubs, or not at all from this network |

If it stays `New` for more than a few minutes, the port is not reachable
from outside: open it at your provider. Behind a NAT or a forwarded port,
tell the bridge how the world reaches it: `VLINK_PUBLIC_IP`,
`VLINK_PUBLIC_PORT`.

## A private bridge

A bridge that is told to nobody, for people you choose: answer "private" to
the installer, or run with `VLINK_PRIVATE=true`. Give them the link the
installer printed; it is also what these print:

```sh
runuser -u vlink -- /opt/vlink/bin/vlink link --addr <your-ip>:443 --data /opt/vlink/data   # a service
docker exec vlink /vlink link --addr <your-ip>:443                                           # docker
```

(`vlink id --addr …` prints the bare reference, `address:port#id`.) People
paste either into Chat → Settings → Network → Bridges → Add bridge, or tap
the link in a message.

## Settings

Environment variables, all optional. A service reads them from
`/opt/vlink/etc/vlink.env` (the installer writes that file from its
answers; `systemctl restart vlink` applies a change); docker takes them
with `-e`.

| Variable | Default | What |
|---|---|---|
| `VLINK_LISTEN` | `0.0.0.0:443` | the address and port to listen on |
| `VLINK_DATA` | `data` (`/opt/vlink/data`, `/data` in the image) | where the bridge keeps its key and certificate |
| `VLINK_PRIVATE` | `false` | `true`: report to no registry |
| `VLINK_PUBLIC_IP` | the address its reports come from | the address the world reaches this machine at, when it is another one |
| `VLINK_PUBLIC_PORT` | the port it listens on | the port the world reaches the bridge at, when it is another one (a container, a forwarded port) |
| `VLINK_MAX_CONNECTIONS` | `8192` | connections held at once |
| `VLINK_REGISTRY` | the Veydan network's, `https://hub.veydan.net/vlink` | registries to report to instead, separated by commas: for a network of your own |
| `VLINK_ROOT` | the Veydan root, built in | another root (a PEM file), for a network of your own |
| `VLINK_LOG` | `info` | `debug` shows every stream |

## Update, move, remove

- **Update.** A service: the same install command again; it replaces the
  program when a newer release is out and keeps the key and the settings.
  Docker: `docker pull rookbeam/vlink`, then remove the container and run
  it again (`docker compose pull && docker compose up -d`).
- **Move to another server.** Copy `/opt/vlink/data` (or the volume) and
  install there. The id stays; at a new address the registry checks the
  bridge again, and a network that approves by hand approves it again.
- **A new certificate.** The TLS key and certificate beside the key may be
  replaced at any time: `vlink id --renew-cert` (a service:
  `runuser -u vlink -- /opt/vlink/bin/vlink id --renew-cert --data /opt/vlink/data`;
  docker: `docker exec vlink /vlink id --renew-cert`), then a restart. The
  id does not change.
- **Remove.** A service:
  `systemctl disable --now vlink && rm /etc/systemd/system/vlink.service && rm -rf /opt/vlink && userdel vlink`.
  Docker: `docker rm -f vlink && docker volume rm vlink`. The registry
  forgets a bridge that went silent by itself.

## Project monitoring (optional)

The image carries a second, small program: the agent of the project's
monitoring. It is off unless you turn it on with `-e VEYDAN_AGENT=on` (or
`VEYDAN_AGENT: "on"` under `environment:` in `docker-compose.yml`). Once
on, it sends a short report every five minutes to the project's servers,
signed with the bridge's own key (`bridge.key` in `/data`): the bridge's
kind, version and uptime, the CPU and memory of the container, its last
errors (no address of anyone in them), and the results of the checks it
was asked for. Those checks are only ever two: carrying test bytes
through a bridge of the project, and asking a relay of the project for
nothing; the agent refuses any target that is not in the project's signed
lists. That shows the project how its network looks from where you are.
It reports nothing about the server beyond the container, nothing about
who uses the bridge, and never sees
anyone's messages, files or calls. It opens no port: it only sends out, so
your firewall and NAT stay as they are. To turn it off, remove the variable
and start the container again; the bridge works the same either way.

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
trust/                what is built in: the Veydan root (certificate and key)
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
