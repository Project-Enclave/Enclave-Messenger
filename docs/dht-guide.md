# DHT (internet discovery) — what it is, and how to set it up

## What this actually is

Every other transport in Enclave finds peers on your local network —
broadcast, Bluetooth, that kind of thing. DHT is the one exception: it's
how two nodes that *aren't* on the same LAN find each other over the
open internet.

It's a Kademlia-style distributed hash table — the same family of
protocol BitTorrent uses to find peers without a central tracker. There's
no server. Nodes know a handful of other nodes, who know a handful of
others, and a lookup walks that graph until it finds who you're looking
for.

Two things this is **not**, said plainly before you set anything up:

- **It does not get you through NAT or a firewall by itself.** DHT
  answers "where does this person claim to be reachable" — it doesn't
  open a hole in your router. If nothing else on your network can reach
  you from the outside, being *found* via DHT won't make you *reachable*.
  You still need port forwarding, a VPS, or similar.
- **There's no public bootstrap server.** Real-world DHTs like
  BitTorrent's ship with well-known bootstrap nodes baked in, so a fresh
  client always has somewhere to start. This one doesn't have that —
  you need to already know the address of at least one node that's
  already in the swarm.

If neither of those apply to you — you're behind a normal home router
with no port forwarding, and you don't have another node's address —
DHT genuinely will not do anything useful for you yet, and that's not a
bug. Skip to [When DHT actually helps](#when-dht-actually-helps) before
setting it up.

## Enabling it

There are three ways in, all equivalent — they write to the same config.

### Web UI

Settings → **network** tab:

- **enable DHT** — the on/off switch
- **bootstrap nodes** — one `host:port` per line
- **your reachable address** — optional; only needed if you're the one
  other people bootstrap from (see [setting up a real swarm](#setting-up-a-real-swarm) below)

Changes here apply the next time the node starts, not live on an
already-running one.

### TUI

`:settings`, then select the DHT fields and press Enter. `dht_enabled`
toggles immediately; `dht_bootstrap` and `dht_public_ip` open a text
prompt. Same "applies on next start" rule.

### Command line

```bash
python3 main.py run --dht \
    --dht-bootstrap 203.0.113.5:51820 \
    --dht-bootstrap another-host.example.com:51820 \
    --dht-public-ip 198.51.100.9
```

- `--dht` — turns it on for this run (`dht_enabled` in config).
- `--dht-bootstrap` — repeatable, one address per flag.
- `--dht-public-ip` — optional. Only pass this if you already know your
  own reachable address (a VPS with a static IP, for example).

One nuance worth knowing rather than discovering by surprise: these
three flags are independent of each other, not gated behind `--dht`.
Passing `--dht-bootstrap` without `--dht` still saves that bootstrap
address into config — it just doesn't turn DHT on for this run. That
saved address takes effect the next time DHT actually is enabled,
whether that's a later CLI run with `--dht`, or flipping the toggle in
the web UI or TUI. Nothing is lost; it just doesn't do anything on the
run where you set it without also passing `--dht`.

All three ways write to the same three config keys, so it doesn't matter
which one you used last time — they'll always show each other's current
values:

| Config key | CLI flag | What it holds |
|---|---|---|
| `dht_enabled` | `--dht` | on/off |
| `dht_bootstrap` | `--dht-bootstrap` (repeatable) | list of `host:port` |
| `dht_public_ip` | `--dht-public-ip` | your own address, if known |

## Setting up a real swarm

Since there's no public bootstrap, *someone* has to be the first node —
the one everyone else's bootstrap list points at.

### If you're that first node

You need to actually be reachable from the internet. The realistic
options:

1. **A VPS with a public IP.** Simplest case — pass
   `--dht-public-ip <that IP>` so you don't rely on auto-detection, and
   make sure the DHT port (see [ports](#ports) below) is open in
   whatever firewall the VPS provider gives you.
2. **Port forwarding on your home router.** Forward the DHT port to the
   machine running Enclave. Your public IP is whatever your ISP gives
   you — check it (e.g. `curl ifconfig.me`) and pass it as
   `--dht-public-ip`, or leave it unset and let auto-detection try.

Either way, you don't need a bootstrap list yourself — you're what
everyone else bootstraps from. Just enable DHT with no
`--dht-bootstrap` flags.

### If you're joining an existing swarm

You need one thing: the `host:port` of a node that's already reachable
(the VPS or forwarded home node above, or any other node someone gave
you the address of). Pass it as `--dht-bootstrap`. You do not need your
own public IP or port forwarding just to *join* — only to be reachable
*by* other people through DHT.

### Auto-detection

If you don't pass `--dht-public-ip`, the node tries to work out its own
reachable address by asking a bootstrap peer to echo back what address
your traffic arrived from (the same idea STUN servers use for NAT
traversal, just simpler). This works for straightforward NAT setups; it
does not work through symmetric NAT or carrier-grade NAT, which is most
of what "no port forwarding available" actually means in practice. If
auto-detection can't work out your address and you haven't set one
manually, other peers won't be able to reach you even though you can
still look things up.

## Ports

DHT runs on the node's transport port **+ 1000** by default (transport
`43100` → DHT `44100`), or on `dht_port` if you set that explicitly in
config. If you're forwarding a port on a router, forward this one, not
the transport port itself.

## Checking it's actually working

- **Web UI** — Settings → network shows whether DHT is enabled in
  config. `GET /api/config/dht` also returns `dht_active`, which
  reflects whether a DHT node is actually running right now (these can
  differ: `dht_enabled` is what's configured, `dht_active` is whether a
  node is currently up).
- **CLI** — `main.py run` prints `DHT (internet discovery) enabled.` on
  startup if it's on. It doesn't tell you whether anyone can actually
  reach you — that's the NAT caveat above, and nothing in the app can
  verify that from the inside.
- **Logs** — the `network` logger records announce attempts, lookups,
  and any peer a DHT lookup resolves. If you enabled DHT and nothing
  ever shows up in peer results after a few minutes, the most likely
  causes, in order: your bootstrap address is wrong or unreachable, your
  own node isn't actually reachable from outside (NAT/firewall), or the
  swarm you're trying to join is just you.

## When DHT actually helps

- Messaging someone who isn't on your LAN and isn't reachable by phone
  number or Bluetooth — the actual reason this transport exists.
- You run a small, known group of nodes (a few friends, a team) where
  one of you already has a VPS or a forwarded port to act as the
  anchor everyone else bootstraps from.

## When it won't, yet

- You want to reach a stranger with no prior address exchange and no
  shared bootstrap node. There's no discovery-of-strangers mechanism —
  DHT here finds nodes you already have *an address for*, directly or
  transitively through the swarm; it doesn't publish a public directory
  of who's online.
- Both sides are behind ordinary home NAT with no port forwarding and
  no VPS anywhere in the group. Auto-detection can't manufacture
  reachability that doesn't exist.

Both of those are open, known limitations (see the project status page)
— not things you're doing wrong.
