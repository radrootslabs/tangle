# Tangle

A Nostr relay for collaborative farming and local food communities.

**What it does:** Tangle is a multi-tenant Nostr relay that routes requests to tenants by hostname. Each tenant has its own relay URL, Pocket store, resource and rate limits, and optional NIP-29 groups.

**[Getting started](#getting-started)**
| [Docs](https://radroots.dev/docs)
| [Config](config/)
| [Releases](https://radroots.dev/downloads/)
| [License](#license)

## Getting started

Install [Rust](https://rustup.rs/) and Git. The repository uses the toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

```sh
git clone https://radroots.dev/git/tangle.git && cd tangle

cargo check --workspace --locked
```

Copy the host and tenant config files:

```sh
mkdir -p runtime/tenants

cp config/tangle.host.example.json runtime/tangle.host.json
cp config/tenants/farmers_market.example.json runtime/tenants/farmers-market.json
```

Run the relay:

```sh
cargo run -p tangle -- config validate --config "runtime/tangle.host.json"
cargo run -p tangle -- tenant list --config "runtime/tangle.host.json"
cargo run -p tangle -- run --config "runtime/tangle.host.json"
```

Check readiness and the tenant's NIP-11 document:

```sh
curl http://localhost:7070/.well-known/tangle/ready

curl --header 'Accept: application/nostr+json' --header 'Host: relay.radroots.test' http://localhost:7000/
```

## Protocol support

- **All tenants:** [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md), [NIP-11](https://github.com/nostr-protocol/nips/blob/master/11.md), [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md), [NIP-45](https://github.com/nostr-protocol/nips/blob/master/45.md), and [NIP-70](https://github.com/nostr-protocol/nips/blob/master/70.md)
- **Group-enabled tenants:** [NIP-29](https://github.com/nostr-protocol/nips/blob/master/29.md)

## Status

Tangle is under active development. Interfaces and configuration may change.

## Acknowledgements 👋

Tangle is a _mashup_ of:
- `chorus` https://github.com/mikedilger/chorus
- `zooid` https://gitea.coracle.social/coracle/zooid

Thanks to [Mike](https://github.com/mikedilger) and [Jon](https://github.com/staab) for creating and open-sourcing these projects.

## License

This repository is licensed under `AGPL-3.0-or-later`. See [LICENSE](LICENSE).
