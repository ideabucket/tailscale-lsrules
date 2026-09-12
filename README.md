# Tailscale DERP Server `.lsrules`

A subscribable Little Snitch rule group which fetches the [official Tailscale DERP map](https://controlplane.tailscale.com/derpmap/default) each day and transforms it to a `.lsrules` file using `jq` and a Github action.

Add this URL to Little Snitch to subscribe:

```
https://raw.githubusercontent.com/ideabucket/tailscale-lsrules/main/derpmap.lsrules
```

If you don't know how to do that without being told, you shouldn't do it.

This repo is **not** provided, authorised, endorsed, or sponsored by Tailscale.

This repo was forked from [jmaddington/tailscale-ips](https://github.com/jmaddington/tailscale-ips), and the rest of this README is lightly modified from his version. 

## How It Works

A [GitHub Action](.github/workflows/update-tailscale-ips.yml) runs once a day (12:00 UTC):

1. Fetches the DERP map JSON from `https://controlplane.tailscale.com/derpmap/default`
2. Pipes the result through [jq](https://jqlang.org) using [this Claude-written jq filter](derpmap-to-lsrules.jq). That filter creates, on a one-rule-per-region basis:
   - For each of the following processes…
     - The Mac App Store version of the Tailscale network extension (code ID: `W5364U7YZB/io.tailscale.ipn.macos.network-extension`)
     - The Mac App Store version of the main Tailscale app (code ID: `W5364U7YZB/io.tailscale.ipn.macos`)
     - The direct-install version of the Tailscale network extension (code ID: `W5364U7YZB/io.tailscale.ipn.macsys.network-extension`)
     - The direct-install version of the main Tailscale app (code ID: `W5364U7YZB/io.tailscale.ipn.macsys`)
   - …each of the following rules…
     - Port `3478/udp` to every DERP server unless it declares `STUNPort: -1`, directly and as a via-process
     - Port `80/tcp` to every DERP server that declares `CanPort80: true`, directly and as a via-process
     - Port `443/tcp` to every DERP server, directly and as a via-process
   - …and in addition…
     - Port `80/tcp` to every DERP server for any process
     - Port `443/tcp` to every DERP server for any process
4. Commits and pushes the updated rules **only if they changed**

When the IPs *did* change, the commit message is: `.lsrules for DERP servers as of YYYY-MM-DD`

### Keepalive commits (and why this repo force-pushes)

GitHub automatically disables scheduled workflows after 60 days of repository inactivity, and scheduled runs alone do **not** count as activity -- only commits do. Since the DERP IPs often go weeks or months without changing, the workflow keeps itself alive with a "keepalive" commit on the days nothing changed:

- The keepalive is a single empty commit at the tip of `main`, with the message `YYYY-MM-DD - keep github workflow alive`.
- To avoid piling up one of these per quiet day, the workflow **rewrites the existing keepalive commit in place** (`git commit --amend --allow-empty`) and **force-pushes** it, rather than adding a new one. So `main` carries at most one keepalive commit at any time.

**If you clone or track this repo:** `main`'s history is periodically rewritten by these force-pushes, so a plain `git pull` may complain about diverged history. This repo is intended to be consumed via the raw file URLs above (raw URLs are unaffected by history rewrites), not cloned. If you do keep a clone, use `git fetch && git reset --hard origin/main` to re-sync, and don't build on top of the keepalive commit -- it will be replaced.

## What are DERP servers?

Tailscale uses DERP (Designated Encrypted Relay for Packets) servers as fallback relays when direct peer-to-peer connections can't be established. They are not used for normal traffic when a direct WireGuard connection succeeds, but firewalls need to allow access to them for Tailscale to function when NAT traversal fails.

See the [Tailscale documentation on DERP](https://tailscale.com/kb/1232/derp-servers) for more details.
