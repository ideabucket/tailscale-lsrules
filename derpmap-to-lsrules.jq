# derpmap-to-lsrules.jq
#
# Converts the Tailscale DERP map into a Little Snitch .lsrules rule group,
# emitting one rule per (protocol, port) per region, addressed by IP literal.
#
# Usage:
#   curl -fsSL https://login.tailscale.com/derpmap/default \
#     | jq -f derpmap-to-lsrules.jq \
#          --arg name "Tailscale DERP servers" \
#     > tailscale-derp.lsrules
#
# --arg process may be omitted, in which case "any" is used.

# DERPNode.DERPPort: "If zero, 443 is used."
# DERPNode.STUNPort: "Zero means 3478. To disable STUN on this node, use -1."
# Both carry `json:",omitempty"`, so zero values are absent from the JSON.
def default_port($p): if . == null or . == 0 then $p else . end;

# DERPNode.IPv4 / .IPv6 are optional literals. The conventional string to
# disable a family is "none", so anything not address-shaped is discarded.
def is_ip:
  type == "string"
  and (test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")
       or test("^[0-9A-Fa-f:]+:[0-9A-Fa-f:.]*$"));

def node_addresses: [ .IPv4, .IPv6 ] | map(select(is_ip));

# Per-node service list: {label, protocol, port} for each port the node exposes.
def services:
  [ (if (.STUNOnly // false) then empty
     else { label: "DERP HTTPS",
            protocol: "tcp",
            port: (.DERPPort | default_port(443)) }
     end),
    (if (.STUNPort // 0) == -1 then empty
     else { label: "STUN",
            protocol: "udp",
            port: (.STUNPort | default_port(3478)) }
     end),
    (if ((.CanPort80 // false) and ((.STUNOnly // false) | not))
     then { label: "DERP HTTP (captive portal check)",
            protocol: "tcp",
            port: 80 }
     else empty
     end) ];

($ARGS.named.process // "any") as $process
| ($ARGS.named.name // "Tailscale DERP servers") as $groupname
| {
    name: $groupname,
    description:
      "Allows outgoing HTTPS and STUN to every node in the Tailscale DERP map, plus HTTP on port 80 for nodes advertising CanPort80. One rule per port per region, addressed by IP literal. Generated from https://login.tailscale.com/derpmap/default",
    rules:
      [ (.Regions // {})
        | to_entries
        | sort_by(.value.RegionID // 0)
        | .[] as $region
        | ($region.value.RegionID // $region.key) as $rid
        | [ ($region.value.Nodes // [])[]
            | (node_addresses) as $addrs
            | select(($addrs | length) > 0)
            | services[]
            | { label, protocol, port, addrs: $addrs } ]
        | group_by([.protocol, .port])
        | sort_by([.[0].protocol, .[0].port])
        | .[]
        | (map(.addrs) | add | unique) as $remotes
        | {
            action: "allow",
            process: $process,
            direction: "outgoing",
            protocol: .[0].protocol,
            ports: (.[0].port | tostring),
            "remote-addresses": ($remotes | join(",")),
            notes: "\(map(.label) | unique | join(" / ")): region \($rid) \($region.value.RegionCode // "?") / \($region.value.RegionName // "?"), \($remotes | length) address(es)"
          }
      ]
  }
