# derpmap-to-lsrules.jq
#
# Converts the Tailscale DERP map into a Little Snitch .lsrules rule group,
# emitting one rule per (protocol, port) per region, addressed by IP literal.
#
# STUN rules are constrained to the Tailscale code IDs; port 80 and port 443
# rules use the general --arg process value (default "any").
#
# Usage:
#   curl -fsSL https://controlplane.tailscale.com/derpmap/default \
#     | jq -f derpmap-to-lsrules.jq \
#          --arg name "Tailscale DERP servers" \
#          --arg process any \
#     > tailscale-derp.lsrules
#
# --arg stun_processes overrides the STUN identities; it takes a
# comma-separated list and generates one rule per identity.
#
# A parallel set of `"process": "any"` + `"via": <code ID>` rules is also
# emitted. --arg via_scope selects which groups get them: "all" (default),
# "stun", or "none". --arg via_processes overrides the identities used,
# taking a comma-separated list like --arg stun_processes.

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

# Per-node service list. `svc` is the machine-readable tag used to pick the
# process; `label` is the human-readable text used in the rule notes.
def services:
  [ (if (.STUNOnly // false) then empty
     else { svc: "derp-443",
            label: "DERP over port 443",
            protocol: "tcp",
            port: (.DERPPort | default_port(443)) }
     end),
    (if (.STUNPort // 0) == -1 then empty
     else { svc: "stun",
            label: "STUN",
            protocol: "udp",
            port: (.STUNPort | default_port(3478)) }
     end),
    (if ((.CanPort80 // false) and ((.STUNOnly // false) | not))
     then { svc: "derp-80",
            label: "DERP over port 80",
            protocol: "tcp",
            port: 80 }
     else empty
     end) ];

# Code IDs for the Tailscale apps, both Mac App Store and direct .pkg versions.
# These allow matching on the process regardless of path -- see:
# https://help.obdev.at/littlesnitch6/adv-lsrules-file-format#IDF

def tailscale_code_ids:
  [ "identifier.W5364U7YZB/io.tailscale.ipn.macos.network-extension",
    "identifier.W5364U7YZB/io.tailscale.ipn.macos",
    "identifier.W5364U7YZB/io.tailscale.ipn.macsys.network-extension",
    "identifier.W5364U7YZB/io.tailscale.ipn.macsys"
  ];

# Splits a comma-separated --arg value, trimming surrounding whitespace and
# discarding empty entries.
def split_arg:
  split(",")
  | map(sub("^\\s+"; "") | sub("\\s+$"; ""))
  | map(select(length > 0));

($ARGS.named.process // "any") as $process
| (if (($ARGS.named.stun_processes // "") | length) == 0
   then tailscale_code_ids
   else ($ARGS.named.stun_processes | split_arg)
   end) as $stun_processes
| (if (($ARGS.named.via_processes // "") | length) == 0
   then tailscale_code_ids
   else ($ARGS.named.via_processes | split_arg)
   end) as $via_processes
| ($ARGS.named.via_scope // "all") as $via_scope
| ($ARGS.named.name // "Tailscale DERP servers") as $groupname
| {
    name: $groupname,
    description:
      "Allows outgoing traffic to port 443 and STUN to every node in the Tailscale DERP map, plus port 80 for nodes advertising CanPort80. One rule per port per region, addressed by IP literal. STUN is constrained to the Tailscale code IDs. Generated from https://controlplane.tailscale.com/derpmap/default",
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
            | { svc, label, protocol, port, addrs: $addrs } ]
        | group_by([.protocol, .port])
        | sort_by([.[0].protocol, .[0].port])
        | .[]
        | (map(.addrs) | add | unique) as $remotes
        | (map(.label) | unique | join(" / ")) as $labels
        | (if (map(.svc) | index("stun")) then $stun_processes else [$process] end) as $procs
        | .[0] as $first
        | ($remotes | join(",")) as $remote_str
        | "region \($rid) \($region.value.RegionCode // "?") / \($region.value.RegionName // "?"), \($remotes | length) address(es)" as $where
        | ( ( $procs[]
              | { action: "allow",
                  process: .,
                  direction: "outgoing",
                  protocol: $first.protocol,
                  ports: ($first.port | tostring),
                  "remote-addresses": $remote_str,
                  notes: "\($labels): \($where)" } ),
            ( if ($via_scope == "all")
                 or ($via_scope == "stun" and ((map(.svc) | index("stun")) != null))
              then ( $via_processes[]
                     | { action: "allow",
                         process: "any",
                         via: .,
                         direction: "outgoing",
                         protocol: $first.protocol,
                         ports: ($first.port | tostring),
                         "remote-addresses": $remote_str,
                         notes: "\($labels), any process via \(.): \($where)" } )
              else empty
              end ) )
      ]
  }
