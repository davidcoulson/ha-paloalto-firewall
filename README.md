# Palo Alto Networks Firewall for Home Assistant

[![CI](https://github.com/davidcoulson/ha-paloalto-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/davidcoulson/ha-paloalto-firewall/actions/workflows/ci.yml)

Monitors PAN-OS firewalls over the XML API — standalone, or an **active/passive HA pair** treated as one unit.

Built as a modern replacement for [FoUStep/ha-pan-customintegration](https://github.com/FoUStep/ha-pan-customintegration) (itself a fork of Skalavala's 2018 sensor). It reuses the same operational commands but adds a UI config flow, async polling, devices, HA-pair awareness and update/licence tracking.

## Install

1. Copy `custom_components/paloalto_firewall` into `/config/custom_components/` (or add this repo to HACS as a custom integration repository).
2. Restart Home Assistant.
3. **Settings → Devices & services → Add integration → Palo Alto Networks Firewall.**

Enter the **management** address of each firewall (not a floating/dataplane IP). For an HA pair enter both; for a standalone box leave the second field empty.

**Verify TLS certificate** is on by default. Turn it off if the management interface uses the firewall's default self-signed certificate, or a certificate that doesn't match the address you entered. Setup tells you when that's the reason it can't connect.

## Firewall prep: a read-only API account

On the firewall (it syncs to the peer with HA config sync):

1. **Device → Admin Roles → Add** — e.g. `ha-monitor`
   - *Web UI*: disable everything
   - *XML API*: enable **Operational Requests** only (also covers the config backup)
   - *Command Line*: None · *REST API*: disable everything
2. **Device → Administrators → Add** — role-based, profile `ha-monitor`, a strong password.
3. Commit.

The integration logs in with username/password, generates an API key per firewall, and regenerates it automatically if it expires (PAN-OS 10.2+ key lifetime). If the password is changed, Home Assistant prompts for re-authentication.

## What you get

**One device per firewall**

| Entity | Notes |
|---|---|
| HA state / HA peer state | active, passive, suspended, non-functional… (`standalone` if HA is off) |
| HA peer connection, HA config synchronized | binary sensors; HA1/HA1-backup/HA2 link status as attributes |
| Management CPU / memory | memory excludes cache (uses *avail Mem*) |
| Dataplane CPU, packet buffer | 1-minute average across all dataplane cores; per-DP in attributes |
| Active sessions, session table %, new connections/s, throughput, packet rate | from `show session info` |
| Temperature, Hardware alarm | hottest sensor; any thermal/fan/PSU alarm. Not created on VM-series |
| GlobalProtect users, Logged-in admins, IPsec tunnels up | usernames/tunnel names in attributes |
| PAN-OS update, Apps & threats content update | read-only update entities (see below) |
| Next licence expiry, Licence expired | |
| Last boot, versions (PAN-OS, content, AV, WildFire, URL, GP client), device certificate | diagnostic |
| Check for updates (button) | runs the update/licence check immediately |

**One "HA pair" device** (when two firewalls are configured)

| Entity | Notes |
|---|---|
| Active firewall | hostname of whichever unit is active; serial, mode and time-active as attributes |
| HA pair problem | on when a unit is unreachable, HA is off, peer link is down, config isn't synchronized, a unit is suspended/non-functional, nobody is active, or both are active. `problems` attribute lists why |
| Last failover | survives restarts |
| Active sessions, throughput, new connections/s, packet rate, dataplane CPU, GlobalProtect users, IPsec tunnels | **follow the active unit**, so graphs stay continuous across a failover. `source` attribute shows which unit fed the value |

### How the active unit is determined

A unit reporting itself `active` wins. If that unit is unreachable, the surviving unit's view of its peer is used — so if the active box dies, the passive one reporting `active` is picked up on the next poll. Each unit is polled independently; one being down (e.g. mid-upgrade) doesn't stop the other loading or updating.

### Failover event

`paloalto_firewall_failover` fires when the active unit changes:

```yaml
triggers:
  - trigger: event
    event_type: paloalto_firewall_failover
actions:
  - action: notify.mobile_app_phone
    data:
      title: Firewall failover
      message: "{{ trigger.event.data.previous_active }} → {{ trigger.event.data.new_active }}"
```

### Updates

`request system software check`, `request content upgrade check` and `request global-protect-client software check` run every 6 hours per unit (configurable) and in the background at startup. The **PAN-OS** update entity tracks the newest release **in your installed feature train** (e.g. 11.1.x) — moving to a new train is a planning decision, so the newest release overall is shown in the `newest_release_any_train` attribute instead. The **GlobalProtect client** update entity works the same way (e.g. newest 6.3.x vs the package the portal currently hands out), and is only created when a GlobalProtect client package is activated.

Update entities are read-only; nothing is downloaded or installed. PAN-OS only lets a superuser activate a GlobalProtect client package, so activate new client versions under Device → GlobalProtect Client.

To check right away, press a firewall's **Check for updates** button, or call the action from an automation (with a response, it returns installed and newest versions per firewall):

```yaml
action: paloalto_firewall.check_for_updates
response_variable: updates
```

## Network: logical routers, WAN egress, interfaces, jobs

These are read from the **active** firewall and live under the HA pair device (or the firewall's own device when standalone). Requires PAN-OS with the Advanced Routing Engine (logical routers).

**One child device per logical router**, each with:

| Entity | Notes |
|---|---|
| Internet egress / IPv6 internet egress | the zone this logical router sends internet traffic to (FIB lookup of 1.1.1.1 / 2606:4700:4700::1111); interface, next hop, vsys, matching route and ECMP paths as attributes |
| Path monitor *interface* via *next hop* | one connectivity sensor per monitored next hop; monitored routes and probe results as attributes |
| FIB routes | IPv4/IPv6 route counts (diagnostic) |
| BGP peers established | count of Established peers; `down` lists the rest, `peers` every peer's state (BGP-enabled logical routers only) |
| BGP *peer* | one connectivity sensor per BGP peer, on while Established; peer/local IP, AS numbers, peer group, uptime, accepted/sent prefixes per address family and last reset reason as attributes |

When an egress changes, `paloalto_firewall_egress_change` fires with `logical_router`, `family`, `previous_interface`/`previous_zone` and `interface`/`zone`/`nexthop`. For example, to be told when internal traffic fails over between WANs:

```yaml
triggers:
  - trigger: event
    event_type: paloalto_firewall_egress_change
    event_data:
      logical_router: core-vr
      family: ipv4
actions:
  - action: notify.mobile_app_phone
    data:
      message: "Internet now via {{ trigger.event.data.zone }} (was {{ trigger.event.data.previous_zone }})"
```

`paloalto_firewall_bgp_peer_change` fires when a peer enters or leaves Established, with `logical_router`, `peer`, `peer_ip`, `remote_as`, `state` and `last_reset`. Peers removed from the configuration have their entities cleaned up on the next reload.

**On the pair device:**

- Interface **link**, **link speed**, and **in/out throughput** for the interfaces chosen in *Configure*. With *Pick interfaces automatically* on (the default) that's the interfaces used by path monitors and internet routes, re-evaluated as routing changes; turn it off to choose a fixed list
- **Uncommitted changes**, **Running jobs**, and **Last commit** (from the firewall's job history; unknown once it ages out)

### IPv6 delegated prefixes and NPTv6

For each DHCPv6 prefix-delegation pool (e.g. one per ISP), on the pair device:

| Entity | Notes |
|---|---|
| *pool* delegated prefix | the prefix the ISP currently delegates; interface, vsys, lease, lifetimes and inherited interface addresses as attributes |
| *pool* NPTv6 prefix mismatch | **on** when an NPTv6 rule in that WAN's vsys translates outside the delegated prefix, or translates to a single /128 interface address (interface-address Dynamic IP with no inherited prefix). `problems` lists the offending rules |

`paloalto_firewall_prefix_change` fires with `pool`, `interface`, `previous_prefix` and `prefix` when an ISP hands out a new prefix, so you can get notified before IPv6 breaks:

```yaml
triggers:
  - trigger: event
    event_type: paloalto_firewall_prefix_change
actions:
  - action: notify.mobile_app_phone
    data:
      message: "{{ trigger.event.data.pool }} prefix changed: {{ trigger.event.data.previous_prefix }} → {{ trigger.event.data.prefix }}. Update NPTv6 rules."
```

Path-monitor entities whose next hop no longer exists (for example after renumbering) are removed automatically when the integration loads.

### GlobalProtect users

A **GlobalProtect &lt;user&gt;** connectivity sensor per user on the pair device: on while the user has a session on the active gateway, with computer, client OS, app version, virtual and public IP and login time as attributes, plus the last logout time and reason. Users are picked up from the gateway's current and previous-user lists, appear automatically the first time they're seen and are kept across restarts. Events fire when a user connects or disconnects:

```yaml
triggers:
  - trigger: event
    event_type: paloalto_firewall_globalprotect_connect
actions:
  - action: notify.mobile_app_phone
    data:
      message: "{{ trigger.event.data.username }} connected from {{ trigger.event.data.public_ip }} ({{ trigger.event.data.computer }})"
```

(`paloalto_firewall_globalprotect_disconnect` has the same fields.) Connection state follows the poll interval, so very short sessions between polls can be missed.

### Repairs

Problems that need a person show up under **Settings → Repairs** and clear themselves once fixed:

- a certificate that expires within 30 days (warning) or has expired (error)
- a licence that expires within 30 days or has expired (the warranty isn't counted)
- an HA pair whose running config stays out of sync for 15 minutes (a commit's brief resync is ignored)

Available updates aren't repeated as repairs; they're already in Settings → Updates.

### Certificates

- **Certificate &lt;name&gt;** — a timestamp sensor per certificate the firewall holds a private key for (portal/gateway, management, decryption or CA certs), with subject, issuer, SANs, `days_left` and chain length.
- **Certificate expiring** — problem sensor, on when any certificate in the configuration (including imported CA and intermediate certs) expires within 30 days; `expiring` and `expired` attributes list them.

Read with `show sslmgr-store config-ca-certificate` and `config-certificate-info`, so the read-only operational API role is enough.

## Back up the configuration

`paloalto_firewall.backup_config` saves each firewall's running configuration (`show config running`) as XML in the `paloalto_firewall_backups` folder of your Home Assistant config, named `<hostname>_<date>-<time>.xml`. Home Assistant's own backups then include it. A firewall whose config hasn't changed since its newest backup isn't saved again, and `keep` (default 30) caps how many are kept per firewall. Run it from a nightly automation:

```yaml
triggers:
  - trigger: time
    at: "03:15:00"
actions:
  - action: paloalto_firewall.backup_config
```

The file is a normal PAN-OS config: import it under Device → Setup → Operations → *Import named configuration snapshot*. Secrets in it are encrypted with the firewall's master key, but treat the files as sensitive.

## Route lookup

`paloalto_firewall.route_lookup` returns the route, egress interface, next hop, zone and vsys a destination uses. Searches one `logical_router`, the logical router of a `source` IP's interface, or all of them:

```yaml
action: paloalto_firewall.route_lookup
data:
  destination: 1.1.1.1
  source: 10.2.4.159        # optional
response_variable: result
```

## Look up a host (ARP / DHCP)

The `paloalto_firewall.lookup` action searches the **active** firewall's ARP table and DHCP leases (falling back to the peer if the active unit can't be reached) and returns the matches. Run it from **Developer Tools → Actions**, or from a script:

```yaml
action: paloalto_firewall.lookup
data:
  query: "00:11:22"   # optional; empty returns everything
  source: all         # all | arp | dhcp
response_variable: result
```

`query` matches a full IP exactly, a MAC address in full or in part with any separator (`00:11:22`, `00-11-22`, `0011.22aa`), or any part of an IP, hostname or interface name. ARP entries and DHCP leases for the same IP and MAC are merged into one result:

```yaml
firewall: fw1
query: "00:11:22"
count: 1
matches:
  - ip: 10.2.3.45
    mac: 00:11:22:aa:bb:cc
    sources: [dhcp, arp]
    hostname: shelly-plug-kitchen
    interface: ethernet1/2.30
    lease_state: committed
    lease_time: Fri Oct 8 02:14:00 2026   # when the lease was granted/renewed (firewall local time)
    lease_duration: 86400                 # seconds
    arp_status: complete
    arp_ttl: 1200
```

If one table can't be read (for example, no DHCP server is configured), the other is still returned and the problem is listed under `errors`.

## Session lookup

`paloalto_firewall.session_lookup` lists live sessions on the active firewall, like `show session all filter …`. Filter on any of `source`, `destination`, `source_port`, `destination_port`, `protocol`, `application`, `from_zone`, `to_zone`, `rule`, `source_user` and `state`; `limit` caps how many come back (default 50) while `total` always reports how many matched. Each session includes zones, ingress/egress interfaces, rule, app, bytes and any source/destination NAT. Pass `session_id` instead to get one session in full detail (`show session id`).

```yaml
action: paloalto_firewall.session_lookup
data:
  source: 10.2.4.86
  destination_port: 443
response_variable: sessions
```

## Test security and NAT policy (hop by hop)

`paloalto_firewall.test_security_policy` (CLI `test security-policy-match`) and `paloalto_firewall.test_nat_policy` (CLI `test nat-policy-match`) work out which rules a flow hits.

Leave vsys and zones empty, and the flow is **traced through every vsys it crosses**:

1. It enters on the interface whose subnet holds the source (or the interface the source is routed via).
2. A FIB lookup in that interface's logical router picks the egress interface. Those two interfaces give the hop's vsys, from-zone and to-zone.
3. If the next hop is one of the firewall's own addresses (vsys linked by a cable or loop), the flow re-enters there, and the trace continues in that vsys.

The policy test runs at each hop:

```yaml
action: paloalto_firewall.test_security_policy
data:
  source: 10.2.4.159
  destination: 1.1.1.1
  destination_port: 443
  application: ssl       # recommended: without it the first rule that *could* match is reported
response_variable: result
```

```yaml
mode: traced
verdict: allow            # first hop that doesn't allow decides; otherwise allow
rule: Internet
decided_at_hop: null
hops:
  - hop: 1
    vsys: vsys1
    logical_router: core-vr
    ingress_interface: ae1.104
    from_zone: IoT
    egress_interface: ae11.101
    to_zone: Spectrum
    rule: URL Filtering
    action: allow
    rules: [...]
  - hop: 2
    vsys: vsys3
    logical_router: spectrum-vr
    ingress_interface: ae12.101
    from_zone: Core
    egress_interface: ethernet1/13
    to_zone: Internet
    rule: Internet
    action: allow
    rules: [...]
```

If you set any of `vsys`, `from_zone` or `to_zone`, that **single hop** is tested, and anything you left out is filled in from the matching traced hop. NAT tests also pass each hop's egress interface as `to-interface`, and list the NAT rules hit under `translations`, with what each rule translates to (from the vsys's running NAT policy).

## Icons

The Palo Alto Networks icon and logo ship in `custom_components/paloalto_firewall/brand/` (Home Assistant 2026.3+ serves them locally). They're used for the integration tile, the PAN-OS and Apps & threats update entities, and the Apps & threats version sensor.

## Options

*Configure* on the integration: status poll interval (default 60 s, min 15 s) and update/licence check interval (default 6 h).

### Polling tiers

| Every poll (scan interval) | Every 5 minutes | Every 6 hours (configurable) |
|---|---|---|
| system/HA/session/resources, GlobalProtect current users, interfaces, FIB/egress, path monitors, interface counters | jobs, uncommitted changes, delegated prefixes + NPTv6 check, BGP peers, GlobalProtect previous users, certificates | software/content/GlobalProtect client checks, licences |

The 5-minute tier also refreshes immediately after a failover, so prefix and BGP events can lag a real change by up to 5 minutes.

### Debug diagnostics

With debug logging enabled for the integration, *Download diagnostics* also includes the raw XML of the network commands it parses (interfaces, FIB, path monitors, jobs, prefixes, running NAT per vsys, BGP per logical router) plus global drop counters. Addresses aren't redacted in that section, so review it before sharing.

## Commands used

`show system info`, `show high-availability state`, `show session info`, `show system resources`, `show running resource-monitor minute last 1`, `show system environmentals`, `show global-protect-gateway current-user` and `previous-user`, `show sslmgr-store config-ca-certificate` and `config-certificate-info`, `show admins`, `show vpn ipsec-sa`, `request system software check`, `request content upgrade check`, `request global-protect-client software check`, `request license info`. Only when you run the backup action: `show config running`.

Commands that a model doesn't support (environmentals on VM-series, GlobalProtect when unlicensed) are skipped quietly and their entities stay unknown or aren't created.

## Tests

```
pip install -r requirements_test.txt
pytest
```

CI runs the tests against Home Assistant 2026.10 (Python 3.14), plus hassfest and HACS validation, on every push and weekly. The tests run against a simulated HA pair (`tests/fakefw.py`) covering the config flow, outage of either unit, clean failover, split-brain detection, re-auth and options.
