# Palo Alto Networks Firewall for Home Assistant

Monitors PAN-OS firewalls over the XML API — standalone, or an **active/passive HA pair** treated as one unit.

Built as a modern replacement for [FoUStep/ha-pan-customintegration](https://github.com/FoUStep/ha-pan-customintegration) (itself a fork of Skalavala's 2018 sensor). It reuses the same operational commands but adds a UI config flow, async polling, devices, HA-pair awareness and update/licence tracking.

## Install

1. Copy `custom_components/paloalto_firewall` into `/config/custom_components/` (or add this repo to HACS as a custom integration repository).
2. Restart Home Assistant.
3. **Settings → Devices & services → Add integration → Palo Alto Networks Firewall.**

Enter the **management** address of each firewall (not a floating/dataplane IP). For an HA pair enter both; for a standalone box leave the second field empty.

## Firewall prep: a read-only API account

On the firewall (it syncs to the peer with HA config sync):

1. **Device → Admin Roles → Add** — e.g. `ha-monitor`
   - *Web UI*: disable everything
   - *XML API*: enable **Operational Requests** only
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

`request system software check` and `request content upgrade check` run every 6 hours per unit (configurable) and in the background at startup. The **PAN-OS** update entity tracks the newest release **in your installed feature train** (e.g. 11.1.x) — moving to a new train is a planning decision, so the newest release overall is shown in the `newest_release_any_train` attribute instead. Update entities are read-only; nothing is downloaded or installed.

## Network: logical routers, WAN egress, interfaces, jobs

These are read from the **active** firewall and live under the HA pair device (or the firewall's own device when standalone). Requires PAN-OS with the Advanced Routing Engine (logical routers).

**One child device per logical router**, each with:

| Entity | Notes |
|---|---|
| Internet egress / IPv6 internet egress | the zone this logical router sends internet traffic to (FIB lookup of 1.1.1.1 / 2606:4700:4700::1111); interface, next hop, vsys, matching route and ECMP paths as attributes |
| Path monitor *interface* via *next hop* | one connectivity sensor per monitored next hop; monitored routes and probe results as attributes |
| FIB routes | IPv4/IPv6 route counts (diagnostic) |

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

**On the pair device:**

- Interface **link**, **link speed**, and **in/out throughput** for the interfaces chosen in *Configure* (by default, the interfaces used by path monitors and internet routes)
- **Uncommitted changes**, **Running jobs**, and **Last commit** (from the firewall's job history; unknown once it ages out)

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

If you set any of `vsys`, `from_zone` or `to_zone`, that **single hop** is tested, and anything you left out is filled in from the matching traced hop. NAT tests also pass each hop's egress interface as `to-interface`, and list the NAT rules hit under `translations`.

## Icons

The Palo Alto Networks icon and logo ship in `custom_components/paloalto_firewall/brand/` (Home Assistant 2026.3+ serves them locally). They're used for the integration tile, the PAN-OS and Apps & threats update entities, and the Apps & threats version sensor.

## Options

*Configure* on the integration: status poll interval (default 60 s, min 15 s) and update/licence check interval (default 6 h).

## Commands used

`show system info`, `show high-availability state`, `show session info`, `show system resources`, `show running resource-monitor minute last 1`, `show system environmentals`, `show global-protect-gateway current-user`, `show admins`, `show vpn ipsec-sa`, `request system software check`, `request content upgrade check`, `request license info`.

Commands that a model doesn't support (environmentals on VM-series, GlobalProtect when unlicensed) are skipped quietly and their entities stay unknown or aren't created.

## Tests

```
pip install pytest-homeassistant-custom-component
pytest
```

The tests run against a simulated HA pair (`tests/fakefw.py`) covering the config flow, outage of either unit, clean failover, split-brain detection, re-auth and options.
