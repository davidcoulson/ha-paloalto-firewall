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
