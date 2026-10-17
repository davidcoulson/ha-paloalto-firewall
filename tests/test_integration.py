import asyncio
from datetime import timedelta

import pytest
from homeassistant import config_entries
from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_capture_events,
    async_fire_time_changed,
)

from custom_components.paloalto_firewall import const
from custom_components.paloalto_firewall.const import (
    CONF_PRIMARY_HOST,
    CONF_SECONDARY_HOST,
    CONF_UNITS,
    DOMAIN,
    EVENT_FAILOVER,
)
from custom_components.paloalto_firewall.devices import get_device

from .fakefw import FakePair

USER_INPUT = {
    CONF_NAME: "Edge",
    CONF_PRIMARY_HOST: "fw1.lan",
    CONF_SECONDARY_HOST: "fw2.lan",
    CONF_USERNAME: "ha-monitor",
    CONF_PASSWORD: "pw",
    CONF_VERIFY_SSL: False,
}


async def _tick(hass: HomeAssistant, freezer, seconds: int) -> None:
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done(wait_background_tasks=True)


@pytest.fixture
def fake(monkeypatch):
    f = FakePair()
    f.patch(monkeypatch)
    return f


async def _setup(hass: HomeAssistant, fake, **kwargs) -> MockConfigEntry:
    entry = MockConfigEntry(
        **kwargs,
        domain=DOMAIN,
        title="Edge",
        unique_id="0123456789001_0123456789002",
        data={
            CONF_NAME: "Edge",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_VERIFY_SSL: False,
            CONF_UNITS: [
                {"host": h, "serial": u["serial"], "hostname": u["hostname"], "model": "PA-440"}
                for h, u in fake.units.items()
            ],
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    return entry


async def test_config_flow_pair(hass: HomeAssistant, fake) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert [u["hostname"] for u in result["data"][CONF_UNITS]] == ["fw1", "fw2"]
    assert result["result"].unique_id == "0123456789001_0123456789002"


async def test_config_flow_errors(hass: HomeAssistant, fake) -> None:
    fake.units["fw2.lan"]["up"] = False
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["errors"] == {"base": "cannot_connect"}
    assert result["description_placeholders"]["host"] == "fw2.lan"
    fake.units["fw2.lan"]["up"] = True
    fake.bad_password = True
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["errors"] == {"base": "invalid_auth"}
    fake.bad_password = False
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**USER_INPUT, CONF_SECONDARY_HOST: "fw1.lan"}
    )
    assert result["errors"] == {"base": "same_device"}


async def test_standalone_flow(hass: HomeAssistant, fake) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    data = {k: v for k, v in USER_INPUT.items() if k != CONF_SECONDARY_HOST}
    result = await hass.config_entries.flow.async_configure(result["flow_id"], data)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert len(result["data"][CONF_UNITS]) == 1


async def test_entities_and_failover(hass: HomeAssistant, fake) -> None:
    await _setup(hass, fake)
    st = hass.states
    assert st.get("sensor.fw1_ha_state").state == "active"
    assert st.get("sensor.fw2_ha_state").state == "passive"
    assert st.get("sensor.edge_ha_pair_active_firewall").state == "fw1"
    assert st.get("binary_sensor.edge_ha_pair_ha_pair_problem").state == "off"
    assert st.get("sensor.fw1_active_sessions").state == "1200"
    assert float(st.get("sensor.fw1_throughput").state) == 125.0  # Mbit/s
    assert st.get("sensor.fw1_management_memory").state == "60.0"
    assert st.get("sensor.fw1_dataplane_cpu").state == "20.0"
    assert st.get("sensor.fw1_temperature").state == "52.4"
    assert st.get("sensor.edge_ha_pair_active_sessions").attributes["source"] == "fw1"

    # Update checks run in the background after setup.
    await hass.async_block_till_done(wait_background_tasks=True)
    upd = st.get("update.fw1_pan_os")
    assert upd.state == "on"
    assert upd.attributes["installed_version"] == "11.1.4-h7"
    assert upd.attributes["latest_version"] == "11.1.6-h3"
    assert upd.attributes["newest_release_any_train"] == "11.2.5"
    assert st.get("update.fw1_apps_threats_content").attributes["latest_version"] == "8901-9160"
    assert st.get("sensor.fw1_next_licence_expiry").attributes["feature"] == "Threat Prevention"

    # Failover: fw1 goes down, fw2 becomes active.
    events = async_capture_events(hass, EVENT_FAILOVER)
    fake.units["fw1.lan"]["up"] = False
    fake.units["fw2.lan"]["state"] = "active"
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=61))
    await hass.async_block_till_done(wait_background_tasks=True)

    assert st.get("sensor.fw1_ha_state").state == "unavailable"
    assert st.get("sensor.edge_ha_pair_active_firewall").state == "fw2"
    assert st.get("sensor.edge_ha_pair_active_sessions").attributes["source"] == "fw2"
    problem = st.get("binary_sensor.edge_ha_pair_ha_pair_problem")
    assert problem.state == "on"
    assert "fw1 unreachable" in problem.attributes["problems"]
    assert len(events) == 1
    assert events[0].data["previous_active"] == "fw1" and events[0].data["new_active"] == "fw2"
    assert st.get("sensor.edge_ha_pair_last_failover").state not in ("unknown", "unavailable")


async def test_setup_with_one_unit_down(hass: HomeAssistant, fake) -> None:
    fake.units["fw2.lan"]["up"] = False
    fake.units["fw1.lan"]["state"] = "active"
    entry = await _setup(hass, fake)
    assert entry.state is config_entries.ConfigEntryState.LOADED
    assert hass.states.get("sensor.fw2_ha_state").state == "unavailable"
    assert hass.states.get("sensor.edge_ha_pair_active_firewall").state == "fw1"
    # Recovers on its own.
    fake.units["fw2.lan"]["up"] = True
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=61))
    await hass.async_block_till_done(wait_background_tasks=True)
    assert hass.states.get("sensor.fw2_ha_state").state == "passive"


async def test_auth_failure_starts_reauth(hass: HomeAssistant, fake) -> None:
    fake.bad_password = True
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_NAME: "Edge",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_VERIFY_SSL: False,
            CONF_UNITS: [{"host": "fw1.lan", "serial": "0123456789001", "hostname": "fw1", "model": None}],
        },
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.state is config_entries.ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert any(f["context"]["source"] == "reauth" for f in flows)
    fake.bad_password = False
    flow = next(f for f in flows if f["context"]["source"] == "reauth")
    result = await hass.config_entries.flow.async_configure(
        flow["flow_id"], {CONF_USERNAME: "u", CONF_PASSWORD: "new"}
    )
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_PASSWORD] == "new"


async def test_options_and_unload(hass: HomeAssistant, fake) -> None:
    entry = await _setup(hass, fake)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"scan_interval": 30, "update_check_hours": 12}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.state is config_entries.ConfigEntryState.LOADED
    assert entry.runtime_data.units[0].coordinator.update_interval == timedelta(seconds=30)
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_clean_failover_and_split_brain(hass: HomeAssistant, fake) -> None:
    await _setup(hass, fake)
    events = async_capture_events(hass, EVENT_FAILOVER)
    fake.units["fw1.lan"]["state"] = "passive"
    fake.units["fw2.lan"]["state"] = "active"
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=61))
    await hass.async_block_till_done(wait_background_tasks=True)
    assert hass.states.get("sensor.edge_ha_pair_active_firewall").state == "fw2"
    assert hass.states.get("binary_sensor.edge_ha_pair_ha_pair_problem").state == "off"
    assert len(events) == 1

    fake.units["fw1.lan"]["state"] = "active"
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=130))
    await hass.async_block_till_done(wait_background_tasks=True)
    problem = hass.states.get("binary_sensor.edge_ha_pair_ha_pair_problem")
    assert problem.state == "on"
    assert "both firewalls active (split brain)" in problem.attributes["problems"]


async def test_lookup_action(hass: HomeAssistant, fake) -> None:
    entry = await _setup(hass, fake)
    # Make fw2 the active unit; the lookup must go to it.
    fake.units["fw1.lan"]["state"] = "passive"
    fake.units["fw2.lan"]["state"] = "active"
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=61))
    await hass.async_block_till_done(wait_background_tasks=True)
    fake.calls.clear()

    result = await hass.services.async_call(
        DOMAIN, "lookup", {"query": "00:11:22"}, blocking=True, return_response=True
    )
    assert result["firewall"] == "fw2"
    assert result["count"] == 2
    assert result["matches"][0]["hostname"] == "shelly-plug-kitchen"
    assert {h for h, _ in fake.calls} == {"fw2.lan"}

    result = await hass.services.async_call(
        DOMAIN,
        "lookup",
        {"query": "garage", "source": "dhcp", "config_entry_id": entry.entry_id},
        blocking=True,
        return_response=True,
    )
    assert [m["ip"] for m in result["matches"]] == ["10.2.3.99"]
    assert result["matches"][0]["sources"] == ["dhcp"]

    # Active unit unreachable: falls back to the peer.
    fake.units["fw2.lan"]["up"] = False
    result = await hass.services.async_call(
        DOMAIN, "lookup", {"query": "10.2.4.1"}, blocking=True, return_response=True
    )
    assert result["firewall"] == "fw1" and result["count"] == 1

    fake.units["fw1.lan"]["up"] = False
    from homeassistant.exceptions import HomeAssistantError

    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(DOMAIN, "lookup", {"query": "x"}, blocking=True, return_response=True)


async def test_lookup_requires_loaded_entry(hass: HomeAssistant, fake) -> None:
    from homeassistant.exceptions import ServiceValidationError
    from homeassistant.setup import async_setup_component

    assert await async_setup_component(hass, DOMAIN, {})
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "lookup", {"query": "x"}, blocking=True, return_response=True)


async def test_security_policy_action(hass: HomeAssistant, fake) -> None:
    from homeassistant.exceptions import HomeAssistantError

    await _setup(hass, fake)
    fake.calls.clear()
    result = await hass.services.async_call(
        DOMAIN,
        "test_security_policy",
        {
            "source": "10.2.4.86",
            "destination": "1.1.1.1",
            "destination_port": 443,
            "protocol": "tcp",
            "from_zone": "iot",
            "to_zone": "untrust",
        },
        blocking=True,
        return_response=True,
    )
    assert result["firewall"] == "fw1"  # the active unit
    assert result["mode"] == "explicit"
    assert result["hops"][0]["matched"] is True
    assert result["rule"] == "IoT-to-Internet" and result["verdict"] == "allow"
    assert result["criteria"]["protocol"] == 6
    assert {h for h, _ in fake.calls} == {"fw1.lan"}

    result = await hass.services.async_call(
        DOMAIN,
        "test_security_policy",
        {"source": "10.2.4.86", "destination": "9.9.9.9"},
        blocking=True,
        return_response=True,
    )
    assert result["hops"][-1]["matched"] is False and "note" in result

    with pytest.raises(HomeAssistantError, match="bogus"):
        await hass.services.async_call(
            DOMAIN,
            "test_security_policy",
            {"source": "10.2.4.86", "destination": "1.1.1.1", "from_zone": "bogus"},
            blocking=True,
            return_response=True,
        )


async def test_network_entities_and_egress_change(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import device_registry as dr

    entry = await _setup(hass, fake)
    st = hass.states.get
    network = entry.runtime_data.network
    assert network.selected_interfaces(network.data) == ["ae9.100", "ae9.101", "ethernet1/1", "ethernet1/2"]

    assert st("sensor.edge_ha_pair_running_jobs").state == "1"
    assert st("binary_sensor.edge_ha_pair_uncommitted_changes").state == "on"
    assert st("sensor.edge_ha_pair_last_commit").attributes["user"] == "admin"
    assert st("binary_sensor.edge_ha_pair_ethernet1_2_link").state == "on"
    assert st("sensor.edge_ha_pair_ethernet1_1_link_speed").state == "10000"
    assert st("sensor.edge_ha_pair_ethernet1_1_in").state == "unknown"  # needs two samples

    egress = st("sensor.core_vr_internet_egress")
    assert egress.state == "WanB"
    assert egress.attributes["interface"] == "ae9.101" and egress.attributes["vsys"] == "vsys1"
    assert st("sensor.core_vr_ipv6_internet_egress").state == "WanA"
    assert st("sensor.wan_b_vr_internet_egress").state == "Internet"
    pm = st("binary_sensor.wan_b_vr_path_monitor_ethernet1_2_via_203_0_113_1")
    assert pm.state == "on"
    assert st("binary_sensor.core_vr_path_monitor_ae9_101_via_fd00_99_b_1").state == "off"

    reg = dr.async_get(hass)
    lr_dev = get_device(reg, (DOMAIN, f"{entry.entry_id}_lr_core-vr"), entry.entry_id)
    pair_dev = get_device(reg, (DOMAIN, f"{entry.entry_id}_ha_pair"), entry.entry_id)
    assert lr_dev.via_device_id == pair_dev.id

    # Next poll: throughput appears; then WAN B fails and core-vr moves to WAN A.
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=61))
    await hass.async_block_till_done(wait_background_tasks=True)
    assert float(st("sensor.edge_ha_pair_ethernet1_1_in").state) > 0

    events = async_capture_events(hass, "paloalto_firewall_egress_change")
    fake.core_v4_via = "a"
    fake.wan_b_up = False
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=130))
    await hass.async_block_till_done(wait_background_tasks=True)
    assert st("sensor.core_vr_internet_egress").state == "WanA"
    assert st("binary_sensor.wan_b_vr_path_monitor_ethernet1_2_via_203_0_113_1").state == "off"
    assert st("binary_sensor.edge_ha_pair_ethernet1_2_link").state == "off"
    ev = [e.data for e in events if e.data["logical_router"] == "core-vr"]
    assert ev == [
        {
            "entry_id": entry.entry_id,
            "logical_router": "core-vr",
            "family": "ipv4",
            "previous_interface": "ae9.101",
            "previous_zone": "WanB",
            "interface": "ae9.100",
            "zone": "WanA",
            "nexthop": "172.31.0.2",
        }
    ]


async def test_route_lookup_and_inferred_policy_tests(hass: HomeAssistant, fake) -> None:
    from homeassistant.exceptions import ServiceValidationError

    await _setup(hass, fake)

    async def call(service, data):
        return await hass.services.async_call(DOMAIN, service, data, blocking=True, return_response=True)

    r = await call("route_lookup", {"destination": "1.1.1.1"})
    assert [x["logical_router"] for x in r["results"]] == ["core-vr", "wan-a-vr", "wan-b-vr"]
    assert r["results"][0]["paths"][0] == {
        "interface": "ae9.101",
        "nexthop": "172.31.0.6",
        "zone": "WanB",
        "vsys": "vsys1",
        "drop": False,
    }
    r = await call("route_lookup", {"destination": "10.9.99.9", "source": "10.9.20.50"})
    assert r["searched"].startswith("source 10.9.20.50 (ae1.20)")
    assert r["results"] == [
        {
            "logical_router": "core-vr",
            "route": "10.9.0.0/16",
            "paths": [{"interface": None, "nexthop": "drop", "zone": None, "vsys": None, "drop": True}],
        }
    ]
    r = await call("route_lookup", {"destination": "1.1.1.1", "logical_router": "wan-a-vr"})
    assert r["results"][0]["paths"][0]["interface"] == "ethernet1/1"
    with pytest.raises(ServiceValidationError):
        await call("route_lookup", {"destination": "1.1.1.1", "logical_router": "nope"})

    # Traced: IoT (vsys1, core-vr) -> WanB, then re-enters on ae9.201 (vsys3, wan-b-vr) -> Internet.
    fake.vsys_calls.clear()
    r = await call(
        "test_security_policy", {"source": "10.9.20.50", "destination": "1.1.1.1", "destination_port": 443}
    )
    assert r["mode"] == "traced"
    assert [(h["vsys"], h["from_zone"], h["to_zone"], h["egress_interface"]) for h in r["hops"]] == [
        ("vsys1", "IoT", "WanB", "ae9.101"),
        ("vsys3", "Core", "Internet", "ethernet1/2"),
    ]
    assert [h["rule"] for h in r["hops"]] == ["IoT-to-Internet", "IoT-to-Internet"]
    assert r["verdict"] == "allow" and r["decided_at_hop"] is None
    assert [v for _, v in fake.vsys_calls] == ["vsys1", "vsys3"]
    assert "<from>IoT</from><to>WanB</to>" in fake.vsys_calls[0][0]
    assert "<from>Core</from><to>Internet</to>" in fake.vsys_calls[1][0]

    # A deny in the second vsys decides the verdict.
    fake.deny_vsys = "vsys3"
    r = await call("test_security_policy", {"source": "10.9.20.50", "destination": "1.1.1.1"})
    assert r["verdict"] == "deny" and r["rule"] == "Block-WanB-Out" and r["decided_at_hop"] == 2
    fake.deny_vsys = None

    # Local destination: a single hop.
    r = await call("test_security_policy", {"source": "10.9.20.50", "destination": "10.9.1.5"})
    assert [(h["from_zone"], h["to_zone"]) for h in r["hops"]] == [("IoT", "Trusted")]

    # Explicit vsys: one hop, gaps filled from the matching traced hop.
    fake.vsys_calls.clear()
    r = await call(
        "test_security_policy", {"source": "10.9.20.50", "destination": "1.1.1.1", "vsys": "vsys3"}
    )
    assert r["mode"] == "explicit" and len(r["hops"]) == 1
    assert (r["hops"][0]["from_zone"], r["hops"][0]["to_zone"]) == ("Core", "Internet")
    assert fake.vsys_calls == [(fake.vsys_calls[0][0], "vsys3")]

    # Explicit zones win.
    r = await call(
        "test_security_policy",
        {
            "source": "10.9.20.50",
            "destination": "1.1.1.1",
            "from_zone": "Trusted",
            "to_zone": "WanA",
            "vsys": "vsys1",
        },
    )
    assert "<from>Trusted</from><to>WanA</to>" in fake.vsys_calls[-1][0]

    # NAT: tested at every hop with that hop's egress interface.
    fake.vsys_calls.clear()
    r = await call(
        "test_nat_policy", {"source": "10.9.20.50", "destination": "1.1.1.1", "destination_port": 443}
    )
    assert [h["egress_interface"] for h in r["hops"]] == ["ae9.101", "ethernet1/2"]
    assert "<to-interface>ethernet1/2</to-interface>" in fake.vsys_calls[1][0]
    assert [(t["hop"], t["vsys"], t["rule"]) for t in r["translations"]] == [
        (1, "vsys1", "IoT-Hide-NAT"),
        (2, "vsys3", "IoT-Hide-NAT"),
    ]
    # Hop 2's rule exists in vsys3's running NAT, so its translation is reported.
    assert r["translations"][1]["translate_to"].startswith("src: ethernet1/2 203.0.113.10")
    assert r["hops"][1]["translation"]["nat_type"] == "ipv4"
    assert r["translations"][0]["translate_to"] is None  # not in vsys1's running NAT


async def test_standalone_network_entities(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import device_registry as dr

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_NAME: "Edge",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_VERIFY_SSL: False,
            CONF_UNITS: [{"host": "fw1.lan", "serial": "0123456789001", "hostname": "fw1", "model": None}],
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert hass.states.get("sensor.fw1_running_jobs").state == "1"
    assert hass.states.get("sensor.core_vr_internet_egress").state == "WanB"
    reg = dr.async_get(hass)
    lr_dev = get_device(reg, (DOMAIN, f"{entry.entry_id}_lr_core-vr"), entry.entry_id)
    fw_dev = get_device(reg, (DOMAIN, "0123456789001"), entry.entry_id)
    assert lr_dev.via_device_id == fw_dev.id


async def test_options_interface_selection(hass: HomeAssistant, fake) -> None:
    entry = await _setup(hass, fake)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    schema_keys = [str(k) for k in result["data_schema"].schema]
    assert "interfaces" in schema_keys
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"scan_interval": 60, "update_check_hours": 6, "auto_interfaces": False, "interfaces": ["ae1.20"]},
    )
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.options["interfaces"] == ["ae1.20"]
    assert hass.states.get("sensor.edge_ha_pair_ae1_20_in") is not None
    assert hass.states.get("binary_sensor.edge_ha_pair_ae1_20_link").state == "on"
    from homeassistant.helpers import entity_registry as er

    assert er.async_get(hass).async_get("sensor.edge_ha_pair_ethernet1_1_in") is None


async def test_prefix_pools_and_npt_mismatch(hass: HomeAssistant, fake, freezer) -> None:
    entry = await _setup(hass, fake)
    st = hass.states.get
    a = st("sensor.edge_ha_pair_wan_a_delegated_prefix")
    assert a.state == "2001:db8:a00::/56"
    assert a.attributes["interface"] == "ethernet1/1" and a.attributes["vsys"] == "vsys2"
    assert a.attributes["inherited"] == {"ae1.20": "2001:db8:a00:20::1"}
    assert st("sensor.edge_ha_pair_wan_b_delegated_prefix").state == "2001:db8:b00::/56"

    bad = st("binary_sensor.edge_ha_pair_wan_a_nptv6_prefix_mismatch")
    assert bad.state == "on"
    assert bad.attributes["problems"] == [
        "NPT: outbound uses 2001:db8:aaa:f0::/60, outside delegated 2001:db8:a00::/56",
    ]
    assert st("binary_sensor.edge_ha_pair_wan_b_nptv6_prefix_mismatch").state == "off"

    # ISP hands out a new prefix: event fires and the mismatch sensor flips on.
    events = async_capture_events(hass, "paloalto_firewall_prefix_change")
    fake.wan_b_prefix = "2001:db8:c00::/56"
    await _tick(hass, freezer, 61)  # fast poll only: prefixes are slow-tier
    assert events == []
    assert st("sensor.edge_ha_pair_wan_b_delegated_prefix").state == "2001:db8:b00::/56"
    await _tick(hass, freezer, 240)
    assert [e.data for e in events] == [
        {
            "entry_id": entry.entry_id,
            "pool": "wan-b",
            "interface": "ethernet1/2",
            "previous_prefix": "2001:db8:b00::/56",
            "prefix": "2001:db8:c00::/56",
        }
    ]
    assert st("binary_sensor.edge_ha_pair_wan_b_nptv6_prefix_mismatch").state == "on"


async def test_stale_path_monitor_entities_removed(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import entity_registry as er

    entry = await _setup(hass, fake)
    reg = er.async_get(hass)
    stale = reg.async_get_or_create(
        "binary_sensor",
        DOMAIN,
        f"{entry.entry_id}_pm_core-vr_ae9_100_fd00_99_old__1",
        config_entry=entry,
    )
    keep = "binary_sensor.wan_b_vr_path_monitor_ethernet1_2_via_203_0_113_1"
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert reg.async_get(stale.entity_id) is None
    assert reg.async_get(keep) is not None


async def test_bgp_peers(hass: HomeAssistant, fake, freezer) -> None:
    from homeassistant.helpers import entity_registry as er

    entry = await _setup(hass, fake)
    st = hass.states.get
    est = st("sensor.core_vr_bgp_peers_established")
    assert est.state == "2" and est.attributes["total"] == 2 and est.attributes["down"] == []
    assert est.attributes["router_id"] == "172.31.255.1"
    dns = st("binary_sensor.core_vr_bgp_dns_anycast_0")
    assert dns.state == "on"
    assert dns.attributes["peer_ip"] == "10.9.7.10" and dns.attributes["remote_as"] == 65001
    assert dns.attributes["prefixes"] == {"ipv4Unicast": {"accepted": 1, "sent": 2}}
    assert st("binary_sensor.wan_a_vr_bgp_core_vr").state == "on"
    assert st("sensor.wan_b_vr_bgp_peers_established") is None  # BGP disabled there

    events = async_capture_events(hass, "paloalto_firewall_bgp_peer_change")
    fake.dns_bgp_up = False
    await _tick(hass, freezer, 301)
    assert st("binary_sensor.core_vr_bgp_dns_anycast_0").state == "off"
    assert st("sensor.core_vr_bgp_peers_established").state == "1"
    assert st("sensor.core_vr_bgp_peers_established").attributes["down"] == ["dns-anycast-0"]
    assert [(e.data["peer"], e.data["established"], e.data["state"]) for e in events] == [
        ("dns-anycast-0", False, "Active")
    ]

    # A peer that disappears from the config is cleaned up on reload.
    reg = er.async_get(hass)
    stale = reg.async_get_or_create(
        "binary_sensor", DOMAIN, f"{entry.entry_id}_bgp_core_vr_old_peer", config_entry=entry
    )
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert reg.async_get(stale.entity_id) is None
    assert reg.async_get("binary_sensor.core_vr_bgp_dns_anycast_0") is not None


async def test_slow_tier_polling(hass: HomeAssistant, fake, freezer) -> None:
    from custom_components.paloalto_firewall.const import CMD_BGP_SUMMARY, CMD_JOBS

    await _setup(hass, fake)

    def count(cmd):
        return sum(1 for _, c in fake.calls if c == cmd)

    jobs, bgp, ifaces = count(CMD_JOBS), count(CMD_BGP_SUMMARY), fake.counter_calls
    assert jobs == 1 and bgp == 1
    await _tick(hass, freezer, 61)
    assert count(CMD_JOBS) == 1 and count(CMD_BGP_SUMMARY) == 1
    assert fake.counter_calls > ifaces  # fast tier still polled
    assert hass.states.get("sensor.core_vr_bgp_peers_established").state == "2"  # cached
    await _tick(hass, freezer, 240)
    assert count(CMD_JOBS) == 2 and count(CMD_BGP_SUMMARY) == 2


async def test_diagnostics_raw_samples_only_at_debug(hass: HomeAssistant, fake) -> None:
    import logging

    from custom_components.paloalto_firewall.diagnostics import (
        async_get_config_entry_diagnostics,
    )

    entry = await _setup(hass, fake)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert diag.get("raw_command_samples") is None
    assert diag["entry"]["data"]["password"] == "**REDACTED**"

    logger = logging.getLogger("custom_components.paloalto_firewall")
    old = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        diag = await async_get_config_entry_diagnostics(hass, entry)
    finally:
        logger.setLevel(old)
    raw = diag["raw_command_samples"]
    assert "xml" in raw["interface_all"] and "xml" in raw["fib"]
    assert {"running_nat_vsys2", "running_nat_vsys3", "bgp_peers_core-vr"} <= set(raw)
    assert "error" in raw["drop_counters"]  # not simulated; captured, not raised


async def test_globalprotect_presence(hass: HomeAssistant, fake, freezer) -> None:
    from homeassistant.helpers import entity_registry as er

    entry = await _setup(hass, fake)
    st = hass.states.get
    alice = st("binary_sensor.edge_ha_pair_globalprotect_alice")
    assert alice.state == "on"
    assert alice.attributes["computer"] == "alice-laptop"
    assert alice.attributes["public_ip"] == "198.51.100.7"
    assert alice.attributes["virtual_ip"] == "10.9.0.2"
    assert alice.attributes["last_logout_reason"] == "user session expired"
    carol = st("binary_sensor.edge_ha_pair_globalprotect_carol")  # previous users only
    assert carol.state == "off"
    assert carol.attributes["last_logout"] == "2026-09-21T15:13:20+00:00"  # newest of two

    events = async_capture_events(hass, "paloalto_firewall_globalprotect_disconnect")
    connects = async_capture_events(hass, "paloalto_firewall_globalprotect_connect")
    fake.gp_online = {"alice", "dave"}
    await _tick(hass, freezer, 61)
    await _tick(hass, freezer, 61)  # network poll reads the unit poll's latest users
    assert st("binary_sensor.edge_ha_pair_globalprotect_bob").state == "off"
    assert [e.data["username"] for e in events] == ["bob"]
    assert events[0].data["public_ip"] == "203.0.113.50"
    # A brand-new user gets an entity on the fly (no connect event: nothing to compare).
    assert st("binary_sensor.edge_ha_pair_globalprotect_dave").state == "on"
    assert connects == []

    # Users seen before survive a reload even if the firewall forgot them.
    fake.gp_online = set()
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert st("binary_sensor.edge_ha_pair_globalprotect_dave").state == "off"
    reg = er.async_get(hass)
    assert reg.async_get("binary_sensor.edge_ha_pair_globalprotect_dave") is not None


async def test_certificates(hass: HomeAssistant, fake) -> None:
    await _setup(hass, fake)
    st = hass.states.get
    leaf = st("sensor.edge_ha_pair_certificate_fw_example_net")
    assert leaf.attributes["device_class"] == "timestamp"
    assert leaf.attributes["days_left"] in (9, 10)
    assert leaf.attributes["issuer"] == "E8"
    assert leaf.attributes["san"] == ["fw.example.net", "gp.example.net"]
    assert leaf.attributes["chain_length"] == 2
    assert st("sensor.edge_ha_pair_certificate_homeca").attributes["self_signed"] is True

    warn = st("binary_sensor.edge_ha_pair_certificate_expiring")
    assert warn.state == "on"
    assert [c["name"] for c in warn.attributes["expiring"]] == ["fw.example.net"]
    assert [c["name"] for c in warn.attributes["expired"]] == ["old-self-signed"]


async def test_gp_client_update_and_check_action(hass: HomeAssistant, fake) -> None:
    from custom_components.paloalto_firewall.const import CMD_GP_CLIENT_CHECK

    await _setup(hass, fake)
    gp = hass.states.get("update.fw1_globalprotect_client")
    assert gp.state == "on"
    assert gp.attributes["installed_version"] == "6.3.3-c1046"
    assert gp.attributes["latest_version"] == "6.3.3-c1199"
    assert gp.attributes["newest_release_any_train"] == "6.4.0"

    before = sum(1 for _, c in fake.calls if c == CMD_GP_CLIENT_CHECK)
    resp = await hass.services.async_call(
        DOMAIN, "check_for_updates", {}, blocking=True, return_response=True
    )
    assert sum(1 for _, c in fake.calls if c == CMD_GP_CLIENT_CHECK) == before + 2
    fw1 = resp["firewalls"]["fw1"]
    assert fw1["ok"] is True
    assert fw1["panos_newest_in_train"] == "11.1.6-h3"
    assert fw1["gp_client_newest_in_train"] == "6.3.3-c1199"
    # Also callable from an automation without a response.
    await hass.services.async_call(DOMAIN, "check_for_updates", {}, blocking=True)


async def test_session_lookup(hass: HomeAssistant, fake) -> None:
    from homeassistant.exceptions import ServiceValidationError

    await _setup(hass, fake)
    resp = await hass.services.async_call(
        DOMAIN,
        "session_lookup",
        {"source": "10.2.4.86", "destination_port": 443, "protocol": "tcp", "limit": 1},
        blocking=True,
        return_response=True,
    )
    assert resp["firewall"] == "fw1" and resp["total"] == 2
    assert resp["returned"] == 1 and resp["truncated"] is True
    s = resp["sessions"][0]
    assert s["application"] == "ssl" and s["rule"] == "Allow web"
    assert s["nat_source"] == "203.0.113.10:40001" and "nat_destination" not in s
    cmd = next(
        c for _, c in reversed(fake.calls) if c.startswith("<show><session><all>") and "count" not in c
    )
    assert "<source>10.2.4.86</source><destination-port>443</destination-port><protocol>6</protocol>" in cmd

    detail = await hass.services.async_call(
        DOMAIN, "session_lookup", {"session_id": 691086}, blocking=True, return_response=True
    )
    assert detail["session"]["c2s"]["source_zone"] == "Core"
    assert detail["session"]["rule"] == "Allow web"

    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(DOMAIN, "session_lookup", {}, blocking=True, return_response=True)


async def test_permission_denied_command_is_not_reauth(hass: HomeAssistant, fake) -> None:
    from custom_components.paloalto_firewall import const

    fake.fail = {const.CMD_IPSEC_SA: "403", const.CMD_CERTS_DEVICE: "403"}
    entry = await _setup(hass, fake)
    assert entry.state is config_entries.ConfigEntryState.LOADED
    assert not hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert hass.states.get("sensor.fw1_active_sessions").state == "1200"
    # One initial key per unit, plus one retry per forbidden command - no storm.
    assert fake.keygens <= 2 + 2 * len(fake.fail)
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.state is config_entries.ConfigEntryState.LOADED


async def test_transient_failures_keep_entities_and_stay_quiet(hass: HomeAssistant, fake, freezer) -> None:
    from homeassistant.helpers import entity_registry as er

    from custom_components.paloalto_firewall import const

    entry = await _setup(hass, fake)
    reg = er.async_get(hass)
    kept = [
        "binary_sensor.core_vr_bgp_dns_anycast_0",
        "sensor.core_vr_bgp_peers_established",
        "binary_sensor.wan_b_vr_path_monitor_ethernet1_2_via_203_0_113_1",
        "sensor.edge_ha_pair_certificate_fw_example_net",
        "sensor.edge_ha_pair_ethernet1_1_in",
    ]
    assert all(reg.async_get(e) for e in kept)

    egress = async_capture_events(hass, "paloalto_firewall_egress_change")
    gp_off = async_capture_events(hass, "paloalto_firewall_globalprotect_disconnect")
    bgp = async_capture_events(hass, "paloalto_firewall_bgp_peer_change")
    fake.fail = {
        const.CMD_FIB: "error",
        const.CMD_PATH_MONITOR: "error",
        const.CMD_GP_USERS: "error",
        const.CMD_BGP_SUMMARY: "error",
        const.CMD_CERTS_DEVICE: "error",
    }
    await _tick(hass, freezer, 301)
    assert egress == [] and gp_off == [] and bgp == []
    # Last good routing data is kept rather than showing "no route".
    assert hass.states.get("sensor.core_vr_internet_egress").state not in ("unknown", "unavailable")

    # A reload while those reads fail must not prune their entities.
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert all(reg.async_get(e) for e in kept), [e for e in kept if not reg.async_get(e)]

    fake.fail = {}
    await _tick(hass, freezer, 301)
    assert egress == [] and gp_off == [] and bgp == []


async def test_network_entities_appear_after_late_first_poll(hass: HomeAssistant, fake, freezer) -> None:
    from custom_components.paloalto_firewall import const

    fake.fail = {const.CMD_INTERFACE_ALL: "error"}
    await _setup(hass, fake)
    assert hass.states.get("sensor.core_vr_internet_egress") is None
    fake.fail = {}
    await _tick(hass, freezer, 61)
    assert hass.states.get("sensor.core_vr_internet_egress").state == "WanB"
    assert hass.states.get("binary_sensor.edge_ha_pair_uncommitted_changes") is not None


async def test_options_keep_automatic_interfaces(hass: HomeAssistant, fake) -> None:
    entry = await _setup(hass, fake)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    defaults = {str(k): k.default() for k in result["data_schema"].schema if "auto" in str(k)}
    assert defaults == {"auto_interfaces": True}
    network = entry.runtime_data.network
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            "scan_interval": 30,
            "update_check_hours": 6,
            "auto_interfaces": True,
            "interfaces": list(network.selected_interfaces(network.data)),
        },
    )
    await hass.async_block_till_done(wait_background_tasks=True)
    assert "interfaces" not in entry.options
    assert entry.options["scan_interval"] == 30


async def test_options_switch_manual_then_back_to_automatic(hass: HomeAssistant, fake) -> None:
    entry = await _setup(hass, fake)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"scan_interval": 60, "update_check_hours": 6, "auto_interfaces": False, "interfaces": ["ae1.20"]},
    )
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.options["interfaces"] == ["ae1.20"]
    result = await hass.config_entries.options.async_init(entry.entry_id)
    defaults = {str(k): k.default() for k in result["data_schema"].schema if "auto" in str(k)}
    assert defaults == {"auto_interfaces": False}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"scan_interval": 60, "update_check_hours": 6, "auto_interfaces": True, "interfaces": ["ae1.20"]},
    )
    await hass.async_block_till_done(wait_background_tasks=True)
    assert "interfaces" not in entry.options


async def test_subinterface_entities_cleaned_up_exactly(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import entity_registry as er

    entry = await _setup(hass, fake)
    reg = er.async_get(hass)
    stale = reg.async_get_or_create(
        "sensor", DOMAIN, f"{entry.entry_id}_if_ethernet1_1_10_in", config_entry=entry
    )
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert reg.async_get(stale.entity_id) is None
    assert reg.async_get("sensor.edge_ha_pair_ethernet1_1_in") is not None


async def test_late_path_monitors_and_peers_get_entities(hass: HomeAssistant, fake, freezer) -> None:
    from custom_components.paloalto_firewall import const

    pm = "binary_sensor.wan_b_vr_path_monitor_ethernet1_2_via_203_0_113_1"
    peer = "binary_sensor.core_vr_bgp_dns_anycast_0"
    fake.fail = {const.CMD_PATH_MONITOR: "error", const.CMD_BGP_SUMMARY: "error"}
    await _setup(hass, fake)
    assert hass.states.get(pm) is None and hass.states.get(peer) is None
    fake.fail = {}
    await _tick(hass, freezer, 301)
    assert hass.states.get(pm).state == "on"
    assert hass.states.get(peer).state == "on"


async def test_interface_read_hiccup_keeps_network_data(hass: HomeAssistant, fake, freezer) -> None:
    from custom_components.paloalto_firewall import const

    await _setup(hass, fake)
    fake.fail = {const.CMD_INTERFACE_ALL: "error"}
    await _tick(hass, freezer, 61)
    assert hass.states.get("sensor.core_vr_internet_egress").state == "WanB"
    assert hass.states.get("binary_sensor.edge_ha_pair_ethernet1_1_link").state == "on"


async def test_removed_logical_router_cleaned_up(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import device_registry as dr
    from homeassistant.helpers import entity_registry as er

    from custom_components.paloalto_firewall.const import lr_identifier, pair_identifier
    from custom_components.paloalto_firewall.devices import ensure_device

    entry = await _setup(hass, fake)
    devices = dr.async_get(hass)
    reg = er.async_get(hass)
    pair = get_device(devices, (DOMAIN, pair_identifier(entry.entry_id)), entry.entry_id)
    gone = ensure_device(
        hass,
        entry,
        (DOMAIN, lr_identifier(entry.entry_id, "old-vr")),
        pair,
        name="old-vr",
    )
    stale = reg.async_get_or_create(
        "sensor",
        DOMAIN,
        f"{entry.entry_id}_lr_old-vr_egress_ipv4",
        config_entry=entry,
        device_id=gone.id,
    )
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert get_device(devices, (DOMAIN, lr_identifier(entry.entry_id, "old-vr")), entry.entry_id) is None
    assert reg.async_get(stale.entity_id) is None
    assert get_device(devices, (DOMAIN, lr_identifier(entry.entry_id, "core-vr")), entry.entry_id)
    assert reg.async_get("sensor.core_vr_internet_egress") is not None


async def test_failover_does_not_fire_bgp_change(hass: HomeAssistant, fake, freezer) -> None:
    await _setup(hass, fake)
    events = async_capture_events(hass, "paloalto_firewall_bgp_peer_change")
    # The newly active unit reports a different peer state than the old one.
    fake.dns_bgp_up = False
    fake.units["fw1.lan"]["state"] = "passive"
    fake.units["fw2.lan"]["state"] = "active"
    await _tick(hass, freezer, 61)
    await _tick(hass, freezer, 61)
    assert hass.states.get("sensor.edge_ha_pair_active_firewall").state == "fw2"
    assert events == []
    # A real change on the new unit is still reported.
    fake.dns_bgp_up = True
    await _tick(hass, freezer, 301)
    assert [e.data["established"] for e in events] == [True]


async def test_new_entries_verify_tls_by_default(hass: HomeAssistant, fake) -> None:
    from homeassistant.const import CONF_VERIFY_SSL as KEY

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    import voluptuous as vol

    defaults = {
        str(k): k.default()
        for k in result["data_schema"].schema
        if getattr(k, "default", vol.UNDEFINED) is not vol.UNDEFINED
    }
    assert defaults[KEY] is True


async def test_config_flow_explains_tls_failure(hass: HomeAssistant, fake) -> None:
    fake.tls_error = True
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**USER_INPUT, CONF_VERIFY_SSL: True}
    )
    assert result["errors"] == {"base": "invalid_cert"}


async def test_unique_ids_migrate_and_do_not_collide(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import entity_registry as er

    from .fakefw import certs_device_with_vsys_copy

    # Entities registered by earlier versions, keyed by name only.
    reg = er.async_get(hass)
    old_cert = reg.async_get_or_create(
        "sensor", DOMAIN, "legacy_entry_cert_fw_example_net", suggested_object_id="my_fw_cert"
    )
    old_gp = reg.async_get_or_create(
        "binary_sensor", DOMAIN, "legacy_entry_gp_user_alice", suggested_object_id="my_alice"
    )
    fake.certs_device = certs_device_with_vsys_copy()
    fake.gp_online = {"alice", "a.b", "a_b"}
    entry = await _setup(hass, fake, entry_id="legacy_entry")

    # Existing entity ids survive the unique-id change.
    cert = reg.async_get(old_cert.entity_id)
    assert cert is not None and cert.unique_id != "legacy_entry_cert_fw_example_net"
    assert hass.states.get(old_cert.entity_id).attributes["days_left"] in (9, 10)
    gp = reg.async_get(old_gp.entity_id)
    assert gp is not None and gp.unique_id != "legacy_entry_gp_user_alice"
    assert hass.states.get(old_gp.entity_id).state == "on"

    # Same certificate name in another vsys, and usernames that slug the same, all get entities.
    names = {s.name for s in hass.states.async_all()}
    assert "Edge HA pair Certificate fw.example.net (vsys1)" in names
    gp_uids = {
        e.unique_id
        for e in er.async_entries_for_config_entry(reg, entry.entry_id)
        if e.unique_id.startswith("legacy_entry_gp_user_")
    }
    assert len(gp_uids) == 4  # alice, a.b, a_b, and carol from previous users
    assert not any(
        e.unique_id.startswith("legacy_entry_cert_fw_example_net") and e.disabled_by
        for e in er.async_entries_for_config_entry(reg, entry.entry_id)
    )


async def test_backup_config(hass: HomeAssistant, fake, freezer, tmp_path) -> None:
    hass.config.config_dir = str(tmp_path)
    root = tmp_path / "paloalto_firewall_backups"
    # A v0.8.x backup at the top level, and another firewall whose hostname
    # starts with "fw1_" (its files must never be pruned for fw1).
    root.mkdir()
    (root / "fw1_20261001-031500.xml").write_text("<config/>")
    other = root / "9999" / "fw1_dc_20261001T031500000000Z.xml"
    other.parent.mkdir()
    other.write_text("<config/>")
    await _setup(hass, fake)

    first = await hass.services.async_call(DOMAIN, "backup_config", {}, blocking=True, return_response=True)
    assert first["folder"] == str(root)
    assert set(first["firewalls"]) == {"fw1", "fw2"} and first["errors"] == {}
    fw1_dir = root / "0123456789001"
    # The v0.8 file is left alone: its hostname doesn't prove which firewall it's from.
    assert (root / "fw1_20261001-031500.xml").exists()
    fw1_files = sorted(p.name for p in fw1_dir.iterdir())
    assert len(fw1_files) == 1 and fw1_files[0].startswith("fw1_") and fw1_files[0].endswith("Z.xml")
    text = (fw1_dir / fw1_files[0]).read_text()
    assert text.startswith('<?xml version="1.0"?>\n<config version="11.1.0">')
    assert "<hostname>fw1</hostname>" in text
    assert next(p.name for p in (root / "0123456789002").iterdir()).startswith("fw2_")

    # Unchanged config: nothing new is written.
    freezer.tick(timedelta(hours=1))
    again = await hass.services.async_call(DOMAIN, "backup_config", {}, blocking=True, return_response=True)
    assert again["firewalls"]["fw1"]["unchanged"] is True
    assert len(list(fw1_dir.iterdir())) == 1

    # Changed config is saved, and keep prunes only this firewall's older copies.
    fake.units["fw1.lan"]["hostname"] = "fw1-renamed"
    fake.units["fw2.lan"]["up"] = False
    freezer.tick(timedelta(hours=1))
    third = await hass.services.async_call(
        DOMAIN, "backup_config", {"keep": 1}, blocking=True, return_response=True
    )
    assert "fw2" in third["errors"]
    assert third["firewalls"]["fw1"]["unchanged"] is False
    assert sorted(third["firewalls"]["fw1"]["pruned"]) == fw1_files
    assert [p.name for p in fw1_dir.iterdir()] == [third["firewalls"]["fw1"]["file"].split("/")[-1]]
    assert other.exists() and (root / "fw1_20261001-031500.xml").exists()
    assert not list(fw1_dir.glob(".*.tmp"))

    # Overlapping calls don't trip over each other.
    fake.units["fw2.lan"]["up"] = True
    results = await asyncio.gather(
        *(
            hass.services.async_call(DOMAIN, "backup_config", {}, blocking=True, return_response=True)
            for _ in range(3)
        )
    )
    assert all(r["errors"] == {} for r in results)


async def test_repairs(hass: HomeAssistant, fake, freezer) -> None:
    from homeassistant.helpers import issue_registry as ir

    soon = (dt_util.now() + timedelta(days=20)).strftime("%B %d, %Y")
    fake.licenses = fake.licenses.replace("November 05, 2026", soon)
    entry = await _setup(hass, fake)
    reg = ir.async_get(hass)

    def issues() -> dict[str, ir.IssueEntry]:
        return {
            i.translation_key
            + ":"
            + str(
                i.translation_placeholders.get("name")
                or i.translation_placeholders.get("feature")
                or i.translation_placeholders.get("firewall")
            ): i
            for (d, _), i in reg.issues.items()
            if d == DOMAIN
        }

    found = issues()
    assert found["certificate_expiring:fw.example.net"].severity == ir.IssueSeverity.WARNING
    assert found["certificate_expired:old-self-signed"].severity == ir.IssueSeverity.ERROR
    licence = found["licence_expiring:Threat Prevention"]
    assert licence.translation_placeholders["days"] in ("19", "20")
    assert not any(k.startswith("licence_") and "warranty" in k.lower() for k in found)
    assert not any(k.startswith("ha_config_unsynced") for k in found)

    # Updates the read-only account can't install are raised once per version.
    gp = [i for k, i in found.items() if k.startswith("update_gpclient")]
    assert len(gp) == 1 and gp[0].severity == ir.IssueSeverity.WARNING
    placeholders = dict(gp[0].translation_placeholders)
    commands = placeholders.pop("commands")
    # Passive fw2 is listed first.
    assert placeholders == {
        "version": "6.3.3-c1199",
        "names": "fw2 & fw1",
        "firewalls": "fw2 (6.3.3-c1046), fw1 (6.3.3-c1046)",
    }
    assert commands.index("# fw2 (passive)") < commands.index("# fw1 (active)")
    assert commands.count("request global-protect-client software activate version 6.3.3-c1199") == 2
    panos = [i for k, i in found.items() if k.startswith("update_panos")]
    assert [i.translation_placeholders["version"] for i in panos] == ["11.1.6-h3"]
    steps = panos[0].translation_placeholders["commands"]
    fw1 = steps[steps.index("# fw1") :]
    assert "request system software install version 11.1.6-h3" in steps
    assert fw1.index("state suspend") < fw1.index("software install") < fw1.index("state functional")
    assert "suspend" not in steps[: steps.index("# fw1")]
    assert not any(k.startswith("update_content") for k in found)

    # A brief desync (e.g. during a commit) is ignored; a lasting one is raised.
    fake.sync = "synchronization in progress"
    await _tick(hass, freezer, 61)
    assert not any(k.startswith("ha_config_unsynced") for k in issues())
    for _ in range(16):
        await _tick(hass, freezer, 61)
    assert "ha_config_unsynced:fw1" in issues()
    fake.sync = "synchronized"
    await _tick(hass, freezer, 61)
    assert not any(k.startswith("ha_config_unsynced") for k in issues())

    # An ignored repair stays ignored through a reload; removing the entry
    # removes its repairs.
    cert = next(i for k, i in issues().items() if k.startswith("certificate_expired"))
    ir.async_ignore_issue(hass, DOMAIN, cert.issue_id, True)
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert reg.async_get_issue(DOMAIN, cert.issue_id).dismissed_version is not None
    assert await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert issues() == {}


def _threat(seq, minutes_ago=1, severity="high", name="Suspicious DNS Query (12345)"):
    stamp = (dt_util.now() - timedelta(minutes=minutes_ago)).strftime("%Y/%m/%d %H:%M:%S")
    return {
        "seqno": seq,
        "time_generated": stamp,
        "severity": severity,
        "threatid": name,
        "subtype": "spyware",
        "action": "sinkhole",
        "src": "10.9.20.50",
        "dst": "198.51.100.9",
        "app": "dns-base",
        "rule": "iot-out",
        "from": "IoT",
        "to": "Internet",
    }


async def test_threat_alerts(hass: HomeAssistant, fake, freezer) -> None:
    fake.threats["fw1.lan"] = [_threat(1, 60 * 30), _threat(2, 30), _threat(3, 5, "critical")]
    await _setup(hass, fake)
    sensor = hass.states.get("sensor.edge_ha_pair_threats_24h")
    # The 30-hour-old entry is outside the window; existing entries raise no events.
    assert sensor.state == "2"
    assert sensor.attributes["by_severity"] == {"critical": 1, "high": 1}
    assert sensor.attributes["latest"][0]["threat"] == "Suspicious DNS Query (12345)"
    assert sensor.attributes["latest"][0]["source"] == "10.9.20.50"

    events = async_capture_events(hass, "paloalto_firewall_threat")
    fake.threats["fw1.lan"].append(_threat(4, 0, "critical", "Cobalt Strike Beacon (86000)"))
    await _tick(hass, freezer, 61)
    assert [e.data["seqno"] for e in events] == [4]
    assert events[0].data["severity"] == "critical"
    assert events[0].data["firewall"] == "fw1"
    assert hass.states.get("sensor.edge_ha_pair_threats_24h").state == "3"
    await _tick(hass, freezer, 61)
    assert len(events) == 1  # not repeated


async def test_threat_alerts_need_log_permission(hass: HomeAssistant, fake, freezer) -> None:
    from homeassistant.helpers import issue_registry as ir

    fake.fail["log:threat"] = "403"
    entry = await _setup(hass, fake)
    assert entry.state is config_entries.ConfigEntryState.LOADED
    assert hass.states.get("sensor.edge_ha_pair_threats_24h").state == "unavailable"
    # Refused once, without a keygen retry; a repair says what to change.
    assert sum(1 for _, c in fake.calls if c == "log:threat") == 1
    assert fake.keygens == 2  # one per unit at startup, none for the refusal
    issue = ir.async_get(hass).async_get_issue(DOMAIN, f"{entry.entry_id}_permission_threat_log")
    assert issue is not None and issue.translation_key == "threat_log_permission"
    # ...and it isn't asked again on later polls.
    for _ in range(3):
        await _tick(hass, freezer, 61)
    assert sum(1 for _, c in fake.calls if c == "log:threat") == 1

    # After a reload with the permission granted, it works and the repair goes away.
    del fake.fail["log:threat"]
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert hass.states.get("sensor.edge_ha_pair_threats_24h").state == "0"
    assert ir.async_get(hass).async_get_issue(DOMAIN, f"{entry.entry_id}_permission_threat_log") is None


async def test_api_keys_are_reused_across_restarts(hass: HomeAssistant, fake, freezer, hass_storage) -> None:
    entry = await _setup(hass, fake)
    assert fake.keygens == 2
    await _tick(hass, freezer, 5)  # the key store saves after a short delay
    stored = hass_storage[f"{DOMAIN}.{entry.entry_id}.keys"]["data"]
    assert stored["keys"] == {"0123456789001": "KEY", "0123456789002": "KEY"}
    assert "p" not in stored["credential"]  # a hash, not the password
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert fake.keygens == 2  # stored keys reused, no new keygen


async def test_setup_waits_only_for_unit_status(hass: HomeAssistant, fake) -> None:
    from homeassistant.const import EVENT_HOMEASSISTANT_STARTED, EVENT_HOMEASSISTANT_STOP
    from homeassistant.core import CoreState

    from custom_components.paloalto_firewall import const

    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id="0123456789001_0123456789002",
        data={
            CONF_NAME: "Edge",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_VERIFY_SSL: False,
            CONF_UNITS: [
                {"host": h, "serial": u["serial"], "hostname": u["hostname"], "model": "PA-440"}
                for h, u in fake.units.items()
            ],
        },
    )
    entry.add_to_hass(hass)
    fake.calls.clear()
    hass.set_state(CoreState.starting)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    # Update checks and the threat log wait until Home Assistant has started.
    calls = {c for _, c in fake.calls}
    assert const.CMD_SYSTEM_INFO in calls and const.CMD_INTERFACE_ALL in calls
    assert const.CMD_SOFTWARE_CHECK not in calls
    assert "log:threat" not in calls
    hass.set_state(CoreState.running)
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
    await hass.async_block_till_done(wait_background_tasks=True)
    calls = {c for _, c in fake.calls}
    assert {const.CMD_SOFTWARE_CHECK, "log:threat"} <= calls

    # Stopping Home Assistant closes the clients: no further requests.
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await hass.async_block_till_done()
    assert all(u.client._closed for u in entry.runtime_data.units)


async def test_backup_default_route(hass: HomeAssistant, fake, freezer) -> None:
    await _setup(hass, fake)
    v6 = "binary_sensor.wan_a_vr_ipv6_backup_default_route"
    assert hass.states.get(v6).state == "off"
    assert hass.states.get("binary_sensor.wan_b_vr_ipv4_backup_default_route").state == "off"
    assert hass.states.get("binary_sensor.core_vr_ipv6_backup_default_route") is None  # no ::/0
    events = async_capture_events(hass, "paloalto_firewall_default_route_change")

    # A router advertisement refreshes the RA-learned route: uptime restarts, nothing changed.
    fake.default_routes["wan-a-vr"]["ipv6"]["uptime"] = "00:00:20"
    await _tick(hass, freezer, 61)
    assert events == []

    # The RA route is withdrawn and the floating static takes over.
    fake.default_routes["wan-a-vr"]["ipv6"].update(distance=240, uptime="00:00:05")
    await _tick(hass, freezer, 61)
    state = hass.states.get(v6)
    assert state.state == "on"
    assert state.attributes["distance"] == 240 and state.attributes["usual_distance"] == 10
    assert [e.data["change"] for e in events] == ["backup"]
    assert events[-1].data["previous_distance"] == 10
    assert state.attributes["changes_24h"] == 1

    fake.default_routes["wan-a-vr"]["ipv6"].update(distance=10, uptime="00:00:10")
    await _tick(hass, freezer, 61)
    assert hass.states.get(v6).state == "off"
    assert events[-1].data["change"] == "primary"

    assert len(events) == 2

    # IPv4 default route gone entirely.
    del fake.default_routes["wan-b-vr"]["ipv4"]
    await _tick(hass, freezer, 61)
    assert events[-1].data["change"] == "lost"
    assert events[-1].data["logical_router"] == "wan-b-vr"
    assert hass.states.get("binary_sensor.wan_b_vr_ipv4_backup_default_route").attributes["present"] is False


async def test_expired_stored_key_is_regenerated(hass: HomeAssistant, fake, freezer, hass_storage) -> None:
    entry = await _setup(hass, fake)
    await _tick(hass, freezer, 5)
    # The firewall rotates its keys while Home Assistant is down.
    fake.valid_keys = {"KEY2"}
    fake.issue_key = "KEY2"
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert "KEY" in fake.rejected_keys  # stored key tried first...
    assert fake.keygens == 4  # ...then one new key per unit
    assert hass.states.get("sensor.fw1_pan_os_version").state == "11.1.4-h7"
    await _tick(hass, freezer, 5)
    assert hass_storage[f"{DOMAIN}.{entry.entry_id}.keys"]["data"]["keys"]["0123456789001"] == "KEY2"


async def test_stored_keys_dropped_when_credentials_change(
    hass: HomeAssistant, fake, freezer, hass_storage
) -> None:
    entry = await _setup(hass, fake)
    await _tick(hass, freezer, 5)
    hass.config_entries.async_update_entry(entry, data={**entry.data, CONF_USERNAME: "other"})
    await hass.async_block_till_done(wait_background_tasks=True)
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert fake.keygens >= 4  # the old account's keys weren't reused


async def test_role_refusal_is_not_a_bad_key(hass: HomeAssistant, fake) -> None:
    """HTTP 403 "not authorized for user role" is a permission limit: no keygen, no reauth."""
    fake.fail[const.CMD_IPSEC_SA] = "403"
    entry = await _setup(hass, fake)
    assert fake.keygens == 2
    assert not any(entry.async_get_active_flows(hass, {config_entries.SOURCE_REAUTH}))
    assert fake.calls.count(("fw1.lan", const.CMD_IPSEC_SA)) == 1  # refused once, not retried with a new key


async def test_threat_unauthorized_code_16(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import issue_registry as ir

    fake.fail["log:threat"] = "16"
    entry = await _setup(hass, fake)
    assert ir.async_get(hass).async_get_issue(DOMAIN, f"{entry.entry_id}_permission_threat_log") is not None


async def test_stop_cancels_requests_in_flight(hass: HomeAssistant, fake) -> None:
    from homeassistant.const import EVENT_HOMEASSISTANT_STOP

    from custom_components.paloalto_firewall.api import PanOSConnectionError

    entry = await _setup(hass, fake)
    client = entry.runtime_data.units[0].client
    fake.hold = asyncio.Event()
    fake.hold_cmd = const.CMD_RUNNING_CONFIG
    task = hass.async_create_task(client.op(const.CMD_RUNNING_CONFIG))
    for _ in range(20):
        await asyncio.sleep(0)
        if fake.held:
            break
    assert fake.held == 1
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await hass.async_block_till_done()
    assert task.cancelled()
    with pytest.raises(PanOSConnectionError, match="shutting down"):
        await client.op(const.CMD_SYSTEM_INFO)
    fake.hold.set()


async def test_log_query_is_bounded_and_cleaned_up(hass: HomeAssistant, fake, monkeypatch) -> None:
    from custom_components.paloalto_firewall import api

    monkeypatch.setattr(api, "LOG_POLL_SECONDS", 0.01)
    entry = await _setup(hass, fake)
    fake.log_job_never_finishes = True
    client = entry.runtime_data.units[0].client
    with pytest.raises(api.PanOSConnectionError, match="still running"):
        await client.log_query("threat", "(severity geq high)", nlogs=5, timeout=0.2)
    assert fake.finished_log_jobs  # the job was stopped on the firewall


async def test_default_route_learned_distances(hass: HomeAssistant, fake, freezer) -> None:
    from homeassistant.helpers import device_registry as dr
    from homeassistant.helpers import entity_registry as er

    # A pre-0.9.1 entity keyed by the lossy slug keeps its entity_id, but only
    # an entity on that router's own device is moved.
    reg = er.async_get(hass)
    host = MockConfigEntry(domain="other_integration")
    host.add_to_hass(hass)
    devices = dr.async_get(hass)
    wan_b = devices.async_get_or_create(
        config_entry_id=host.entry_id, identifiers={(DOMAIN, "e1_lr_wan-b-vr")}
    )
    old = reg.async_get_or_create(
        "binary_sensor",
        DOMAIN,
        "e1_defroute_wan_b_vr_ipv4",
        suggested_object_id="my_wan_b_route",
        device_id=wan_b.id,
    )
    stray = reg.async_get_or_create(
        "binary_sensor",
        DOMAIN,
        "e1_defroute_wan_a_vr_ipv6",
        suggested_object_id="stray",
        device_id=wan_b.id,  # on the wrong router's device
    )
    # A BGP-learned default at distance 20 is the router's normal route.
    fake.default_routes["wan-b-vr"]["ipv4"].update(distance=20)
    fake.default_routes["wan-b-vr"]["ipv4"]["protocol"] = "bgp"
    await _setup(hass, fake, entry_id="e1")
    migrated = reg.async_get(old.entity_id)
    assert migrated is not None and migrated.unique_id != "e1_defroute_wan_b_vr_ipv4"
    assert hass.states.get(old.entity_id).state == "off"
    assert reg.async_get(stray.entity_id).unique_id == "e1_defroute_wan_a_vr_ipv6"  # not taken

    # No default route at all: unknown, not "normal".
    del fake.default_routes["wan-a-vr"]["ipv4"]
    await _tick(hass, freezer, 61)
    state = hass.states.get("binary_sensor.wan_a_vr_ipv4_backup_default_route")
    assert state.state == "unknown" and state.attributes["present"] is False


async def test_failed_reads_do_not_clear_repairs(hass: HomeAssistant, fake, freezer) -> None:
    from homeassistant.helpers import issue_registry as ir

    entry = await _setup(hass, fake)
    reg = ir.async_get(hass)

    def ids() -> set[str]:
        return {i for (d, i) in reg.issues if d == DOMAIN and reg.issues[(d, i)].active}

    before = ids()
    assert any("_cert_" in i for i in before) and any("_update_gpclient_" in i for i in before)
    # The certificate store, the update checks and HA state all fail to read.
    fake.fail[const.CMD_CERTS_STORE] = "error"
    fake.fail[const.CMD_GP_CLIENT_CHECK] = "error"
    fake.fail[const.CMD_HA_STATE] = "error"
    entry.runtime_data.network.request_slow_refresh()
    for unit in entry.runtime_data.units:
        await unit.updates.async_refresh()
    await _tick(hass, freezer, 61)
    assert before <= ids()


async def test_threat_times_use_the_firewalls_clock(hass: HomeAssistant, fake, freezer) -> None:
    await hass.config.async_set_time_zone("America/New_York")
    # The firewall runs on UTC, a different zone from Home Assistant.
    fake.clock = dt_util.utcnow().strftime("%a %b %d %H:%M:%S %Y")
    stamp = (dt_util.utcnow() - timedelta(minutes=5)).strftime("%Y/%m/%d %H:%M:%S")
    fake.threats["fw1.lan"] = [{**_threat(1), "time_generated": stamp}]
    await _setup(hass, fake)
    latest = hass.states.get("sensor.edge_ha_pair_threats_24h").attributes["latest"][0]
    when = dt_util.parse_datetime(latest["time"])
    assert abs((dt_util.utcnow() - when).total_seconds() - 300) < 90


async def test_threat_capped_flag_persists(hass: HomeAssistant, fake, freezer, monkeypatch) -> None:
    from custom_components.paloalto_firewall import threats

    monkeypatch.setattr(threats, "FIRST_READ", 3)
    monkeypatch.setattr(threats, "POLL_READ", 2)
    fake.threats["fw1.lan"] = [_threat(i) for i in range(1, 6)]
    await _setup(hass, fake)
    assert hass.states.get("sensor.edge_ha_pair_threats_24h").attributes["count_capped"] is True
    await _tick(hass, freezer, 61)
    assert hass.states.get("sensor.edge_ha_pair_threats_24h").attributes["count_capped"] is True


async def test_threat_cap_ignores_old_entries(hass: HomeAssistant, fake, monkeypatch) -> None:
    """A full read of entries all older than 24 h doesn't mean today's count is short."""
    from custom_components.paloalto_firewall import threats

    monkeypatch.setattr(threats, "FIRST_READ", 3)
    fake.threats["fw1.lan"] = [_threat(i, minutes_ago=60 * 30 + i) for i in range(1, 6)]
    await _setup(hass, fake)
    state = hass.states.get("sensor.edge_ha_pair_threats_24h")
    assert state.state == "0"
    assert state.attributes["count_capped"] is False


async def test_gp_migration_checks_the_original_name(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import entity_registry as er

    reg = er.async_get(hass)
    # Old entity for user "a_b"; "a.b" (same old slug) must not take it.
    old = reg.async_get_or_create(
        "binary_sensor",
        DOMAIN,
        "e2_gp_user_a_b",
        suggested_object_id="my_a_b",
        original_name="GlobalProtect a_b",
    )
    fake.gp_online = {"a.b", "a_b"}
    await _setup(hass, fake, entry_id="e2")
    assert hass.states.get(old.entity_id).attributes["friendly_name"].endswith("a_b")


async def test_threats_wait_through_a_slow_start(hass: HomeAssistant, fake, freezer) -> None:
    from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
    from homeassistant.core import CoreState

    hass.set_state(CoreState.starting)
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id="0123456789001_0123456789002",
        data={
            CONF_NAME: "Edge",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_VERIFY_SSL: False,
            CONF_UNITS: [
                {"host": h, "serial": u["serial"], "hostname": u["hostname"], "model": "PA-440"}
                for h, u in fake.units.items()
            ],
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    for _ in range(4):  # several scan intervals while Home Assistant is still starting
        await _tick(hass, freezer, 61)
    assert ("fw1.lan", "log:threat") not in fake.calls
    hass.set_state(CoreState.running)
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert ("fw1.lan", "log:threat") in fake.calls


async def test_threat_offset_uses_when_the_clock_was_read(hass: HomeAssistant, fake, freezer) -> None:
    """A status sample read 10 minutes ago still gives the right offset."""
    from custom_components.paloalto_firewall.parsers import firewall_utc_offset

    fake.clock = dt_util.utcnow().strftime("%a %b %d %H:%M:%S %Y")  # firewall on UTC
    entry = await _setup(hass, fake)
    status = entry.runtime_data.units[0].coordinator.data
    freezer.tick(timedelta(minutes=10))
    assert firewall_utc_offset(status["system"]["time"], status["fetched_at"]) == 0
    assert entry.runtime_data.threats._utc_offset(entry.runtime_data.units[0]) == 0


async def test_repeated_full_reads_do_not_extend_the_cap(
    hass: HomeAssistant, fake, freezer, monkeypatch
) -> None:
    from custom_components.paloalto_firewall import threats

    monkeypatch.setattr(threats, "FIRST_READ", 10)
    monkeypatch.setattr(threats, "POLL_READ", 2)
    fake.threats["fw1.lan"] = [_threat(i) for i in range(1, 4)]
    await _setup(hass, fake)
    assert hass.states.get("sensor.edge_ha_pair_threats_24h").attributes["count_capped"] is False
    for _ in range(3):  # each later read returns 2 already-known entries: no gap
        await _tick(hass, freezer, 61)
    assert hass.states.get("sensor.edge_ha_pair_threats_24h").attributes["count_capped"] is False


async def test_network_cache_expires_and_recovers(hass: HomeAssistant, fake, freezer) -> None:
    entry = await _setup(hass, fake)
    network = entry.runtime_data.network
    link = "binary_sensor.edge_ha_pair_ethernet1_1_link"
    for unit in fake.units.values():
        unit["up"] = False
    await _tick(hass, freezer, 61)
    assert network.last_update_success
    assert hass.states.get(link).state == "on"
    assert network.data["gp_current"] is None
    assert network.data["gp_users"] is None
    await _tick(hass, freezer, int(network.freshness_grace.total_seconds()) + 1)
    assert not network.last_update_success
    assert hass.states.get(link).state == "unavailable"
    fake.units["fw1.lan"]["up"] = True
    await _tick(hass, freezer, 61)
    assert network.last_update_success
    assert hass.states.get(link).state == "on"


async def test_network_ignores_stale_successful_gp_status(hass: HomeAssistant, fake, freezer) -> None:
    entry = await _setup(hass, fake)
    network = entry.runtime_data.network
    assert network.data["gp_current"]
    freezer.tick(network.freshness_grace + timedelta(seconds=1))
    await network.async_refresh()
    assert network.last_update_success
    assert network.data["gp_current"] is None
    assert network.data["gp_users"] is None


@pytest.mark.parametrize("poll", ["status", "updates", "network", "slow_network"])
async def test_poll_failure_cancels_and_awaits_siblings(hass: HomeAssistant, fake, monkeypatch, poll) -> None:
    from homeassistant.exceptions import ConfigEntryAuthFailed

    entry = await _setup(hass, fake)
    runtime = entry.runtime_data
    coordinator = {
        "status": runtime.units[0].coordinator,
        "updates": runtime.units[0].updates,
        "network": runtime.network,
        "slow_network": runtime.network,
    }[poll]
    started = asyncio.Event()
    calls = []
    finished = []

    async def read(*args, **kwargs):
        index = len(calls)
        calls.append(index)
        if index == 0:
            await started.wait()
            raise ConfigEntryAuthFailed("expired credentials")
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            finished.append(index)

    monkeypatch.setattr(coordinator, "_optional", read)
    with pytest.raises(ConfigEntryAuthFailed, match="expired credentials"):
        if poll == "slow_network":
            await coordinator._refresh_slow(runtime.units[0], runtime.network.data["interfaces"])
        else:
            await coordinator._async_update_data()
    assert len(calls) > 1
    assert sorted(finished) == calls[1:]


async def test_unload_closes_clients_and_cancels_reads(hass: HomeAssistant, fake) -> None:
    from custom_components.paloalto_firewall.const import CMD_INTERFACE_ALL

    entry = await _setup(hass, fake)
    units = entry.runtime_data.units
    fake.hold = asyncio.Event()
    fake.hold_cmd = CMD_INTERFACE_ALL
    task = asyncio.create_task(units[0].client.op(CMD_INTERFACE_ALL))
    while not fake.held:
        await asyncio.sleep(0)
    assert await hass.config_entries.async_unload(entry.entry_id)
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(u.client._closed and not u.client._inflight for u in units)


@pytest.mark.parametrize("failure", ["status", "platforms"])
async def test_failed_setup_closes_clients(hass: HomeAssistant, fake, monkeypatch, failure) -> None:
    from unittest.mock import AsyncMock

    from custom_components.paloalto_firewall.api import PanOSClient

    clients = []
    original_init = PanOSClient.__init__

    def init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        clients.append(self)

    monkeypatch.setattr(PanOSClient, "__init__", init)
    if failure == "status":
        fake.bad_password = True
    else:
        monkeypatch.setattr(
            hass.config_entries, "async_forward_entry_setups", AsyncMock(side_effect=RuntimeError("failed"))
        )
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_NAME: "Edge",
            CONF_USERNAME: "u",
            CONF_PASSWORD: "p",
            CONF_VERIFY_SSL: False,
            CONF_UNITS: [{"host": "fw1.lan", "serial": "0123456789001", "hostname": "fw1"}],
        },
    )
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert clients and all(c._closed and not c._inflight for c in clients)


async def test_diagnostics_redacts_raw_identities(hass: HomeAssistant, fake, monkeypatch) -> None:
    import json

    from custom_components.paloalto_firewall import probes
    from custom_components.paloalto_firewall.diagnostics import async_get_config_entry_diagnostics

    seeds = {
        "username": "seed-vpn-user",
        "primary-username": "seed-primary-user",
        "computer": "seed-vpn-computer",
        "public-ip": "198.51.100.199",
        "public-ipv6": "2001:db8::199",
        "virtual-ip": "192.0.2.199",
        "virtual-ipv6": "2001:db8:1::199",
    }
    original_respond = fake.respond

    def respond(host, cmd, *args, **kwargs):
        if cmd in (const.CMD_GP_USERS, const.CMD_GP_PREVIOUS):
            fields = "".join(f"<{key}>{value}</{key}>" for key, value in seeds.items())
            return f'<response status="success"><result><entry>{fields}</entry></result></response>', 200
        return original_respond(host, cmd, *args, **kwargs)

    monkeypatch.setattr(fake, "respond", respond)
    for host in fake.units:
        fake.threats[host] = [{"seqno": 1, "srcuser": "seed-threat-user", "misc": "seed-threat-url"}]
    monkeypatch.setattr(probes, "debug_enabled", lambda: True)
    entry = await _setup(hass, fake)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    serialized = json.dumps(diag, default=str)
    for value in [*seeds.values(), "seed-threat-user", "seed-threat-url"]:
        assert value not in serialized
    raw = diag["raw_command_samples"]
    assert "**REDACTED**" in raw["gp_current"]["xml"]
    assert "**REDACTED**" in raw["gp_previous"]["xml"]
    assert "**REDACTED**" in raw["threat_log"]["entries"][0]


async def test_network_name_ids_and_safe_migration(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import entity_registry as er

    from custom_components.paloalto_firewall import _remove_stale_network_entities
    from custom_components.paloalto_firewall.binary_sensor import network_binary_sensors
    from custom_components.paloalto_firewall.const import lr_identifier
    from custom_components.paloalto_firewall.network import name_key, pm_key_suffix

    entry = await _setup(hass, fake)
    network = entry.runtime_data.network
    reg = er.async_get(hass)
    peers = network.data["bgp"]["core-vr"]["peers"]
    peers["isp-a"] = next(iter(peers.values()))
    peers["isp_a"] = peers["isp-a"]
    group = next(iter(network.data["path_groups"].values()))
    network.data["path_groups"]["isp.a|eth|hop"] = group
    network.data["path_groups"]["isp_a|eth|hop"] = group
    entities = network_binary_sensors(entry)
    assert len({e.unique_id for e in entities}) == len(entities)
    assert pm_key_suffix("isp.a|eth|hop") != pm_key_suffix("isp_a|eth|hop")

    from homeassistant.helpers import device_registry as dr

    device = get_device(
        dr.async_get(hass), (DOMAIN, lr_identifier(entry.entry_id, "core-vr")), entry.entry_id
    )
    old_uid = f"{entry.entry_id}_bgp_core_vr_isp_a"
    old = reg.async_get_or_create(
        "binary_sensor",
        DOMAIN,
        old_uid,
        config_entry=entry,
        device_id=device.id,
        original_name="BGP isp_a",
    )
    network_binary_sensors(entry)
    assert reg.async_get(old.entity_id).unique_id == f"{entry.entry_id}_bgp_{name_key('core-vr', 'isp_a')}"
    _remove_stale_network_entities(hass, entry)
    assert reg.async_get(old.entity_id) is not None

    # Path-monitor migration also runs before stale cleanup and retains entity_id.
    pm = next(
        e
        for e in er.async_entries_for_config_entry(reg, entry.entry_id)
        if e.unique_id.startswith(f"{entry.entry_id}_pm_")
    )
    key = next(k for k in network.data["path_groups"] if pm.unique_id.endswith(pm_key_suffix(k)))
    legacy = key.replace("|", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    reg.async_update_entity(pm.entity_id, new_unique_id=f"{entry.entry_id}_pm_{legacy}")
    _remove_stale_network_entities(hass, entry)
    assert reg.async_get(pm.entity_id).unique_id == pm.unique_id

    # A matching slug on another router, or without the original name, is not proof.
    reg.async_remove(old.entity_id)
    for original_name, device_id in (("BGP isp-a", None), (None, device.id)):
        other = reg.async_get_or_create(
            "binary_sensor",
            DOMAIN,
            old_uid,
            device_id=device_id,
            original_name=original_name,
        )
        network_binary_sensors(entry)
        assert reg.async_get(other.entity_id).unique_id == old_uid
        reg.async_remove(other.entity_id)


@pytest.mark.parametrize("days, expected", [(-1, True), (10, True), (60, False)])
async def test_certificate_problem_includes_expired(hass: HomeAssistant, fake, days, expected) -> None:
    from custom_components.paloalto_firewall.binary_sensor import PanOSCertExpiringSensor

    entry = await _setup(hass, fake)
    network = entry.runtime_data.network
    network.data["certificates"]["store"] = [
        {
            "name": "only-cert",
            "expires": (dt_util.utcnow() + timedelta(days=days)).isoformat(),
        }
    ]
    sensor = PanOSCertExpiringSensor(entry)
    assert sensor.is_on is expected
    network.data["certificates"]["store"] = None
    assert sensor.is_on is None
    assert not sensor.available


async def test_same_name_certificate_repairs_keep_full_identity(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import issue_registry as ir

    from custom_components.paloalto_firewall.repairs import PanOSRepairs

    entry = await _setup(hass, fake)
    store = [
        {
            "name": "shared-cn",
            "serial": serial,
            "issuer": issuer,
            "expires": (dt_util.utcnow() - timedelta(days=1)).isoformat(),
        }
        for serial, issuer in (("1", "ca-a"), ("2", "ca-a"), ("1", "ca-b"))
    ]
    entry.runtime_data.network.data["certificates"]["store"] = store
    repairs = PanOSRepairs(hass, entry)
    repairs.async_evaluate()
    registry = ir.async_get(hass)

    def cert_issues():
        return {
            k: v
            for k, v in registry.issues.items()
            if k[0] == DOMAIN and v.translation_key.startswith("certificate_")
        }

    before = cert_issues()
    assert len(before) == 3
    store.pop(0)
    repairs.async_evaluate()
    assert len(cert_issues()) == 2
    assert set(cert_issues()) < set(before)


async def test_optional_unit_entities_discovered_after_recovery(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import entity_registry as er

    fake.fail = {cmd: "error" for cmd in (const.CMD_ENVIRONMENTALS, const.CMD_GP_USERS, const.CMD_IPSEC_SA)}
    for unit in fake.units.values():
        unit["gp"] = "0.0.0"
    entry = await _setup(hass, fake)
    suffixes = ("temperature", "globalprotect_users", "ipsec_tunnels", "hardware_alarm", "gp_client_update")
    reg = er.async_get(hass)

    def optional_ids():
        return {
            e.unique_id
            for e in er.async_entries_for_config_entry(reg, entry.entry_id)
            if any(
                e.unique_id == f"{u.config.serial}_{s}" for u in entry.runtime_data.units for s in suffixes
            )
        }

    assert optional_ids() == set()
    fake.fail = {}
    for unit in fake.units.values():
        unit["gp"] = "6.3.3-c1046"
    for unit in entry.runtime_data.units:
        await unit.coordinator.async_refresh()
    await hass.async_block_till_done(wait_background_tasks=True)
    expected = {f"{u.config.serial}_{s}" for u in entry.runtime_data.units for s in suffixes}
    assert optional_ids() == expected
    for unit in entry.runtime_data.units:
        await unit.coordinator.async_refresh()
    await hass.async_block_till_done(wait_background_tasks=True)
    assert optional_ids() == expected
    coordinators = [u.coordinator for u in entry.runtime_data.units]
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert all(not c._listeners for c in coordinators)


async def test_same_hostname_failover_uses_serial(hass: HomeAssistant, fake, monkeypatch) -> None:
    from custom_components.paloalto_firewall import network as network_module
    from custom_components.paloalto_firewall.services import _network_state

    for unit in fake.units.values():
        unit["hostname"] = "shared"
    entry = await _setup(hass, fake)
    network = entry.runtime_data.network
    first, second = entry.runtime_data.units
    assert network.data["unit_serial"] == first.config.serial
    await network.async_refresh()
    assert any(c["in_kbps"] is not None for c in network.data["counters"].values())

    # Service lookups must read this unit's interfaces despite the equal hostname.
    before = fake.calls.count((second.config.host, const.CMD_INTERFACE_ALL))
    await _network_state(entry, second)
    assert fake.calls.count((second.config.host, const.CMD_INTERFACE_ALL)) == before + 1
    before = fake.calls.count((first.config.host, const.CMD_INTERFACE_ALL))
    await _network_state(entry, first)
    assert fake.calls.count((first.config.host, const.CMD_INTERFACE_ALL)) == before

    events = async_capture_events(hass, "paloalto_firewall_bgp_peer_change")
    fake.dns_bgp_up = False
    monkeypatch.setattr(network_module, "pick_unit", lambda entry: second)
    await network.async_refresh()
    assert network.last_update_success
    assert network.data["unit_serial"] == second.config.serial
    assert events == []
    assert all(c["in_kbps"] is None for c in network.data["counters"].values())
    assert network._slow["unit_serial"] == second.config.serial


@pytest.mark.parametrize("failed", ["interfaces", "live", "slow"])
async def test_same_hostname_failover_does_not_reuse_other_unit_cache(
    hass: HomeAssistant, fake, monkeypatch, failed
) -> None:
    from custom_components.paloalto_firewall import network as network_module

    for unit in fake.units.values():
        unit["hostname"] = "shared"
    entry = await _setup(hass, fake)
    network = entry.runtime_data.network
    second = entry.runtime_data.units[1]
    monkeypatch.setattr(network_module, "pick_unit", lambda entry: second)
    if failed == "slow":
        fake.fail = {const.CMD_BGP_SUMMARY: "error", const.CMD_PD_POOLS: "error"}
    elif failed == "interfaces":
        fake.fail = {const.CMD_INTERFACE_ALL: "error"}
    else:
        fake.fail = {
            cmd: "error"
            for cmd in (
                const.CMD_INTERFACE_ALL,
                const.CMD_FIB,
                const.CMD_PATH_MONITOR,
                const.CMD_ROUTES.format("ipv4"),
                const.CMD_ROUTES.format("ipv6"),
            )
        }
    await network.async_refresh()
    if failed == "slow":
        assert network.last_update_success
        assert network.data["bgp"] == {}
        assert network.data["prefix_pools"] == {}
    else:
        assert not network.last_update_success


@pytest.mark.parametrize(
    "stored, hosts",
    [
        (["fw1.lan"], ["fw1.lan", "fw2.lan"]),
        (["fw1.lan", "fw2.lan"], ["fw2.lan"]),
        (["fw1.lan", "fw2.lan"], ["fw2.lan", "fw1.lan"]),
        (["fw2.lan"], ["fw1.lan", "fw2.lan"]),
    ],
)
async def test_config_flow_rejects_overlapping_serials(hass: HomeAssistant, fake, stored, hosts) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_UNITS: [{"serial": fake.units[h]["serial"]} for h in stored]},
    )
    entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {**USER_INPUT, CONF_PRIMARY_HOST: hosts[0], CONF_SECONDARY_HOST: hosts[1] if len(hosts) > 1 else ""},
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


@pytest.mark.parametrize("changed_host", ["fw1.lan", "fw2.lan"])
async def test_reauth_rejects_different_serial(hass: HomeAssistant, fake, changed_host) -> None:
    entry = await _setup(hass, fake)
    fake.units[changed_host]["serial"] = "replacement"
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": config_entries.SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_USERNAME: "new-user", CONF_PASSWORD: "new-password"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "serial_mismatch"
    assert entry.data[CONF_USERNAME] == "u"
    assert entry.data[CONF_PASSWORD] == "p"


async def test_status_rejects_different_serial(hass: HomeAssistant, fake) -> None:
    entry = await _setup(hass, fake)
    coordinator = entry.runtime_data.units[0].coordinator
    previous = coordinator.data
    fake.units["fw1.lan"]["serial"] = "replacement"
    fake.calls.clear()
    await coordinator.async_refresh()
    assert not coordinator.last_update_success
    assert "serial replacement does not match configured" in str(coordinator.last_exception)
    assert coordinator.data is previous
    assert hass.states.get("sensor.fw1_active_sessions").state == "unavailable"
    assert fake.calls == [("fw1.lan", const.CMD_SYSTEM_INFO)]


@pytest.mark.parametrize(
    "command, payload, source",
    [
        (const.CMD_BGP_SUMMARY, "[1]", "bgp"),
        (const.CMD_BGP_PEERS_LR.format("core-vr"), '{"peer":{"state":"Established","detail":1}}', "peers"),
        (const.CMD_ROUTES.format("ipv4"), '{"core-vr":null}', "routes"),
    ],
)
async def test_malformed_network_json_is_isolated(
    hass: HomeAssistant, fake, monkeypatch, command, payload, source
) -> None:
    original = fake.respond

    def respond(host, cmd, *args, **kwargs):
        if cmd == command:
            return f'<response status="success"><result><json>{payload}</json></result></response>', 200
        return original(host, cmd, *args, **kwargs)

    monkeypatch.setattr(fake, "respond", respond)
    entry = await _setup(hass, fake)
    network = entry.runtime_data.network
    assert network.last_update_success
    assert network.data["interfaces"]
    assert network.data["egress"]
    if source == "bgp":
        assert not network._slow["bgp_ok"]
    elif source == "peers":
        assert not network.data["bgp"]["core-vr"]["ok"]
    else:
        assert not network.data["sources_ok"]["default_routes"]


async def test_fib_parsing_and_egress_share_executor_job(hass: HomeAssistant, fake, monkeypatch) -> None:
    import threading

    from custom_components.paloalto_firewall import network as network_module

    entry = await _setup(hass, fake)
    network = entry.runtime_data.network
    original_parse = network_module.parsers.parse_fib
    original_lookup = network_module.parsers.fib_lookup
    main_thread = threading.get_ident()
    threads = []
    jobs = []
    original_job = hass.async_add_executor_job

    def parse(result):
        threads.append(threading.get_ident())
        return original_parse(result)

    def lookup(*args):
        threads.append(threading.get_ident())
        return original_lookup(*args)

    def job(target, *args):
        if target is network_module._fib_and_egress:
            jobs.append(target)
        return original_job(target, *args)

    monkeypatch.setattr(network_module.parsers, "parse_fib", parse)
    monkeypatch.setattr(network_module.parsers, "fib_lookup", lookup)
    monkeypatch.setattr(hass, "async_add_executor_job", job)
    previous_fib, previous_egress = network.data["fib"], network.data["egress"]
    await network.async_refresh()
    assert network.last_update_success
    assert network.data["fib"] == previous_fib
    assert network.data["egress"] == previous_egress
    assert len(jobs) == 1
    assert len(threads) > 1
    assert len(set(threads)) == 1
    assert threads[0] != main_thread
