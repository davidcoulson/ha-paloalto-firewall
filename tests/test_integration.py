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


async def _setup(hass: HomeAssistant, fake) -> MockConfigEntry:
    entry = MockConfigEntry(
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
            CONF_NAME: "Edge", CONF_USERNAME: "u", CONF_PASSWORD: "p", CONF_VERIFY_SSL: False,
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
        DOMAIN, "lookup", {"query": "garage", "source": "dhcp", "config_entry_id": entry.entry_id},
        blocking=True, return_response=True,
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
        await hass.services.async_call(
            DOMAIN, "lookup", {"query": "x"}, blocking=True, return_response=True
        )


async def test_lookup_requires_loaded_entry(hass: HomeAssistant, fake) -> None:
    from homeassistant.exceptions import ServiceValidationError
    from homeassistant.setup import async_setup_component

    assert await async_setup_component(hass, DOMAIN, {})
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(
            DOMAIN, "lookup", {"query": "x"}, blocking=True, return_response=True
        )


async def test_security_policy_action(hass: HomeAssistant, fake) -> None:
    from homeassistant.exceptions import HomeAssistantError

    await _setup(hass, fake)
    fake.calls.clear()
    result = await hass.services.async_call(
        DOMAIN, "test_security_policy",
        {"source": "10.2.4.86", "destination": "1.1.1.1", "destination_port": 443,
         "protocol": "tcp", "from_zone": "iot", "to_zone": "untrust"},
        blocking=True, return_response=True,
    )
    assert result["firewall"] == "fw1"  # the active unit
    assert result["mode"] == "explicit"
    assert result["hops"][0]["matched"] is True
    assert result["rule"] == "IoT-to-Internet" and result["verdict"] == "allow"
    assert result["criteria"]["protocol"] == 6
    assert {h for h, _ in fake.calls} == {"fw1.lan"}

    result = await hass.services.async_call(
        DOMAIN, "test_security_policy", {"source": "10.2.4.86", "destination": "9.9.9.9"},
        blocking=True, return_response=True,
    )
    assert result["hops"][-1]["matched"] is False and "note" in result

    with pytest.raises(HomeAssistantError, match="bogus"):
        await hass.services.async_call(
            DOMAIN, "test_security_policy",
            {"source": "10.2.4.86", "destination": "1.1.1.1", "from_zone": "bogus"},
            blocking=True, return_response=True,
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
    assert ev == [{
        "entry_id": entry.entry_id, "logical_router": "core-vr", "family": "ipv4",
        "previous_interface": "ae9.101", "previous_zone": "WanB",
        "interface": "ae9.100", "zone": "WanA", "nexthop": "172.31.0.2",
    }]


async def test_route_lookup_and_inferred_policy_tests(hass: HomeAssistant, fake) -> None:
    from homeassistant.exceptions import ServiceValidationError

    await _setup(hass, fake)

    async def call(service, data):
        return await hass.services.async_call(DOMAIN, service, data, blocking=True, return_response=True)

    r = await call("route_lookup", {"destination": "1.1.1.1"})
    assert [x["logical_router"] for x in r["results"]] == ["core-vr", "wan-a-vr", "wan-b-vr"]
    assert r["results"][0]["paths"][0] == {
        "interface": "ae9.101", "nexthop": "172.31.0.6", "zone": "WanB", "vsys": "vsys1", "drop": False
    }
    r = await call("route_lookup", {"destination": "10.9.99.9", "source": "10.9.20.50"})
    assert r["searched"].startswith("source 10.9.20.50 (ae1.20)")
    assert r["results"] == [{"logical_router": "core-vr", "route": "10.9.0.0/16",
                             "paths": [{"interface": None, "nexthop": "drop", "zone": None, "vsys": None, "drop": True}]}]
    r = await call("route_lookup", {"destination": "1.1.1.1", "logical_router": "wan-a-vr"})
    assert r["results"][0]["paths"][0]["interface"] == "ethernet1/1"
    with pytest.raises(ServiceValidationError):
        await call("route_lookup", {"destination": "1.1.1.1", "logical_router": "nope"})

    # Traced: IoT (vsys1, core-vr) -> WanB, then re-enters on ae9.201 (vsys3, wan-b-vr) -> Internet.
    fake.vsys_calls.clear()
    r = await call("test_security_policy", {"source": "10.9.20.50", "destination": "1.1.1.1", "destination_port": 443})
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
    r = await call("test_security_policy", {"source": "10.9.20.50", "destination": "1.1.1.1", "vsys": "vsys3"})
    assert r["mode"] == "explicit" and len(r["hops"]) == 1
    assert (r["hops"][0]["from_zone"], r["hops"][0]["to_zone"]) == ("Core", "Internet")
    assert fake.vsys_calls == [(fake.vsys_calls[0][0], "vsys3")]

    # Explicit zones win.
    r = await call("test_security_policy", {"source": "10.9.20.50", "destination": "1.1.1.1",
                                            "from_zone": "Trusted", "to_zone": "WanA", "vsys": "vsys1"})
    assert "<from>Trusted</from><to>WanA</to>" in fake.vsys_calls[-1][0]

    # NAT: tested at every hop with that hop's egress interface.
    fake.vsys_calls.clear()
    r = await call("test_nat_policy", {"source": "10.9.20.50", "destination": "1.1.1.1", "destination_port": 443})
    assert [h["egress_interface"] for h in r["hops"]] == ["ae9.101", "ethernet1/2"]
    assert "<to-interface>ethernet1/2</to-interface>" in fake.vsys_calls[1][0]
    assert [(t["hop"], t["vsys"], t["rule"]) for t in r["translations"]] == [
        (1, "vsys1", "IoT-Hide-NAT"), (2, "vsys3", "IoT-Hide-NAT"),
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
            CONF_NAME: "Edge", CONF_USERNAME: "u", CONF_PASSWORD: "p", CONF_VERIFY_SSL: False,
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
        result["flow_id"], {"scan_interval": 60, "update_check_hours": 6, "interfaces": ["ae1.20"]}
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
        "NPT (#2): inbound uses 2001:db8:aaa:f0::/60, outside delegated 2001:db8:a00::/56",
    ]
    assert st("binary_sensor.edge_ha_pair_wan_b_nptv6_prefix_mismatch").state == "off"

    # ISP hands out a new prefix: event fires and the mismatch sensor flips on.
    events = async_capture_events(hass, "paloalto_firewall_prefix_change")
    fake.wan_b_prefix = "2001:db8:c00::/56"
    await _tick(hass, freezer, 61)  # fast poll only: prefixes are slow-tier
    assert events == []
    assert st("sensor.edge_ha_pair_wan_b_delegated_prefix").state == "2001:db8:b00::/56"
    await _tick(hass, freezer, 240)
    assert [e.data for e in events] == [{
        "entry_id": entry.entry_id, "pool": "wan-b", "interface": "ethernet1/2",
        "previous_prefix": "2001:db8:b00::/56", "prefix": "2001:db8:c00::/56",
    }]
    assert st("binary_sensor.edge_ha_pair_wan_b_nptv6_prefix_mismatch").state == "on"


async def test_stale_path_monitor_entities_removed(hass: HomeAssistant, fake) -> None:
    from homeassistant.helpers import entity_registry as er

    entry = await _setup(hass, fake)
    reg = er.async_get(hass)
    stale = reg.async_get_or_create(
        "binary_sensor", DOMAIN, f"{entry.entry_id}_pm_core-vr_ae9_100_fd00_99_old__1",
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
    stale = reg.async_get_or_create("binary_sensor", DOMAIN, f"{entry.entry_id}_bgp_core_vr_old_peer", config_entry=entry)
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
        DOMAIN, "session_lookup",
        {"source": "10.2.4.86", "destination_port": 443, "protocol": "tcp", "limit": 1},
        blocking=True, return_response=True,
    )
    assert resp["firewall"] == "fw1" and resp["total"] == 2
    assert resp["returned"] == 1 and resp["truncated"] is True
    s = resp["sessions"][0]
    assert s["application"] == "ssl" and s["rule"] == "Allow web"
    assert s["nat_source"] == "203.0.113.10:40001" and "nat_destination" not in s
    cmd = next(c for _, c in reversed(fake.calls) if c.startswith("<show><session><all>") and "count" not in c)
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


async def test_transient_failures_keep_entities_and_stay_quiet(
    hass: HomeAssistant, fake, freezer
) -> None:
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


async def test_network_entities_appear_after_late_first_poll(
    hass: HomeAssistant, fake, freezer
) -> None:
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
    network = entry.runtime_data.network
    auto = network.auto_interfaces(network.data)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"scan_interval": 30, "update_check_hours": 6, "interfaces": list(auto)}
    )
    await hass.async_block_till_done(wait_background_tasks=True)
    assert "interfaces" not in entry.options
    assert entry.options["scan_interval"] == 30


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
