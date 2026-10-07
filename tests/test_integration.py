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

from .fakefw import FakePair

USER_INPUT = {
    CONF_NAME: "Edge",
    CONF_PRIMARY_HOST: "fw1.lan",
    CONF_SECONDARY_HOST: "fw2.lan",
    CONF_USERNAME: "ha-monitor",
    CONF_PASSWORD: "pw",
    CONF_VERIFY_SSL: False,
}


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
