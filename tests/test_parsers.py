from datetime import date

from custom_components.paloalto_firewall import parsers
from custom_components.paloalto_firewall.api import parse_response

from . import fakefw


def test_system_info():
    d = parsers.parse_system_info(parse_response(fakefw.system_info("fw1", "0011")))
    assert d["serial"] == "0011" and d["model"] == "PA-440"
    assert d["uptime_seconds"] == ((12 * 24 + 3) * 60 + 4) * 60 + 5


def test_ha_and_standalone():
    d = parsers.parse_ha_state(parse_response(fakefw.ha_state("active", "passive")))
    assert d["local_state"] == "active" and d["peer_conn_status"] == "up"
    assert d["running_sync"] == "synchronized"
    assert parsers.parse_ha_state(parse_response(fakefw.OK.format("<enabled>no</enabled>"))) == {"enabled": False}


def test_resources_new_and_old_top():
    d = parsers.parse_system_resources(parse_response(fakefw.RESOURCES))
    assert d["mgmt_cpu_pct"] == 9.8
    assert d["mgmt_memory_pct"] == 60.0  # (7800-3120)/7800
    old = fakefw.OK.format("""<![CDATA[Cpu(s):  2.0%us,  1.0%sy,  0.0%ni, 96.0%id
Mem:   4000000k total,  3000000k used,  1000000k free,   200000k buffers
Swap:  0k total, 0k used, 0k free,  800000k cached]]>""")
    d = parsers.parse_system_resources(parse_response(old))
    assert d["mgmt_cpu_pct"] == 4.0 and d["mgmt_memory_pct"] == 50.0


def test_dataplane_env_sessions():
    d = parsers.parse_dataplane(parse_response(fakefw.DATAPLANE))
    assert d["cpu_avg_pct"] == 20.0 and d["cpu_max_pct"] == 55.0 and d["packet_buffer_pct"] == 2.0
    e = parsers.parse_environmentals(parse_response(fakefw.ENV))
    assert e["max_temp_c"] == 52.4 and e["alarm"] is False
    s = parsers.parse_session_info(parse_response(fakefw.session_info(6400)))
    assert s["utilization_pct"] == 10.0


def test_versions_and_licenses():
    sw = parsers.parse_software_check(parse_response(fakefw.SOFTWARE))
    latest = parsers.latest_panos(sw["versions"], "11.1.4-h7")
    assert latest["train"]["version"] == "11.1.6-h3"
    assert latest["overall"]["version"] == "11.2.5"
    assert parsers.panos_version_key("11.1.4-h7") < parsers.panos_version_key("11.1.4-h10")
    c = parsers.parse_content_check(parse_response(fakefw.CONTENT))
    assert parsers.latest_content(c["versions"])["version"] == "8901-9160"
    lic = parsers.parse_licenses(parse_response(fakefw.LICENSES))
    assert lic["next_expiry"] == date(2026, 11, 5)
    assert lic["next_expiry_feature"] == "Threat Prevention"
    assert lic["expired"] == []  # expired warranty is ignored
    assert all("warranty" not in l["feature"].lower() for l in lic["licenses"])


def test_lookup_parsing_and_matching():
    arp = parsers.parse_arp(parse_response(fakefw.ARP))
    assert [a["arp_status"] for a in arp] == ["complete", "complete", "incomplete", "static"]
    assert arp[2]["mac"] is None
    dhcp = parsers.parse_dhcp_leases(parse_response(fakefw.DHCP))
    assert dhcp[0]["interface"] == "ethernet1/2.30"
    assert dhcp[0]["lease_time"] == "Fri Oct 9 02:14:00 2026"
    assert dhcp[0]["lease_duration"] == 86400
    assert "lease_expires" not in dhcp[0]

    hosts = parsers.merge_hosts(arp, dhcp)
    assert [h["ip"] for h in hosts] == ["10.2.3.6", "10.2.3.45", "10.2.3.99", "10.2.3.120", "10.2.4.1"]
    kitchen = hosts[1]
    assert kitchen["sources"] == ["dhcp", "arp"] and kitchen["hostname"] == "shelly-plug-kitchen"
    assert kitchen["arp_status"] == "complete"
    garage = hosts[2]  # incomplete ARP merged into the lease for the same IP
    assert garage["mac"] == "00:11:22:dd:ee:ff" and garage["arp_status"] == "incomplete"

    def find(q):
        return [h["ip"] for h in hosts if parsers.host_matches(h, q)]

    assert find("10.2.3.45") == ["10.2.3.45"]  # exact IP, not 10.2.3.45x
    assert find("10.2.3.4") == []  # full IP means exact
    assert find("10.2.4") == ["10.2.4.1"]  # partial IP is a substring
    assert find("00:11:22") == ["10.2.3.45", "10.2.3.99"]
    assert find("0011.22aa") == ["10.2.3.45"]  # Cisco-style
    assert find("00-11-22-AA-BB-CC") == ["10.2.3.45"]
    assert find("KITCHEN") == ["10.2.3.45"]
    assert find("ethernet1/3") == ["10.2.4.1"]
    assert len(find("")) == 5
