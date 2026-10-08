"""A fake PAN-OS HA pair that answers the XML API commands the integration uses."""

from __future__ import annotations

from custom_components.paloalto_firewall import const
from custom_components.paloalto_firewall.api import (
    PanOSAuthError,
    PanOSConnectionError,
    parse_response,
)

OK = '<response status="success"><result>{}</result></response>'


def system_info(host, serial, sw="11.1.4-h7", app="8900-9150"):
    return OK.format(f"""<system><hostname>{host}</hostname><ip-address>10.0.0.{serial[-1]}</ip-address>
<uptime>12 days, 3:04:05</uptime><family>400</family><model>PA-440</model><serial>{serial}</serial>
<sw-version>{sw}</sw-version><global-protect-client-package-version>6.2.4</global-protect-client-package-version>
<app-version>{app}</app-version><av-version>4950-5470</av-version><threat-version>{app}</threat-version>
<wildfire-version>912345-916000</wildfire-version><url-filtering-version>20261007.20123</url-filtering-version>
<logdb-version>11.1.2</logdb-version><operational-mode>normal</operational-mode>
<device-certificate-status>Valid</device-certificate-status><multi-vsys>off</multi-vsys></system>""")


def ha_state(local, peer, conn="up", sync="synchronized"):
    return OK.format(f"""<enabled>yes</enabled><group><mode>Active-Passive</mode>
<local-info><version>1</version><state>{local}</state><state-duration>3600</state-duration>
<mgmt-ip>10.0.0.1/24</mgmt-ip><preemptive>no</preemptive><priority>100</priority><state-sync>Complete</state-sync></local-info>
<peer-info><conn-status>{conn}</conn-status><state>{peer}</state><mgmt-ip>10.0.0.2</mgmt-ip><priority>110</priority>
<conn-ha1><conn-status>{conn}</conn-status></conn-ha1><conn-ha2><conn-status>{conn}</conn-status></conn-ha2></peer-info>
<running-sync>{sync}</running-sync><running-sync-enabled>yes</running-sync-enabled></group>""")


def session_info(active):
    return OK.format(f"""<tmo-tcp>3600</tmo-tcp><num-max>64000</num-max><num-active>{active}</num-active>
<num-tcp>{active - 100}</num-tcp><num-udp>90</num-udp><num-icmp>10</num-icmp><cps>42</cps><kbps>125000</kbps><pps>15000</pps>""")


RESOURCES = OK.format("""<![CDATA[top - 11:57:01 up 12 days,  3:04,  0 users,  load average: 1.25, 1.10, 0.98
Tasks: 160 total,   1 running, 159 sleeping,   0 stopped,   0 zombie
%Cpu(s):  6.3 us,  3.1 sy,  0.0 ni, 90.2 id,  0.0 wa,  0.2 hi,  0.2 si,  0.0 st
MiB Mem :   7800.0 total,    300.0 free,   4000.0 used,   3500.0 buff/cache
MiB Swap:      0.0 total,      0.0 free,      0.0 used.   3120.0 avail Mem
]]>""")

DATAPLANE = OK.format("""<resource-monitor><data-processors><dp0><minute>
<cpu-load-average><entry><coreid>0</coreid><value>10</value></entry><entry><coreid>1</coreid><value>30</value></entry></cpu-load-average>
<cpu-load-maximum><entry><coreid>0</coreid><value>15</value></entry><entry><coreid>1</coreid><value>55</value></entry></cpu-load-maximum>
<resource-utilization><entry><name>session (average)</name><value>1</value></entry><entry><name>packet buffer (average)</name><value>2</value></entry></resource-utilization>
</minute></dp0></data-processors></resource-monitor>""")

ENV = OK.format("""<thermal><Slot1><entry><slot>1</slot><description>Temperature @ CPU</description><min>0</min><max>85</max><alarm>False</alarm><DegreesC>52.4</DegreesC></entry>
<entry><slot>1</slot><description>Temperature @ Board</description><min>0</min><max>70</max><alarm>False</alarm><DegreesC>41.0</DegreesC></entry></Slot1></thermal>
<power><Slot1><entry><slot>1</slot><description>Power: 1.0V</description><alarm>False</alarm><Volts>1.0</Volts></entry></Slot1></power>""")

GP = OK.format("<entry><username>alice</username></entry><entry><username>bob</username></entry>")
ADMINS = OK.format("<admins><entry><admin>admin</admin><from>10.0.0.50</from></entry></admins>")
IPSEC = OK.format("<ntun>2</ntun><entries><entry><name>site-a</name></entry><entry><name>site-b</name></entry></entries>")

SOFTWARE = OK.format("""<sw-updates last-updated-at="2026/10/07 11:00:00"><msg/><versions>
<entry><version>11.2.5</version><downloaded>no</downloaded><current>no</current><latest>yes</latest><released-on>2026/09/01</released-on><release-notes><![CDATA[https://example.com/11.2.5]]></release-notes></entry>
<entry><version>11.1.6-h3</version><downloaded>yes</downloaded><current>no</current><latest>no</latest><released-on>2026/09/20</released-on><release-notes><![CDATA[https://example.com/11.1.6-h3]]></release-notes></entry>
<entry><version>11.1.4-h7</version><downloaded>yes</downloaded><current>yes</current><latest>no</latest><released-on>2026/05/01</released-on><release-notes><![CDATA[https://example.com/11.1.4-h7]]></release-notes></entry>
<entry><version>10.2.13</version><downloaded>no</downloaded><current>no</current><latest>no</latest><released-on>2026/02/01</released-on></entry>
</versions></sw-updates>""")

CONTENT = OK.format("""<content-updates last-updated-at="2026/10/07"><entry><version>8900-9150</version><current>yes</current><downloaded>yes</downloaded></entry>
<entry><version>8901-9160</version><current>no</current><downloaded>no</downloaded><released-on>2026/10/06</released-on></entry></content-updates>""")

LICENSES = OK.format("""<licenses><entry><feature>Threat Prevention</feature><description>Threat</description><issued>October 01, 2024</issued><expires>November 05, 2026</expires><expired>no</expired></entry>
<entry><feature>PAN-DB URL Filtering</feature><issued>October 01, 2024</issued><expires>March 01, 2027</expires><expired>no</expired></entry>
<entry><feature>Software warranty</feature><description>90 days for software warranty</description><issued>July 29, 2022</issued><expires>October 29, 2022</expires><expired>yes</expired></entry>
<entry><feature>Standard</feature><issued>October 01, 2024</issued><expires>Never</expires><expired>no</expired></entry></licenses>""")

ARP = OK.format("""<max>1500</max><total>4</total><timeout>1800</timeout><dp>dp0</dp><entries>
<entry><status>  c  </status><ip>10.2.3.45</ip><mac>00:11:22:aa:bb:cc</mac><ttl>1200</ttl><interface>ethernet1/2.30</interface><port>ethernet1/2</port></entry>
<entry><status>  c  </status><ip>10.2.3.6</ip><mac>bc:24:11:00:00:06</mac><ttl>1700</ttl><interface>ethernet1/2.30</interface><port>ethernet1/2</port></entry>
<entry><status>  i  </status><ip>10.2.3.99</ip><mac>(incomplete)</mac><ttl>3</ttl><interface>ethernet1/2.30</interface><port>ethernet1/2</port></entry>
<entry><status>  s  </status><ip>10.2.4.1</ip><mac>de:ad:be:ef:00:01</mac><ttl>0</ttl><interface>ethernet1/3</interface><port>ethernet1/3</port></entry>
</entries>""")

DHCP = OK.format("""<interface name="ethernet1/2.30"><allocated>3</allocated><total>200</total>
<entry name="10.2.3.45"><ip>10.2.3.45</ip><mac>00:11:22:aa:bb:cc</mac><hostname>shelly-plug-kitchen</hostname><state>committed</state><duration>86400</duration><leasetime>Fri Oct  9 02:14:00 2026</leasetime></entry>
<entry name="10.2.3.99"><ip>10.2.3.99</ip><mac>00:11:22:dd:ee:ff</mac><hostname>esp-garage</hostname><state>committed</state><duration>86400</duration><leasetime>Fri Oct  9 07:00:00 2026</leasetime></entry>
<entry name="10.2.3.120"><ip>10.2.3.120</ip><mac>aa:bb:cc:33:44:55</mac><hostname>iphone</hostname><state>expired</state><duration>86400</duration><leasetime>Wed Oct  7 09:00:00 2026</leasetime></entry>
</interface>""")

POLICY_MATCH = OK.format("""<rules><entry name="IoT-to-Internet"><index>12</index><from><member>iot</member></from><source><member>any</member></source>
<source-region>none</source-region><to><member>untrust</member></to><destination><member>any</member></destination>
<destination-region>none</destination-region><category><member>any</member></category>
<application_service><member>ssl/tcp/any/443</member></application_service><action>allow</action><icmp-unreachable>no</icmp-unreachable>
<terminal>yes</terminal></entry></rules>""")

POLICY_MATCH_OLD = OK.format("<rules><entry>IoT-to-Internet; index: 12</entry></rules>")
POLICY_NO_MATCH = OK.format("<rules/>")


class FakePair:
    """State for two firewalls; tests mutate it to simulate failover/outage."""

    def __init__(self):
        self.units = {
            "fw1.lan": {"hostname": "fw1", "serial": "0123456789001", "state": "active", "up": True},
            "fw2.lan": {"hostname": "fw2", "serial": "0123456789002", "state": "passive", "up": True},
        }
        self.bad_password = False
        self.calls: list[tuple[str, str]] = []

    def peer(self, host):
        return next(u for h, u in self.units.items() if h != host)

    def respond(self, host, cmd):
        self.calls.append((host, cmd))
        unit = self.units[host]
        if not unit["up"]:
            raise PanOSConnectionError(f"{host} down")
        if self.bad_password:
            raise PanOSAuthError("Invalid credentials")
        peer = self.peer(host)
        if cmd.startswith("<test><security-policy-match>"):
            if "<from>bogus</from>" in cmd:
                return parse_response(
                    '<response status="error"><msg><line>from bogus is invalid</line></msg></response>'
                )
            return parse_response(POLICY_NO_MATCH if "9.9.9.9" in cmd else POLICY_MATCH)
        table = {
            const.CMD_SYSTEM_INFO: system_info(unit["hostname"], unit["serial"]),
            const.CMD_HA_STATE: ha_state(
                unit["state"], peer["state"] if peer["up"] else "unknown",
                "up" if peer["up"] else "down",
            ),
            const.CMD_SESSION_INFO: session_info(1200),
            const.CMD_SYSTEM_RESOURCES: RESOURCES,
            const.CMD_DATAPLANE: DATAPLANE,
            const.CMD_ENVIRONMENTALS: ENV,
            const.CMD_GP_USERS: GP,
            const.CMD_ADMINS: ADMINS,
            const.CMD_IPSEC_SA: IPSEC,
            const.CMD_SOFTWARE_CHECK: SOFTWARE,
            const.CMD_CONTENT_CHECK: CONTENT,
            const.CMD_LICENSE_INFO: LICENSES,
            const.CMD_ARP_ALL: ARP,
            const.CMD_DHCP_LEASES: DHCP,
        }
        return parse_response(table[cmd])

    def patch(self, monkeypatch):
        from custom_components.paloalto_firewall.api import PanOSClient

        fake = self

        async def generate_key(self):
            fake.respond(self.host, const.CMD_SYSTEM_INFO)  # raises if down/bad auth
            self.api_key = "KEY"
            return "KEY"

        async def op(self, cmd, timeout=30):
            return fake.respond(self.host, cmd)

        monkeypatch.setattr(PanOSClient, "generate_key", generate_key)
        monkeypatch.setattr(PanOSClient, "op", op)
