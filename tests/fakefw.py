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
<sw-version>{sw}</sw-version><global-protect-client-package-version>6.3.3-c1046</global-protect-client-package-version>
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

GP_HOSTS = {"alice": ("alice-laptop", "198.51.100.7", "10.9.0.2"), "bob": ("bob-mac", "203.0.113.50", "10.9.0.3")}


def _gp_entry(user, login=1790861465, logout=None, reason=None):
    computer, public, virtual = GP_HOSTS.get(user, (f"{user}-pc", "192.0.2.1", "10.9.0.9"))
    out = (f"<entry><domain/><username>{user}</username><primary-username>{user}</primary-username>"
           f"<computer>{computer}</computer><client>Apple Mac OS X 26.6.2</client>"
           f"<app-version>6.3.3-1046</app-version><virtual-ip>{virtual}</virtual-ip>"
           f"<virtual-ipv6>::</virtual-ipv6><public-ip>{public}</public-ip><public-ipv6>::</public-ipv6>"
           f"<tunnel-type>IPSec</tunnel-type><source-region>US</source-region>"
           f"<login-time-utc>{login}</login-time-utc>")
    if logout:
        out += f"<logout-time-utc>{logout}</logout-time-utc><reason>{reason}</reason>"
    return out + "</entry>"


def gp_current(online):
    return OK.format("".join(_gp_entry(u) for u in sorted(online)))


GP_PREVIOUS = OK.format(
    _gp_entry("carol", 1790000000, 1790003600, "user logout")
    + _gp_entry("alice", 1789000000, 1789003600, "user session expired")
    + _gp_entry("carol", 1789500000, 1789503600, "user logout")
)

GP_CLIENT = OK.format("""<sw-updates last-updated-at="2026/10/10 02:41:29"><msg/><versions>
<entry><version>6.3.3-c1199</version><downloaded>no</downloaded><current>no</current><latest>no</latest><released-on>2026/10/08 10:10:39</released-on><release-notes>https://example.com/gp</release-notes></entry>
<entry><version>6.3.3-c1046</version><downloaded>yes</downloaded><current>yes</current><latest>no</latest><released-on>2026/06/12 21:00:16</released-on></entry>
<entry><version>6.3.3</version><downloaded>no</downloaded><current>no</current><latest>no</latest><released-on>2025/04/30</released-on></entry>
<entry><version>6.4.0</version><downloaded>no</downloaded><current>no</current><latest>no</latest><released-on>2026/09/30</released-on></entry>
<entry><version>6.2.8-c1084</version><downloaded>no</downloaded><current>no</current><latest>no</latest><released-on>2026/10/08</released-on></entry>
</versions></sw-updates>""")


def _make_pem(cn, days, issuer_cn=None, sans=()):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=60))
        .not_valid_after(now + timedelta(days=days))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode(), now + timedelta(days=days)


def certs_device():
    leaf, leaf_exp = _make_pem("fw.example.net", 10, "E8", ("fw.example.net", "gp.example.net"))
    inter, _ = _make_pem("E8", 300, "ISRG Root X1")
    ca, ca_exp = _make_pem("HomeCA", 1200)
    text = (
        "428F87DB2E24DEF29438F3FF550A4B0B4EAADC8E:2B6BE102DAA80ACD7BC32AD4AE51E9AEC9A799A3\n"
        "    vsys id: 0\n    cert name: fw.example.net\n"
        f"    subject name hash: 428F\n    public key: {leaf}{inter}\n    private key: exist\n\n"
        "88EF2F55E94BF3246665458AF69E8177C7B448C9:47E23078E27E36F7DAFF16B4A568B2B228964C34\n"
        "    vsys id: 0\n    cert name: HomeCA\n"
        f"    subject name hash: 88EF\n    public key: {ca}\n    private key: exist\n\n"
    )
    store = ""
    for name, exp, status in (
        ("/CN=fw.example.net", leaf_exp, "V"),
        ("/CN=HomeCA", ca_exp, "V"),
        ("/CN=old-self-signed", None, "E"),
    ):
        stamp = exp.strftime("%y%m%d%H%M%SZ") if exp else "260811122609Z"
        store += (
            "ABCDEF:123456\n    serial number: \n        issuer: /CN=HomeCA\n"
            f"        db-exp-date: {stamp}(whenever)\n        db-serialno: ABCDEF\n"
            f"        db-name: {name}\n        db-status: {status}\n\n"
        )
    return OK.format(text), OK.format(store)


CERTS_DEVICE, CERTS_STORE = certs_device()

SESSIONS = OK.format("""<entry><dst>1.1.1.1</dst><xsource>203.0.113.10</xsource><source>10.2.4.86</source>
<xdst>1.1.1.1</xdst><xsport>40001</xsport><xdport>443</xdport><sport>51515</sport><dport>443</dport>
<proto>6</proto><from>Core</from><to>Internet</to><start-time>Sat Oct 10 02:41:19 2026</start-time>
<nat>True</nat><srcnat>True</srcnat><dstnat>False</dstnat><state>ACTIVE</state><type>FLOW</type>
<total-byte-count>9000</total-byte-count><idx>691086</idx><vsys>vsys1</vsys><application>ssl</application>
<security-rule>Allow web</security-rule><ingress>ae1.20</ingress><egress>ethernet1/1</egress></entry>
<entry><dst>1.1.1.1</dst><xsource>10.2.4.86</xsource><source>10.2.4.86</source><xdst>1.1.1.1</xdst>
<xsport>51516</xsport><xdport>53</xdport><sport>51516</sport><dport>53</dport><proto>17</proto><from>Core</from>
<to>Internet</to><nat>False</nat><srcnat>False</srcnat><dstnat>False</dstnat><state>ACTIVE</state>
<idx>691090</idx><vsys>vsys1</vsys><application>dns-base</application><security-rule>Allow DNS</security-rule>
<total-byte-count>120</total-byte-count></entry>""")
SESSION_COUNT = OK.format("<member>2</member>")
SESSION_DETAIL = OK.format("""<slot>1</slot><c2s><source>10.2.4.86</source><dst>1.1.1.1</dst><dport>443</dport>
<source-zone>Core</source-zone></c2s><application>ssl</application><rule>Allow web</rule><end-reason>unknown</end-reason>""")
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
POLICY_DENY = OK.format('<rules><entry name="Block-WanB-Out"><index>4</index><action>deny</action></entry></rules>')


# --- Advanced Routing / interfaces (synthetic, same shape as PAN-OS 12.1) ----
# core-vr (vsys1, internal) reaches wan-a-vr (vsys2) / wan-b-vr (vsys3) via ae9.x


def _ifnet(name, vsys, zone, fwd, ip, tag=0, addr6=""):
    return (f"<entry><name>{name}</name><id>1</id><tag>{tag}</tag><vsys>{vsys}</vsys><zone>{zone}</zone>"
            f"<fwd>{fwd}</fwd><ip>{ip}</ip><addr/><dyn-addr/><addr6>{addr6}</addr6></entry>")


def interface_all(wan_b_link="up"):
    hw = "".join(
        f"<entry><name>{n}</name><id>1</id><type>0</type><mac>00:00:5e:00:53:0{i}</mac>"
        f"<speed>{sp}</speed><duplex>{dx}</duplex><state>{st}</state><st>x</st></entry>"
        for i, (n, sp, dx, st) in enumerate([
            ("ethernet1/1", "10000", "full", "up"),
            ("ethernet1/2", "10000", "full", wan_b_link),
            ("ae1", "[n/a]", "[n/a]", "up"),
            ("ae9", "[n/a]", "[n/a]", "up"),
            ("ha1-a", "1000", "full", "up"),
        ])
    )
    ifnet = "".join([
        _ifnet("ethernet1/1", "2", "Internet", "lr:wan-a-vr", "100.64.10.2/10"),
        _ifnet("ethernet1/2", "3", "Internet", "lr:wan-b-vr", "203.0.113.10/24"),
        _ifnet("ae1", "1", "Trusted", "lr:core-vr", "10.9.1.1/24"),
        _ifnet("ae1.20", "1", "IoT", "lr:core-vr", "10.9.20.1/24", 20, "fd00:9:20::1/64"),
        _ifnet("ae9.100", "1", "WanA", "lr:core-vr", "172.31.0.1/30", 100, "fd00:99:a::2/64"),
        _ifnet("ae9.101", "1", "WanB", "lr:core-vr", "172.31.0.5/30", 101, "fd00:99:b::2/64"),
        _ifnet("ae9.200", "2", "Core", "lr:wan-a-vr", "172.31.0.2/30", 200),
        _ifnet("ae9.201", "3", "Core", "lr:wan-b-vr", "172.31.0.6/30", 201),
        _ifnet("ha1-a", "0", "", "ha", "198.18.0.1/30"),
    ])
    return OK.format(f"<hw>{hw}</hw><ifnet>{ifnet}</ifnet>")


def _fib_entry(dst, iface, nh, flags="ug"):
    return (f"<entry><id>1</id><dst>{dst}</dst><interface>{iface}</interface><nh_type>0</nh_type>"
            f"<flags>{flags}</flags><nexthop>{nh}</nexthop><mtu>1500</mtu></entry>")


def fib(core_v4_via="b"):
    via = {"a": ("ae9.100", "172.31.0.2"), "b": ("ae9.101", "172.31.0.6")}[core_v4_via]
    tables = {
        ("core-vr", 0): [
            _fib_entry("0.0.0.0/1", *via), _fib_entry("128.0.0.0/1", *via),
            _fib_entry("10.9.0.0/16", "", "drop", "u"),
            _fib_entry("10.9.1.0/24", "ae1", "0.0.0.0", "u"),
            _fib_entry("10.9.20.0/24", "ae1.20", "0.0.0.0", "u"),
            _fib_entry("172.31.0.0/30", "ae9.100", "0.0.0.0", "u"),
            _fib_entry("172.31.0.4/30", "ae9.101", "0.0.0.0", "u"),
        ],
        ("core-vr", 1): [_fib_entry("2000::/3", "ae9.100", "fd00:99:a::1")],
        ("wan-a-vr", 0): [
            _fib_entry("0.0.0.0/0", "ethernet1/1", "100.64.0.1"),
            _fib_entry("10.9.0.0/16", "ae9.200", "172.31.0.1"),
        ],
        ("wan-b-vr", 0): [
            _fib_entry("0.0.0.0/0", "ethernet1/2", "203.0.113.1"),
            _fib_entry("10.9.0.0/16", "ae9.201", "172.31.0.5"),
        ],
    }
    body = "".join(
        f"<entry><id>{i}</id><vr>{vr}</vr><max>20000</max><type>{t}</type><entries>{''.join(e)}</entries></entry>"
        for i, ((vr, t), e) in enumerate(tables.items())
    )
    return OK.format(f"<dp>dp0</dp><total>12</total><fibs>{body}</fibs>")


def path_monitor(wan_b_up=True):
    def entry(dst, nh, iface, up):
        mons = "".join(
            f"<monitordst-{i}>{m}</monitordst-{i}><interval-count-{i}>3/5</interval-count-{i}>"
            f"<monitorstatus-{i}>{'Success' if up else 'Failed'}</monitorstatus-{i}>"
            for i, m in enumerate(["192.0.2.53", "198.51.100.53"])
        )
        return (f"<entry><destination>{dst}</destination><nexthop>{nh}</nexthop><metric>10</metric>"
                f"<interface>{iface}</interface><pathmonitor-cond>Enabled(All)</pathmonitor-cond>"
                f"<pathmonitor-status>{'Up' if up else 'Down'} </pathmonitor-status>{mons}</entry>")
    return OK.format(
        entry("0.0.0.0/0", "100.64.0.1", "ethernet1/1", True)
        + entry("0.0.0.0/0", "203.0.113.1", "ethernet1/2", wan_b_up)
        + entry("2000::/3", "fd00:99:b::1", "ae9.101", False)
    )


JOBS = OK.format(
    "<job><tenq>2026/10/09 20:40:00</tenq><id>101</id><user>admin</user><type>Commit</type>"
    "<status>FIN</status><result>OK</result><tfin>2026/10/09 20:41:10</tfin><progress>100</progress></job>"
    "<job><tenq>2026/10/09 20:52:45</tenq><id>102</id><user>Auto update agent</user><type>WildFire</type>"
    "<status>ACT</status><result>PEND</result><tfin/><progress>40</progress></job>"
)


def interface_detail(name, ibytes, obytes):
    return OK.format(
        f"<dp>dp0</dp><ifnet><name>{name}</name><counters><hw><entry><name>{name}</name>"
        f"<ibytes>{ibytes}</ibytes><obytes>{obytes}</obytes><ipackets>1</ipackets><opackets>1</opackets>"
        f"<ierrors>0</ierrors><idrops>0</idrops></entry></hw><ifnet/></counters></ifnet>"
    )


# PAN-OS returns NAT test matches as bare rule names.
NAT_MATCH = OK.format("<rules>\n\t<entry>IoT-Hide-NAT</entry>\n</rules>")


def pd_pools(wan_b_prefix="2001:db8:b00::/56"):
    def pool(name, prefix, iface, inherited):
        assign = "".join(f'<entry name="{n}"><address>{a}</address></entry>' for n, a in inherited)
        return (f'<entry name="{name}"><prefix>{prefix}</prefix><interface>{iface}</interface>'
                f"<lease>6 days 23:00:00</lease><preferred-lifetime>604800</preferred-lifetime>"
                f"<valid-lifetime>604800</valid-lifetime><iaid>1</iaid><duid>x</duid><state>active</state>"
                f"<inherited-interface/><address-assignment>{assign}</address-assignment></entry>")
    return OK.format(
        "<pools>"
        + pool("wan-a", "2001:db8:a00::/56", "ethernet1/1", [("ae1.20", "2001:db8:a00:20::1")])
        + pool("wan-b", wan_b_prefix, "ethernet1/2", [])
        + "</pools>"
    )


def running_nat(vsys):
    if vsys == "vsys2":  # wan-a: translation points at an old prefix
        body = """Nat policy configured on vsys2:
"NPT; index: 1" {
        nat-type nptv6;
        from Core;
        source fd00:9::/60 ;
        to Internet;
        to-interface ethernet1/1 ;
        destination any;
        translate-to "src: 2001:db8:aaa:f0:0:0:0:0/60 (static-ip) (pool idx: 0)";
        terminal no;
}

"NPT; index: 2" {
        nat-type nptv6;
        from any;
        source any;
        to Internet;
        to-interface  ;
        destination 2001:db8:aaa:f0:0:0:0:0/60 ;
        translate-to "dst: fd00:9:0:0:0:0:0:0/60";
        terminal no;
}
"""
    elif vsys == "vsys3":  # wan-b: matches its delegated prefix
        body = """Nat policy configured on vsys3:
"NPT; index: 1" {
        nat-type nptv6;
        from Core;
        source fd00:9::/60 ;
        to Internet;
        to-interface ethernet1/2 ;
        destination any;
        translate-to "src: 2001:db8:b00:f0:0:0:0:0/60 (static-ip) (pool idx: 0)";
        terminal no;
}

"IoT-Hide-NAT; index: 2" {
        nat-type ipv4;
        from [ Core IoT ];
        source [ 10.9.0.0/16 ];
        to Internet;
        to-interface ethernet1/2 ;
        destination any;
        translate-to "src: ethernet1/2 203.0.113.10(*) (dynamic-ip-and-port) (pool idx: 3)";
        terminal no;
}
"""
    else:
        body = f"Nat policy configured on {vsys}:\n"
    return OK.format(f"<member>{body}</member>")


BGP_SUMMARY = OK.format('<json>{"core-vr": {"enabled": "yes", "router-id": "172.31.255.1", "local-as": 65000}, '
                        '"wan-a-vr": {"enabled": "yes", "router-id": "172.31.255.2", "local-as": 65000}, '
                        '"wan-b-vr": {"enabled": "no", "router-id": "172.31.255.3", "local-as": 65000}}</json>')


def bgp_peers(lr, dns_up=True):
    import json as _json

    def peer(state, peer_ip, remote_as, group, accepted):
        return {"remote-as": remote_as, "local-as": 65000, "peer-group-name": group, "state": state,
                "local-ip": "172.31.255.1", "peer-ip": peer_ip, "status-time": 3600.0, "ipv4": True, "ipv6": False,
                "detail": {"hostname": group, "bgpTimerUpString": "01:00:00", "lastResetDueTo": "Waiting for peer OPEN",
                           "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": accepted, "sentPrefixCounter": 2}}}}
    peers = {
        "core-vr": {
            "dns-anycast-0": peer("Established" if dns_up else "Active", "10.9.7.10", 65001, "anycast", 1),
            "wan-a-vr": peer("Established", "172.31.255.2", 65000, "wan", 3),
        },
        "wan-a-vr": {"core-vr": peer("Established", "172.31.255.1", 65000, "core", 5)},
    }.get(lr, {})
    return OK.format(f"<json>{_json.dumps(peers)}</json>")


class FakePair:
    """State for two firewalls; tests mutate it to simulate failover/outage."""

    def __init__(self):
        self.units = {
            "fw1.lan": {"hostname": "fw1", "serial": "0123456789001", "state": "active", "up": True},
            "fw2.lan": {"hostname": "fw2", "serial": "0123456789002", "state": "passive", "up": True},
        }
        self.bad_password = False
        self.calls: list[tuple[str, str]] = []
        self.vsys_calls: list[tuple[str, str | None]] = []
        self.core_v4_via = "b"
        self.wan_b_up = True
        self.counter_calls = 0
        self.last_vsys: str | None = None
        self.deny_vsys: str | None = None
        self.wan_b_prefix = "2001:db8:b00::/56"
        self.dns_bgp_up = True
        self.gp_online = {"alice", "bob"}

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
        if cmd.startswith("<show><interface>") and cmd != const.CMD_INTERFACE_ALL:
            self.counter_calls += 1
            name = cmd[len("<show><interface>"):-len("</interface></show>")]
            n = self.counter_calls
            return parse_response(interface_detail(name, n * 7_500_000, n * 750_000))
        if cmd.startswith("<show><advanced-routing><bgp><peer><status><logical-router>"):
            lr = cmd.split("<logical-router>")[1].split("<")[0]
            return parse_response(bgp_peers(lr, self.dns_bgp_up))
        if cmd.startswith("<show><session><all><filter>"):
            return parse_response(SESSION_COUNT if "<count>yes</count>" in cmd else SESSIONS)
        if cmd.startswith("<show><session><id>"):
            return parse_response(SESSION_DETAIL)
        if cmd.startswith("<test><nat-policy-match>"):
            return parse_response(NAT_MATCH)
        if cmd.startswith("<test><security-policy-match>"):
            if "<from>bogus</from>" in cmd:
                return parse_response(
                    '<response status="error"><msg><line>from bogus is invalid</line></msg></response>'
                )
            if self.deny_vsys and self.last_vsys == self.deny_vsys:
                return parse_response(POLICY_DENY)
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
            const.CMD_GP_USERS: gp_current(self.gp_online),
            const.CMD_GP_PREVIOUS: GP_PREVIOUS,
            const.CMD_GP_CLIENT_CHECK: GP_CLIENT,
            const.CMD_CERTS_DEVICE: CERTS_DEVICE,
            const.CMD_CERTS_STORE: CERTS_STORE,
            const.CMD_ADMINS: ADMINS,
            const.CMD_IPSEC_SA: IPSEC,
            const.CMD_SOFTWARE_CHECK: SOFTWARE,
            const.CMD_CONTENT_CHECK: CONTENT,
            const.CMD_LICENSE_INFO: LICENSES,
            const.CMD_INTERFACE_ALL: interface_all("up" if self.wan_b_up else "down"),
            const.CMD_FIB: fib(self.core_v4_via),
            const.CMD_PATH_MONITOR: path_monitor(self.wan_b_up),
            const.CMD_JOBS: JOBS,
            const.CMD_PENDING_CHANGES: OK.format("yes"),
            const.CMD_PD_POOLS: pd_pools(self.wan_b_prefix),
            const.CMD_BGP_SUMMARY: BGP_SUMMARY,
            const.CMD_RUNNING_NAT: running_nat(self.last_vsys),
            const.CMD_ARP_ALL: ARP,
            const.CMD_DHCP_LEASES: DHCP,
        }
        if cmd not in table:
            return parse_response(
                '<response status="error"><msg><line>Invalid syntax.</line></msg></response>'
            )
        return parse_response(table[cmd])

    def patch(self, monkeypatch):
        from custom_components.paloalto_firewall.api import PanOSClient

        fake = self

        async def generate_key(self):
            fake.respond(self.host, const.CMD_SYSTEM_INFO)  # raises if down/bad auth
            self.api_key = "KEY"
            return "KEY"

        async def op(self, cmd, timeout=30, vsys=None):
            fake.last_vsys = vsys
            if cmd.startswith("<test>"):
                fake.vsys_calls.append((cmd, vsys))
            return fake.respond(self.host, cmd)

        monkeypatch.setattr(PanOSClient, "generate_key", generate_key)
        monkeypatch.setattr(PanOSClient, "op", op)
