"""Constants for the Palo Alto Networks Firewall integration."""

from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "paloalto_firewall"
MANUFACTURER = "Palo Alto Networks"

PLATFORMS = [Platform.BINARY_SENSOR, Platform.BUTTON, Platform.SENSOR, Platform.UPDATE]

CONF_PRIMARY_HOST = "primary_host"
CONF_SECONDARY_HOST = "secondary_host"
CONF_UNITS = "units"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_UPDATE_INTERVAL = "update_check_hours"

DEFAULT_NAME = "Palo Alto"
DEFAULT_SCAN_INTERVAL = 60  # seconds
DEFAULT_UPDATE_INTERVAL = 6  # hours
MIN_SCAN_INTERVAL = 15

EVENT_FAILOVER = f"{DOMAIN}_failover"

# Operational commands
CMD_SYSTEM_INFO = "<show><system><info></info></system></show>"
CMD_HA_STATE = "<show><high-availability><state></state></high-availability></show>"
CMD_SESSION_INFO = "<show><session><info></info></session></show>"
CMD_SYSTEM_RESOURCES = "<show><system><resources></resources></system></show>"
CMD_DATAPLANE = (
    "<show><running><resource-monitor><minute><last>1</last></minute>"
    "</resource-monitor></running></show>"
)
CMD_ENVIRONMENTALS = "<show><system><environmentals></environmentals></system></show>"
CMD_GP_USERS = (
    "<show><global-protect-gateway><current-user></current-user>"
    "</global-protect-gateway></show>"
)
CMD_ADMINS = "<show><admins></admins></show>"
CMD_IPSEC_SA = "<show><vpn><ipsec-sa></ipsec-sa></vpn></show>"
CMD_SOFTWARE_CHECK = "<request><system><software><check></check></software></system></request>"
CMD_CONTENT_CHECK = "<request><content><upgrade><check></check></upgrade></content></request>"
CMD_LICENSE_INFO = "<request><license><info></info></license></request>"
CMD_ARP_ALL = "<show><arp><entry name='all'/></arp></show>"
CMD_DHCP_LEASES = (
    "<show><dhcp><server><lease><interface>all</interface></lease></server></dhcp></show>"
)

SERVICE_LOOKUP = "lookup"
LOOKUP_TIMEOUT = 60

UPDATE_CHECK_TIMEOUT = 120


def pair_identifier(entry_id: str) -> str:
    return f"{entry_id}_ha_pair"
