"""Noise and allowlist filtering.

Two separate decisions are made for every parsed event:

* **Noise** events (broadcast/multicast chatter, DHCP, mDNS, NetBIOS, SSDP)
  are dropped entirely: they are not stored and not analysed.
* **Allowlisted** sources (trusted admin hosts, the gateway) are stored so
  they stay visible in the event explorer, but are excluded from detection
  so they can never raise an alert.

Why filter at all? A normal network is full of automatic "who is out there?"
traffic from routers, printers and phones. UFW logs a lot of it as blocked,
and without filtering it would fill the database and the charts and could
push a harmless device over a detection threshold (a false positive).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

from .parser import FirewallEvent

# UDP destination ports that carry local-network housekeeping traffic:
#   67/68     DHCP (devices asking for an IP address)
#   137/138   NetBIOS (Windows name lookups)
#   1900      SSDP (UPnP device discovery)
#   5353      mDNS (Bonjour / Avahi service discovery)
#   5355      LLMNR (Windows local name resolution)
DEFAULT_NOISE_PORTS = (67, 68, 137, 138, 1900, 5353, 5355)

# Address ranges used for multicast (one sender, many receivers) and the
# limited broadcast address that every device on the local network receives.
_MULTICAST_V4 = ipaddress.ip_network("224.0.0.0/4")
_MULTICAST_V6 = ipaddress.ip_network("ff00::/8")
_BROADCAST = ipaddress.ip_address("255.255.255.255")


def parse_networks(entries: Iterable[str]) -> list:
    """Turn strings like '192.168.56.1' or '10.0.0.0/8' into network objects.

    Invalid entries are skipped (the UI validates them before saving).
    A single address such as 192.168.56.1 becomes a network of size one
    (192.168.56.1/32), so addresses and ranges are handled the same way.
    """
    nets = []
    for entry in entries:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            # strict=False accepts "10.0.0.5/8" and treats it as 10.0.0.0/8
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return nets


def is_valid_network(entry: str) -> bool:
    """Used by the Rules page to reject bad allowlist input before saving."""
    try:
        ipaddress.ip_network(entry.strip(), strict=False)
        return True
    except ValueError:
        return False


@dataclass
class FilterConfig:
    """Filter settings, loaded from the database before each analysis."""

    allowlist: list = field(default_factory=list)          # list of ip_network
    drop_broadcast: bool = True
    drop_multicast: bool = True
    noise_ports: tuple = DEFAULT_NOISE_PORTS


@dataclass
class FilterStats:
    """How many events each filter caught (shown on the run page)."""

    noise: int = 0
    allowlisted: int = 0


class EventFilter:
    def __init__(self, config: FilterConfig | None = None):
        self.config = config or FilterConfig()
        self.stats = FilterStats()

    def _ip(self, value: str):
        """Parse an address string; returns None if it is not a valid IP."""
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    def is_noise(self, event: FirewallEvent) -> bool:
        """True if the event is background chatter that should be dropped."""
        cfg = self.config
        dst = self._ip(event.dst_ip)
        if dst is not None:
            # Broadcast: 255.255.255.255, or an address ending in .255.
            # The ".255" test assumes a /24 network, which is the usual case
            # in home, school and lab networks.
            if cfg.drop_broadcast and (dst == _BROADCAST or event.dst_ip.endswith(".255")):
                return True
            # Multicast: check against the IPv4 or IPv6 range as appropriate.
            if cfg.drop_multicast and (dst in _MULTICAST_V4 if dst.version == 4 else dst in _MULTICAST_V6):
                return True
        # IGMP is the protocol devices use to join multicast groups.
        if event.proto == "IGMP" and cfg.drop_multicast:
            return True
        # Known housekeeping services (see DEFAULT_NOISE_PORTS above).
        if event.proto == "UDP" and event.dst_port in cfg.noise_ports:
            return True
        return False

    def is_allowlisted(self, event: FirewallEvent) -> bool:
        """True if the source address falls inside any allowlist entry."""
        src = self._ip(event.src_ip)
        if src is None:
            return False
        # The version check avoids comparing an IPv4 address with an IPv6 range.
        return any(src.version == net.version and src in net for net in self.config.allowlist)

    def classify(self, event: FirewallEvent) -> str:
        """Return 'noise', 'allowlisted' or 'ok' and update stats.

        The pipeline uses the answer like this:
          noise       -> thrown away
          allowlisted -> stored, but not given to the detection engine
          ok          -> stored and analysed
        Noise is checked first, so noise from a trusted host is still dropped.
        """
        if self.is_noise(event):
            self.stats.noise += 1
            return "noise"
        if self.is_allowlisted(event):
            self.stats.allowlisted += 1
            return "allowlisted"
        return "ok"
