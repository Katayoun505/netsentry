"""
geoip.py — IP-to-location resolution for NetSentry.

Uses a local MaxMind GeoLite2-City database for real public IPs.
Private / link-local / reserved IPs (e.g. our Kali test VM on a
Host-Only VirtualBox network) cannot be geolocated for real, since
they were never routed on the public internet. For those, we return
a clearly-flagged SIMULATED location so the dashboard/map still has
something to display during demos, without silently faking data.
"""

import ipaddress
import random
import hashlib
import geoip2.database
import geoip2.errors

_DB_PATH = "GeoLite2-City.mmdb"
_reader = geoip2.database.Reader(_DB_PATH)

# A small pool of plausible "attacker" cities used ONLY when the
# source IP is private/non-routable. Chosen to look realistic on a
# world map for demo purposes — never presented as real data.
_SIMULATED_LOCATIONS = [
    {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    {"country": "China", "city": "Shanghai", "lat": 31.2304, "lon": 121.4737},
    {"country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333},
    {"country": "Nigeria", "city": "Lagos", "lat": 6.5244, "lon": 3.3792},
    {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890},
]


def _is_public(ip_str: str) -> bool:
    """Return True only for addresses that are actually routable on
    the public internet (i.e. NOT private, link-local, loopback,
    reserved, or multicast)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_link_local
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_multicast
    )


def _stable_index(ip_str: str, bucket_count: int) -> int:
    """
    Deterministic, stable bucket index for a given IP string.
    Python's built-in hash() is randomized per process, so we use
    md5 instead purely to get a consistent number - no security
    purpose here, just consistent demo behavior.
    """
    digest = hashlib.md5(ip_str.encode()).hexdigest()
    return int(digest, 16) % bucket_count


def lookup_ip(ip_str: str) -> dict:
    """
    Resolve an IP to location info.

    Returns a dict:
        {
            "ip": "...",
            "country": "...",
            "city": "...",
            "lat": float,
            "lon": float,
            "simulated": bool
        }
    """
    if _is_public(ip_str):
        try:
            response = _reader.city(ip_str)
            return {
                "ip": ip_str,
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "simulated": False,
            }
        except geoip2.errors.AddressNotFoundError:
            pass  # fall through to simulated, e.g. very new/unlisted public IP

    # Private/link-local/reserved IP (our Kali VM, etc.) OR lookup miss.
    # Deterministic-ish pick so the SAME source IP always maps to the
    # SAME simulated city within a run, instead of jumping around.
    idx = _stable_index(ip_str, len(_SIMULATED_LOCATIONS))
    sim = _SIMULATED_LOCATIONS[idx]
    return {
        "ip": ip_str,
        "country": sim["country"],
        "city": sim["city"],
        "lat": sim["lat"],
        "lon": sim["lon"],
        "simulated": True,
    }