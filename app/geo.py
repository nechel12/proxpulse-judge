"""Local .mmdb pool: GeoLite2 / DB-IP Lite, loaded into RAM, LRU-cached lookups."""
from __future__ import annotations

import functools
import ipaddress
import logging
import os
from pathlib import Path

log = logging.getLogger("judge.geo")

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError

    HAVE_GEOIP2 = True
except ImportError:  # pragma: no cover
    HAVE_GEOIP2 = False

GEO_DIR = Path(os.environ.get("GEO_DIR", "/app/geo"))

CITY_CANDIDATES = ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb")
COUNTRY_CANDIDATES = ("GeoLite2-Country.mmdb", "dbip-country-lite.mmdb")
ASN_CANDIDATES = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")


class GeoDB:
    def __init__(self, directory: Path = GEO_DIR) -> None:
        self.directory = directory
        self.city = None
        self.country = None
        self.asn = None
        self.sources: dict[str, str] = {}
        if not HAVE_GEOIP2:
            log.warning("geoip2 not installed, geo disabled")
            return
        self.city, city_src = self._open(CITY_CANDIDATES)
        self.country, country_src = self._open(COUNTRY_CANDIDATES)
        self.asn, asn_src = self._open(ASN_CANDIDATES)
        if city_src:
            self.sources["city"] = city_src
        if country_src:
            self.sources["country"] = country_src
        if asn_src:
            self.sources["asn"] = asn_src
        # glob fallback: any *-city*.mmdb / *-asn*.mmdb
        if self.city is None:
            for p in sorted(directory.glob("*-city*.mmdb")) + sorted(
                directory.glob("*city*.mmdb")
            ):
                try:
                    self.city = geoip2.database.Reader(
                        str(p), mode=geoip2.database.MODE_MEMORY
                    )
                    self.sources["city"] = p.name
                    break
                except Exception as e:  # noqa: BLE001
                    log.warning("cannot open %s: %s", p, e)
        log.info("geo sources: %s (dir=%s)", self.sources or "none", directory)

    def _open(self, names: tuple[str, ...]):
        for name in names:
            path = self.directory / name
            if path.exists():
                try:
                    reader = geoip2.database.Reader(
                        str(path), mode=geoip2.database.MODE_MEMORY
                    )
                    return reader, name
                except Exception as e:  # noqa: BLE001
                    log.warning("cannot open %s: %s", path, e)
        return None, None

    def mtime_key(self) -> float:
        """DB freshness marker — part of the lookup cache key."""
        mtimes = []
        for reader, name in (
            (self.city, self.sources.get("city")),
            (self.country, self.sources.get("country")),
            (self.asn, self.sources.get("asn")),
        ):
            if reader and name:
                try:
                    mtimes.append((self.directory / name).stat().st_mtime)
                except OSError:
                    pass
        return max(mtimes) if mtimes else 0.0

    def lookup(self, ip: str) -> dict:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"ip": ip, "error": "invalid ip"}
        return _cached_lookup(ip, self.mtime_key(), id(self))


@functools.lru_cache(maxsize=65536)
def _cached_lookup(ip: str, _mtime: float, _pool: int) -> dict:
    # NOTE: pool is resolved via the global singleton; _pool/_mtime only
    # participate in the cache key (fresh pool or new DB files => miss).
    return _lookup_uncached(ip)


_POOL = None  # set by init_pool()


def init_pool(directory: Path = GEO_DIR) -> GeoDB:
    global _POOL
    _POOL = GeoDB(directory)
    _cached_lookup.cache_clear()
    return _POOL


def _lookup_uncached(ip: str) -> dict:
    pool = _POOL
    out: dict = {"ip": ip}
    if pool is None or not HAVE_GEOIP2:
        out["error"] = "no db"
        return out
    city = country = asn = None
    if pool.city is not None:
        try:
            city = pool.city.city(ip)
        except AddressNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            out["city_error"] = str(e)[:80]
    if city is None and pool.country is not None:
        try:
            country = pool.country.country(ip)
        except AddressNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            out["country_error"] = str(e)[:80]
    if pool.asn is not None:
        try:
            asn = pool.asn.asn(ip)
        except AddressNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            out["asn_error"] = str(e)[:80]
    if city is not None:
        out.update(
            {
                "country": city.country.name,
                "country_code": city.country.iso_code,
                "city": city.city.name,
                "latitude": city.location.latitude,
                "longitude": city.location.longitude,
            }
        )
    elif country is not None:
        out.update(
            {"country": country.country.name, "country_code": country.country.iso_code}
        )
    if asn is not None:
        out.update(
            {
                "asn": asn.autonomous_system_number,
                "aso": asn.autonomous_system_organization,
            }
        )
    if len(out) == 1:  # only "ip"
        out["error"] = "not found"
    return out
