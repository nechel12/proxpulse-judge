# geo/

The `.mmdb` databases go here; they are not in git. `docker-compose.yml`
mounts this folder read-only, so download them on the host:

- No key needed: `bash scripts/download-dbip.sh` (DB-IP Lite, CC BY 4.0,
  attribution with a link to <https://db-ip.com> required).
- Or put `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` here (a free MaxMind
  account; GeoLite EULA with aspects of CC BY-SA 4.0).

After new files arrive, restart the container: the geo cache lives in memory.
