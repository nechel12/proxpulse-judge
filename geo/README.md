# geo/ — directory for the .mmdb databases (mounted into the container read-only, not in git).
#
# Fastest, no keys needed:  bash scripts/download-dbip.sh
# Or place GeoLite2-City.mmdb / GeoLite2-ASN.mmdb here (a MaxMind account is needed).
# Licenses: DB-IP Lite — CC BY 4.0 (attribution required, https://db-ip.com),
# GeoLite2 — GeoLite EULA + aspects of CC BY-SA 4.0 (a MaxMind account is needed).
# After refreshing the databases, restart the container (the geo cache lives in memory).
# docker-compose mounts this directory read-only: the databases are downloaded on
# the host by the script, the entrypoint cannot write here.
