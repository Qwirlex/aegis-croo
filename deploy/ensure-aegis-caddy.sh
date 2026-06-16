#!/bin/sh
# Keep aegiscan.xyz present in the shared revertguard Caddy.
# If a revertguard redeploy recreated the Caddy container and dropped our route,
# re-apply it: take their CURRENT Caddyfile, append our aegiscan block, reload.
# Safe by design, it reuses whatever salescheduler config they have at the time.
CADDY=revertguard-caddy-1

# Already serving aegiscan? nothing to do.
docker exec "$CADDY" wget -qO- http://localhost:2019/config/ 2>/dev/null | grep -q aegiscan.xyz && exit 0

docker exec "$CADDY" sh -c '
cp /etc/caddy/Caddyfile /tmp/aegis-combined 2>/dev/null || : > /tmp/aegis-combined
printf "\naegiscan.xyz, www.aegiscan.xyz {\n  reverse_proxy 172.18.0.1:3000\n}\n" >> /tmp/aegis-combined
caddy reload --config /tmp/aegis-combined --adapter caddyfile --force
' >/dev/null 2>&1
