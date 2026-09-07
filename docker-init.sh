#!/bin/sh
set -e

CONF=/data/config.ini

umask 0000

if [ ! -f "$CONF" ] || [ -n "$S2L_RESET_CONFIG" ]; then
	echo ">>> writing $CONF from the environment"
	cat >"$CONF" <<EOF
stmp_listen=${STMP_LISTEN:-0.0.0.0:25}
stmp_tls_listen=${STMP_TLS_LISTEN:-}
stmp_hostname=${STMP_HOSTNAME:-stmp2log}
stmp_user=${STMP_USER:-}
stmp_pass=${STMP_PASS:-}
stmp_maxsize=${STMP_MAXSIZE:-10M}

data=/data
web_listen=${WEB_LISTEN:-0.0.0.0:8025}
web_pass=${WEB_PASS:-}
web_path=${WEB_PATH:-stmp2log}
push_url=${PUSH_URL:-}

max_entries=${MAX_ENTRIES:-5000}
max_days=${MAX_DAYS:-0}
keep_raw=${KEEP_RAW:-0}
keep_attachments=${KEEP_ATTACHMENTS:-0}
retry_queue=${RETRY_QUEUE:-0}
EOF
fi

chmod 0777 /data 2>/dev/null || true
chmod 0666 "$CONF" 2>/dev/null || true

if ! grep -q '^web_pass=..*' "$CONF"; then
	echo ">>> WARNING: web_pass is empty, the web UI has no login (set -e WEB_PASS=...)"
fi

exec stmp2log -c "$CONF" ${S2L_ARGS:-}
