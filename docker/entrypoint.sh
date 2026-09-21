#!/bin/sh
# Container entrypoint of perch-collector.
#
# A collector that dials a controller (PERCH_COLLECTOR_SERVER_URL set, any
# transport but poll) authenticates its WebSocket with its own API key, and an
# adopted collector has to present the same key after every restart. When no
# key is given, generate one on first start and keep it in the state directory
# (a volume in the compose file), the way the OpenWrt package keeps it in UCI.
# The instance id lives in the same directory.
set -eu

STATE_DIR="${PERCH_COLLECTOR_STATE_DIR:-/var/lib/perch-collector}"
server_url="${PERCH_COLLECTOR_SERVER_URL:-${GOCOLLECTOR_SERVER_URL:-}}"
api_key="${PERCH_COLLECTOR_API_KEY:-${GOCOLLECTOR_API_KEY:-}}"
transport="${PERCH_COLLECTOR_TRANSPORT:-${GOCOLLECTOR_TRANSPORT:-auto}}"

if [ -n "$server_url" ] && [ -z "$api_key" ] && [ "$transport" != "poll" ]; then
	key_file="$STATE_DIR/api-key"
	if [ ! -s "$key_file" ]; then
		mkdir -p "$STATE_DIR"
		umask 077
		od -An -tx1 -N16 /dev/urandom | tr -d ' \n' > "$key_file.tmp"
		mv "$key_file.tmp" "$key_file"
		echo "perch-collector: generated an API key in $key_file" \
			"(fingerprint $(tr -d '\n' < "$key_file" | sha256sum | cut -c1-8), compare it in Settings -> Collectors before adopting)"
	fi
	PERCH_COLLECTOR_API_KEY="$(tr -d '\n' < "$key_file")"
	export PERCH_COLLECTOR_API_KEY
fi

exec perch-collector "$@"
