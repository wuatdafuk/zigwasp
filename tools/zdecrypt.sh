#!/usr/bin/env bash
# Dissect a zigwasp capture with Zigbee decryption enabled.
#
# Reads the network key from a file so it never appears on a command line, in
# shell history, or in terminal output. The file lives in the project directory
# (gitignored), not in $HOME. Create it once:
#     ssh <user>@<ha-host> python3 < tools/get-zha-key.py     # prints the key
#     printf '%s\n' 'aa:bb:..:ff' > .zha-network-key
#     chmod 600 .zha-network-key
#
# Usage: tools/zdecrypt.sh <capture.pcap> [extra tshark args...]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYFILE="${ZHA_KEYFILE:-$HERE/.zha-network-key}"
PCAP="${1:?usage: zdecrypt.sh <capture.pcap> [tshark args...]}"
shift || true
[ -r "$KEYFILE" ] || { echo "no key file at $KEYFILE (see header)" >&2; exit 1; }
KEY="$(head -n1 "$KEYFILE" | tr -d '[:space:]')"
[ -n "$KEY" ] || { echo "key file $KEYFILE is empty" >&2; exit 1; }
exec tshark -r "$PCAP" \
  -o "uat:zigbee_pc_keys:\"$KEY\",\"Normal\",\"zha\"" \
  "$@"
