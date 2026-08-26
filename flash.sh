#!/usr/bin/env bash
# Flash a Zephyr image to the LPSTK-CC1352R.
#
# Two board-specific quirks are handled here:
#
# 1. QUIESCE FIRST. Halting the CPU while the RF core is receiving leaves the
#    radio running underneath the reset CPU. The next boot's RF_open() then
#    inherits a live radio and TI's oscillatorISR storms on IRQ 34 forever --
#    a wedge that survives vectreset, SYSRESETREQ and even an AON_PMCTL
#    SYSRESET, clearing only on a physical power cycle. Sending 'Q' makes the
#    running sniffer bring its interface down first, so the halt is safe.
#    Harmless if the board is running something else or is already stalled.
#
# 2. RESTORE THE FACTORY CCFG. Zephyr's cc1352r_sensortag CCFG differs from
#    this board's (MODE_CONF 0xf3bbff3a vs factory 0xf1bbffff -- VDDR_CAP trim).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEX="${1:-$HERE/build/sniffer/zephyr/zephyr.hex}"
CCFG="$HERE/backup/lpstk-factory-ccfg.bin"
PORT="${PORT:-/dev/ttyACM0}"
[ -f "$HEX" ]  || { echo "no such image: $HEX" >&2; exit 1; }
[ -f "$CCFG" ] || { echo "missing factory CCFG: $CCFG" >&2; exit 1; }

if [ -w "$PORT" ]; then
  echo ">>> quiescing radio on $PORT"
  python3 - "$PORT" <<'PY' || true
import serial, sys, time
try:
    s = serial.Serial(sys.argv[1], 115200, timeout=1.0)
    time.sleep(0.3); s.reset_input_buffer()
    s.write(b'Q'); s.flush(); time.sleep(1.0)
    s.close()
except Exception as e:
    print(f"    (quiesce skipped: {e})")
PY
fi

echo ">>> programming $HEX"
openocd -f "$HERE/openocd/lpstk-cc1352r.cfg" \
  -c init -c halt \
  -c "program $HEX verify" \
  -c "flash write_image erase $CCFG 0x00057FA8 bin" \
  -c "verify_image $CCFG 0x00057FA8 bin" \
  -c "reset run" -c shutdown
echo ">>> done (factory CCFG restored)"
