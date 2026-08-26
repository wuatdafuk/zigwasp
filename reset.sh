#!/usr/bin/env bash
# Hard-reset the LPSTK via the XDS110's nRESET line.
#
# WHY: TI's ti_cc13x2.cfg uses "cortex_m reset_config vectreset", which resets
# only the CPU core. The oscillator and power domains survive, so if firmware
# wedges the 48 MHz oscillator (TI's oscillatorISR storming on IRQ 34), every
# warm reset inherits the wedged state and the radio never starts. Asserting
# nRESET gives a clean power-on-like reset. OpenOCD reports DAP errors as the
# debug power drops -- that is expected here, not a failure.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
openocd -f "$HERE/openocd/lpstk-cc1352r-srst.cfg" -c init -c "reset run" -c shutdown 2>&1 \
  | grep -viE "Invalid ACK|STICKY|unpowered|unexpected reset" || true
