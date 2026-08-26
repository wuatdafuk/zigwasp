# zigwasp

IEEE 802.15.4 / Zigbee sniffer on an **LPSTK-CC1352R**, driven by a standalone
XDS110 probe. Firmware is Zephyr 4.4.2; the host side emits PCAP for Wireshark.

## Capture

```sh
./host/zigwasp-extcap.py --capture --fifo /tmp/z.pcap --channel 15
# live into Wireshark:
./host/zigwasp-extcap.py --capture --fifo /dev/stdout --channel 15 | wireshark -k -i -
```

## Build and flash

```sh
export ZEPHYR_BASE=$PWD/zephyrproject/zephyr
export ZEPHYR_SDK_INSTALL_DIR=$PWD/zephyr-sdk-1.0.1
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
zephyrproject/.venv/bin/west build -p always -b cc1352r_sensortag \
    -d build/sniffer apps/sniffer
./flash.sh                      # quiesces the radio, programs, restores CCFG
```

Always flash with `./flash.sh`. Halting the CPU while the radio is receiving
wedges the oscillator in a way that survives every software reset and needs a
physical power cycle; `flash.sh` sends `'Q'` first to stop the radio cleanly.

## Wireshark GUI

The extcap plugin is symlinked into both extcap directories:

```
~/.local/lib/wireshark/extcap/zigwasp-extcap.py
/usr/lib/x86_64-linux-gnu/wireshark/extcap/zigwasp-extcap.py
```

"zigwasp 802.15.4 sniffer (LPSTK-CC1352R)" appears in the interface list; the
gear icon sets Channel (default 15) and Serial port.

Wireshark here is the **Flatpak** build (`org.wireshark.Wireshark`), which has
two implications:

- It runs extcap plugins under its own Python, which cannot see apt/pip modules.
  `host/zigwasp-extcap.py` therefore uses **only the standard library**
  (`termios`/`select`, not pyserial). Do not reintroduce third-party imports.
- Its sandbox hides `/dev` by default, so the serial port is invisible inside it.
  Grant access once:

  ```sh
  flatpak override --user --device=all org.wireshark.Wireshark
  # revert: flatpak override --user --reset org.wireshark.Wireshark
  ```

  This writes `~/.local/share/flatpak/overrides/org.wireshark.Wireshark`, the
  same file Flatseal edits -- so it appears in Flatseal under
  Wireshark -> Device -> "All devices", and can be toggled there instead.

The plugin also tolerates Wireshark passing empty `--port`/`--channel` (it does
this unless you open the interface options dialog) by falling back to the
defaults and then autodetecting `/dev/ttyACM*`.

## Serial protocol (115200 8N1 on the XDS110 UART)

Device to host, little-endian:

| field | size | notes |
|---|---|---|
| magic | 2 | `A7 5A` |
| version | 1 | 1 |
| channel | 1 | 11..26 |
| rssi | 1 | int8 dBm |
| lqi | 1 | |
| timestamp | 4 | microseconds since boot |
| length | 2 | |
| frame | n | MAC frame including FCS |
| checksum | 1 | sum of bytes after magic, mod 256 |

Host to device: `C <ch>` set channel, `P` ping, `Q` quiesce radio,
`R` clean reboot.

## Layout

| path | what |
|---|---|
| `apps/sniffer/` | firmware |
| `apps/radio_test/` | minimal radio bring-up test |
| `host/zigwasp-extcap.py` | serial to PCAP / Wireshark extcap |
| `openocd/` | XDS110 config + OpenOCD `XDS_SET_SUPPLY` patch |
| `zephyr-promisc.patch` | driver patch: promiscuous + passive |
| `flash.sh`, `reset.sh` | flash / hard reset helpers |
| `backup/` | factory CCFG (committed); full flash dump (local only) |

`backup/lpstk-factory-flash.bin` is deliberately **not** in version control: a
full flash readout includes the device's NV storage, which can contain Zigbee
network keys if the board was ever commissioned, plus its unique IEEE address.
It is kept on disk as a restore image. Recreate it with:

```sh
openocd -f openocd/lpstk-cc1352r.cfg -c init -c halt \
  -c "dump_image backup/lpstk-factory-flash.bin 0x00000000 0x58000" -c shutdown
```

Restore with `./flash.sh backup/lpstk-factory-flash.bin`.

The sniffer is strictly passive: auto-ACK is disabled in the driver patch, so it
never transmits into the network it observes.

## Local patches (not upstream)

- **OpenOCD**: this XDS110 pod rejects `XDS_SET_SUPPLY` (error -267), which
  aborts `init` in 0.12.0 and upstream master. Patched build in `/usr/local`;
  patch in `openocd/`.
- **Zephyr cc13xx driver**: adds `IEEE802154_HW_PROMISC`, implements
  `IEEE802154_CONFIG_PROMISCUOUS` (`frameFiltEn=0`, `autoAckEn=0`), and sets
  `bAutoFlushCrc=0` / `bAutoFlushIgn=0` to keep corrupt and filtered frames.
- **`CONFIG_NET_L2_ETHERNET=y`** is required: Zephyr's `promisc_mode_set()`
  returns `-ENOTSUP` unless Ethernet L2 is built, regardless of what the
  802.15.4 L2 advertises. No Ethernet interface is created.
