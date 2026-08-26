#!/usr/bin/env python3
"""
Wireshark extcap plugin for the zigwasp LPSTK-CC1352R 802.15.4 sniffer.

Reads the firmware's length-delimited records off the XDS110 serial port and
writes a PCAP stream (DLT 195, IEEE802_15_4_WITHFCS) to the FIFO Wireshark
gives us. Strictly passive: the firmware runs with auto-ACK disabled, so
nothing is ever transmitted into the network being observed.

Install: symlink into ~/.local/lib/wireshark/extcap/ and restart Wireshark.
"""
import argparse, glob, os, select, struct, sys, termios, time, tty

MAGIC = b'\xa7\x5a'
DLT_IEEE802_15_4_WITHFCS = 195
DEFAULT_PORT = '/dev/ttyACM0'
DEFAULT_CHANNEL = 15   # set to your Zigbee network channel (11-26)
BAUD = 115200


def pcap_header():
    # magic, ver 2.4, no tz correction, no sigfigs, snaplen, linktype
    return struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535,
                       DLT_IEEE802_15_4_WITHFCS)


def pcap_record(data, ts):
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack('<IIII', sec, usec, len(data), len(data)) + data


def parse(buf):
    """Pull complete records out of buf. Returns (frames, remaining_buf)."""
    out = []
    while True:
        i = buf.find(MAGIC)
        if i < 0:
            # keep a trailing byte in case a magic straddles the boundary
            buf = buf[-1:] if buf else buf
            break
        if len(buf) < i + 13:
            buf = buf[i:]
            break
        length = struct.unpack('<H', buf[i + 10:i + 12])[0]
        end = i + 12 + length + 1
        if len(buf) < end:
            buf = buf[i:]
            break
        rec = buf[i:end]
        if (sum(rec[2:12 + length]) & 0xFF) == rec[-1]:
            if length:
                dev_us = struct.unpack('<I', rec[6:10])[0]
                out.append((dev_us, bytes(rec[12:12 + length])))
            buf = buf[end:]
        else:
            # bad checksum: skip this magic and resynchronise
            buf = buf[i + 2:]
    return out, buf


class Serial:
    """Minimal raw serial port on stdlib only.

    Deliberately avoids pyserial: Wireshark resolves this script's interpreter
    via /usr/bin/env python3, which may not be the Python that has pyserial
    installed, and an extcap plugin that dies on ModuleNotFoundError is useless.
    """

    def __init__(self, port, baud):
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY)
        tty.setraw(self.fd)
        a = termios.tcgetattr(self.fd)
        speed = getattr(termios, 'B%d' % baud)
        a[2] = (a[2] | termios.CLOCAL | termios.CREAD)
        if hasattr(termios, 'CRTSCTS'):
            a[2] &= ~termios.CRTSCTS
        a[4] = speed
        a[5] = speed
        a[6][termios.VMIN] = 0
        a[6][termios.VTIME] = 0
        termios.tcsetattr(self.fd, termios.TCSANOW, a)

    def write(self, data):
        os.write(self.fd, data)

    def flush_input(self):
        termios.tcflush(self.fd, termios.TCIFLUSH)

    def read(self, n, timeout=0.2):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return b''
        try:
            return os.read(self.fd, n)
        except OSError:
            return b''

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


def resolve_port(requested):
    """Pick a usable serial port.

    Wireshark does not always populate string arguments from {default=...} --
    if the user never opens the interface options dialog, --port can arrive
    empty, which used to blow up with FileNotFoundError on ''. Fall back to the
    default, then to autodetecting an XDS110 CDC port.
    """
    cand = (requested or '').strip().strip('"').strip("'")
    if cand and os.path.exists(cand):
        return cand
    if cand:
        sys.stderr.write("zigwasp: %s not found, autodetecting\n" % cand)
    if os.path.exists(DEFAULT_PORT):
        return DEFAULT_PORT
    found = sorted(glob.glob('/dev/ttyACM*')) + sorted(glob.glob('/dev/ttyUSB*'))
    if found:
        sys.stderr.write("zigwasp: using %s\n" % found[0])
        return found[0]
    raise SystemExit("zigwasp: no serial port found (tried %r, %s, /dev/ttyACM*)"
                     % (cand, DEFAULT_PORT))


def do_capture(fifo, port, channel):
    ser = Serial(resolve_port(port), BAUD)
    time.sleep(0.3)
    ser.flush_input()
    ser.write(b'C' + bytes([channel]))
    time.sleep(0.3)
    ser.flush_input()

    anchor = [None]
    with open(fifo, 'wb', 0) as out:
        out.write(pcap_header())
        buf = b''
        while True:
            chunk = ser.read(4096)
            if chunk:
                buf += chunk
                frames, buf = parse(buf)
                for dev_us, frame in frames:
                    # Anchor the device's microsecond clock to host time on the
                    # first frame, so packets get distinct, correctly-spaced
                    # timestamps instead of all sharing the read-batch time.
                    if anchor[0] is None:
                        anchor[0] = (time.time(), dev_us)
                    host0, dev0 = anchor[0]
                    delta = (dev_us - dev0) & 0xFFFFFFFF
                    if delta > 0x80000000:      # device clock wrapped
                        delta -= 0x100000000
                    out.write(pcap_record(frame, host0 + delta / 1_000_000.0))


def main():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument('--extcap-interfaces', action='store_true')
    p.add_argument('--extcap-dlts', action='store_true')
    p.add_argument('--extcap-config', action='store_true')
    p.add_argument('--extcap-interface')
    p.add_argument('--extcap-version')
    p.add_argument('--capture', action='store_true')
    p.add_argument('--fifo')
    p.add_argument('--channel', type=lambda v: int(v) if str(v).strip() else DEFAULT_CHANNEL,
                   default=DEFAULT_CHANNEL)
    p.add_argument('--port', default='')
    p.add_argument('--extcap-capture-filter')
    p.add_argument('-h', '--help', action='store_true')
    args, _ = p.parse_known_args()

    if args.extcap_interfaces:
        print("extcap {version=1.0}{help=zigwasp LPSTK-CC1352R 802.15.4 sniffer}")
        print("interface {value=zigwasp}{display=zigwasp 802.15.4 sniffer (LPSTK-CC1352R)}")
        return

    if args.extcap_dlts:
        print(f"dlt {{number={DLT_IEEE802_15_4_WITHFCS}}}"
              "{name=IEEE802_15_4_WITHFCS}{display=IEEE 802.15.4 with FCS}")
        return

    if args.extcap_config:
        print("arg {number=0}{call=--channel}{display=Channel}"
              "{type=integer}{range=11,26}"
              f"{{default={DEFAULT_CHANNEL}}}"
              "{tooltip=IEEE 802.15.4 channel (11-26 = 2405-2480 MHz)}")
        print("arg {number=1}{call=--port}{display=Serial port}"
              f"{{type=string}}{{default={DEFAULT_PORT}}}"
              "{tooltip=XDS110 application UART}")
        return

    if args.capture:
        if not args.fifo:
            sys.exit("--capture requires --fifo")
        chan = args.channel if args.channel else DEFAULT_CHANNEL
        if not (11 <= chan <= 26):
            sys.exit("channel must be 11..26")
        args.channel = chan
        do_capture(args.fifo, args.port, args.channel)
        return

    p.print_help()


if __name__ == '__main__':
    main()
