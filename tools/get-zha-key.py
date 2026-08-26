#!/usr/bin/env python3
"""Print the ZHA network key (and channel/PAN) from Home Assistant's zigbee.db.

Run it ON the HA host, or pipe it there over ssh:

    ssh <user>@<ha-host> python3 < tools/get-zha-key.py

Prints the network key so it can be pasted into Wireshark:
Edit -> Preferences -> Protocols -> ZBEE NWK -> Pre-configured Keys.
Opens the database read-only; it does not modify anything.
"""
import json
import sqlite3
import sys

DB = "/opt/ha/config/zigbee.db"


def main():
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    except sqlite3.Error as e:
        sys.exit(f"cannot open {DB}: {e}")

    cur = con.cursor()
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")
        if "network_backup" in r[0]]

    newest = None
    for t in sorted(tables):
        try:
            rows = list(cur.execute(f"SELECT * FROM {t} ORDER BY rowid DESC LIMIT 1"))
        except sqlite3.Error:
            continue
        for row in rows:
            for value in row:
                if isinstance(value, str) and value.strip().startswith("{"):
                    try:
                        info = json.loads(value).get("network_info", {})
                    except json.JSONDecodeError:
                        continue
                    if info.get("network_key", {}).get("key"):
                        newest = info

    if not newest:
        sys.exit("no network backup with a key found in zigbee.db")

    print(f"channel        : {newest.get('channel')}")
    print(f"pan_id         : {newest.get('pan_id')}")
    print(f"extended_pan_id: {newest.get('extended_pan_id')}")
    print(f"key_seq        : {newest['network_key'].get('seq')}")
    print()
    print("network key (paste into Wireshark, Byte Order = Normal):")
    print(f"  {newest['network_key']['key']}")

    tclk = newest.get("tc_link_key", {}).get("key")
    if tclk:
        print()
        print("trust centre link key:")
        print(f"  {tclk}")


if __name__ == "__main__":
    main()
