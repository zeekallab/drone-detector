#!/usr/bin/env python3
"""Convert FAA Remote ID serial lists to the Zeek TSV read by DroneManufacturer::model_file.

Input: CSV exports in the jlrjr/faa-rid-lookup layout (FAA "Declaration of
Compliance" accepted Remote ID serials):
  serial ranges:  serial_start, serial_end, make, model, status, deleted, ...
  exact serials:  serial_number, make, model, status, deleted, ...

Only rows with status "accepted" and deleted != 1 are kept.

Usage:
  python3 tools/faa_to_zeek.py --ranges serial_ranges.csv --exact exact_serials.csv \\
      -o remoteid-serials.tsv
Then on the sensor:
  redef DroneManufacturer::model_file = "/path/to/remoteid-serials.tsv";
Zeek re-reads the file when it changes, so replacing it updates matching live.
"""
import argparse
import csv
import os
import sys
import tempfile


def clean(v):
    v = ' '.join((v or '').split())  # no tabs/newlines inside a TSV field
    return v if v else '-'           # '-' is Zeek's unset marker


def rows(path, start_col, end_col):
    with open(path, newline='', encoding='utf-8-sig') as f:
        for r in csv.DictReader(f):
            if (r.get('status') or '').strip().lower() != 'accepted' or (r.get('deleted') or '0').strip() == '1':
                continue
            start = (r.get(start_col) or '').strip().upper()
            end = (r.get(end_col) or '').strip().upper()
            make = clean(r.get('make'))
            if len(start) < 5 or len(start) != len(end) or make == '-':
                continue
            yield start, end, make, clean(r.get('model'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ranges', help='serial ranges CSV')
    ap.add_argument('--exact', help='exact serials CSV')
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args()
    if not a.ranges and not a.exact:
        ap.error('give --ranges and/or --exact')
    out = []
    if a.ranges:
        out += rows(a.ranges, 'serial_start', 'serial_end')
    if a.exact:
        out += rows(a.exact, 'serial_number', 'serial_number')
    out = sorted(set(out))
    # Write atomically so a re-reading Zeek never sees a half-written file.
    d = os.path.dirname(os.path.abspath(a.output))
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.remoteid-', suffix='.tsv')
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write('#separator \\x09\n#fields\tserial_start\tserial_end\tmake\tmodel\n')
        for r in out:
            f.write('\t'.join(r) + '\n')
    os.replace(tmp, a.output)
    print(f'wrote {len(out)} rows to {a.output}', file=sys.stderr)


if __name__ == '__main__':
    main()
