# This will import a file of CIC-IDS2017/GeneratedLabelledFlows/somefile.CSV into zeng_security database

#Run:     py import_cicids2017.py "C:\Users\fersh\Downloads\CIC IDS 2017\CSVs\GeneratedLabelledFlows\TrafficLabelling\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"

# problem on: 

import argparse
import csv
import getpass
import hashlib
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path


def normalized_feature_names(headers):
    names = []
    used = Counter()
    for header in headers[7:-1]:
        base = re.sub(r"[^a-z0-9]+", "_", header.strip().lower()).strip("_")
        used[base] += 1
        names.append(base if used[base] == 1 else f"{base}_{used[base]}")
    return names


def finite_number(value):
    if not value.strip():
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def optional_int(value):
    return int(value) if value.strip() else None


def flow_timestamp(value):
    if not value.strip():
        return None
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp: {value!r}")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_row(row, batch_id, row_number, feature_names, jsonb):
    features = {
        name: finite_number(value)
        for name, value in zip(feature_names, row[7:-1], strict=True)
    }
    return (
        batch_id,
        row_number,
        row[0].strip() or None,
        flow_timestamp(row[6]),
        row[1].strip() or None,
        optional_int(row[2]),
        row[3].strip() or None,
        optional_int(row[4]),
        optional_int(row[5]),
        row[-1].strip(),
        jsonb(features),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path, help="CSV from GeneratedLabelledFlows.zip")
    args = parser.parse_args()
    path = args.csv_path.expanduser().resolve()
    if not path.is_file():
        parser.error(f"File does not exist: {path}")

    # Delay the dependency import so parsing helpers can be checked independently.
    import psycopg
    from psycopg.types.json import Jsonb

    file_hash = sha256_file(path)  #TODO: changed encoding below this from utf-8-sig to latin-1 because of a character problem during import batch 9
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.reader(source)
        headers = next(reader)
        expected = (
            "Flow ID", "Source IP", "Source Port", "Destination IP",
            "Destination Port", "Protocol", "Timestamp",
        )
        if tuple(x.strip() for x in headers[:7]) != expected or headers[-1].strip() != "Label":
            raise ValueError("Expected a GeneratedLabelledFlows CSV with flow metadata and Label")
        feature_names = normalized_feature_names(headers)
        if len(set(feature_names)) != len(feature_names):
            raise ValueError("Two feature columns have the same normalized name")

        with psycopg.connect(
            dbname="zeng_security", host="localhost", port=5432,
            user="postgres", password=getpass.getpass("PostgreSQL password: "),
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, row_count FROM import_batches WHERE source_sha256 = %s", (file_hash,))
                existing = cur.fetchone()
                if existing:
                    print(f"Already imported: batch {existing[0]}, {existing[1]:,} rows")
                    return
                cur.execute(
                    "INSERT INTO import_batches (source_file, source_sha256, source_headers) "
                    "VALUES (%s, %s, %s) RETURNING id",
                    (path.name, file_hash, Jsonb(headers)),
                )
                batch_id = cur.fetchone()[0]
                counts = Counter()
                columns = (
                    "import_batch_id, source_row_number, source_flow_id, observed_at, "
                    "source_ip, source_port, destination_ip, destination_port, "
                    "protocol, original_label, features"
                )
                with cur.copy(f"COPY network_flows ({columns}) FROM STDIN") as copy:
                    for line_number, row in enumerate(reader, start=2):
                        if len(row) != len(headers):
                            raise ValueError(f"CSV line {line_number}: expected {len(headers)} columns, got {len(row)}")
                        try:
                            values = parse_row(row, batch_id, line_number, feature_names, Jsonb)
                        except (ValueError, OverflowError) as exc:
                            raise ValueError(f"CSV line {line_number}: {exc}") from exc
                        copy.write_row(values)
                        counts[row[-1].strip()] += 1
                        if sum(counts.values()) % 100_000 == 0:
                            print(f"Prepared {sum(counts.values()):,} flows...")
                cur.execute(
                    "UPDATE import_batches SET row_count = %s WHERE id = %s",
                    (sum(counts.values()), batch_id),
                )
                print(f"Imported {sum(counts.values()):,} flows in batch {batch_id}:")
                for label, count in counts.items():
                    print(f"  {label}: {count:,}")
            # The batch and flows are committed together; on error both roll back.


if __name__ == "__main__":
    main()
