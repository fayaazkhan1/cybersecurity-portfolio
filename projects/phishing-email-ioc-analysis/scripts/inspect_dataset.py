"""
inspect_dataset.py

Purpose:
Inspect the structure of the phishing-email dataset without printing
email bodies, URLs, or other potentially malicious content.

The script:
1. Confirms the dataset exists.
2. Raises Python's CSV field-size limit for large email bodies.
3. Displays column names.
4. Counts total records.
5. Shows the distribution of dataset labels.
"""

import csv
from collections import Counter
from pathlib import Path


# Location of the raw phishing dataset.
DATASET_PATH = Path("data/raw/Nazario.csv")


# Python's csv module normally limits a single CSV field to about 128 KB.
#
# Email datasets can contain large HTML bodies or encoded content inside
# a single field, so we raise the limit to 10 MB.
#
# We use a bounded value instead of making the limit unlimited.
csv.field_size_limit(10 * 1024 * 1024)


# Confirm the dataset exists before attempting to open it.
if not DATASET_PATH.exists():
    print(f"Error: Dataset not found: {DATASET_PATH}")
    raise SystemExit(1)


# Counter will store how many records belong to each dataset label.
#
# Example:
#
# {
#     "1": 1000,
#     "0": 500
# }
#
# We are NOT assuming yet what those labels mean.
label_counts = Counter()

row_count = 0


with DATASET_PATH.open(
    "r",
    encoding="utf-8",
    errors="replace",
    newline=""
) as csv_file:

    reader = csv.DictReader(csv_file)

    print("Dataset columns:")
    print("----------------")

    for column_name in reader.fieldnames or []:
        print(f"- {column_name}")

    # Process one email record at a time.
    #
    # This does not print the email body or URLs.
    for row in reader:
        row_count += 1

        # Safely retrieve the label field.
        #
        # If a row somehow has no label, "<missing>" will be recorded
        # instead of causing the program to crash.
        label = row.get("label", "<missing>")

        label_counts[label] += 1


print()
print(f"Dataset: {DATASET_PATH}")
print(f"Total records: {row_count}")

print()
print("Label distribution:")
print("-------------------")

for label, count in sorted(label_counts.items()):
    print(f"{label!r}: {count}")
