#!/bin/bash

MASTER_FILE="master_file.yar"
TMP_FILE="master_file_tmp.yar"
BACKUP_FILE="master_file.yar.bak"

# Backup the original master file
cp "$MASTER_FILE" "$BACKUP_FILE"


# Append the contents of master_file_tmp.yar
cat "$TMP_FILE" > master_file_updated.yar

# Keep only "custom" rules and remove "/app/transform/yara/rules/0PSWAT_fsYara/"
grep 'include "/app/transform/yara/rules/custom/' "$MASTER_FILE" >> master_file_updated.yar

# Replace the original master file
mv master_file_updated.yar "$MASTER_FILE"

echo "Updated $MASTER_FILE, backup saved as $BACKUP_FILE"
