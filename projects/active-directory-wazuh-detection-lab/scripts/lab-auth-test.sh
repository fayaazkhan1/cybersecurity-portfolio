#!/usr/bin/env bash

# Authorized lab use only.
# Use only against systems and accounts you own.
# Replace the placeholder with an intentionally incorrect, lab-only password.

set -u

DOMAIN="BLUECORP"
SERVER="192.168.56.10"
WRONG_PASSWORD="[REPLACE_WITH_LAB_ONLY_INVALID_PASSWORD]"
USER_FILE="${HOME}/lab-users.txt"
LOG_FILE="${HOME}/lab-auth-test-results.log"

if [[ ! -f "${USER_FILE}" ]]; then
    echo "Error: User file not found: ${USER_FILE}"
    exit 1
fi

echo "Controlled authentication simulation started: $(date -Is)" | tee "${LOG_FILE}"

while IFS= read -r USER; do
    [[ -z "${USER}" ]] && continue

    echo "Generating one expected authentication failure for ${DOMAIN}/${USER} at $(date -Is)" | tee -a "${LOG_FILE}"

    smbclient "//${SERVER}/SYSVOL" \
        -U "${DOMAIN}/${USER}%${WRONG_PASSWORD}" \
        -c "ls" >>"${LOG_FILE}" 2>&1

    sleep 8
done < "${USER_FILE}"

echo "Controlled authentication simulation finished: $(date -Is)" | tee -a "${LOG_FILE}"
