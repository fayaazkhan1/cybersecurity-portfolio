#!/usr/bin/env bash

# Authorized lab use only.
# Use only against systems and accounts you own.

set -uo pipefail

DOMAIN="BLUECORP"
SERVER="192.168.56.10"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
USER_FILE="${SCRIPT_DIR}/lab-users.txt"
LOG_FILE="${SCRIPT_DIR}/lab-auth-test-results.log"

if ! command -v smbclient >/dev/null 2>&1; then
    echo "Error: smbclient is not installed."
    echo "Install it with: sudo apt install smbclient"
    exit 1
fi

if [[ ! -f "${USER_FILE}" ]]; then
    echo "Error: User file not found: ${USER_FILE}"
    exit 1
fi

read -rsp "Enter an intentionally invalid lab-only password: " WRONG_PASSWORD
echo

if [[ -z "${WRONG_PASSWORD}" ]]; then
    echo "Error: Password cannot be empty."
    exit 1
fi

echo "Controlled authentication simulation started: $(date -Is)" |
    tee "${LOG_FILE}"

while IFS= read -r USER; do
    [[ -z "${USER}" ]] && continue

    echo "Generating one expected authentication failure for ${DOMAIN}/${USER} at $(date -Is)" |
        tee -a "${LOG_FILE}"

    smbclient "//${SERVER}/SYSVOL" \
        -U "${DOMAIN}/${USER}%${WRONG_PASSWORD}" \
        -c "ls" >>"${LOG_FILE}" 2>&1

    sleep 8
done < "${USER_FILE}"

unset WRONG_PASSWORD

echo "Controlled authentication simulation finished: $(date -Is)" |
    tee -a "${LOG_FILE}"
