#!/usr/bin/env bash
#
# nuclear-user-removal.sh
# Deletes EVERY user with UID >= 1000 on the system
# No confirmation. No mercy. Kills processes first.
#
# Intended for Metasploitable3 Ubuntu hardening practice only.
# YOU HAVE BEEN WARNED.
#

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root" >&2
    exit 1
fi

echo "Starting nuclear user deletion (UID >= 1000)"
echo "Current time: $(date)"
echo "This cannot be undone without restore."

# Step 1: Collect all human-ish users (UID >= 1000)
users_to_nuke=()
while IFS=: read -r username _ uid _ _ _ shell; do
    if (( uid >= 1000 && uid < 65534 )); then
        # Skip nobody/nfsnobody style accounts if they exist
        if [[ "$username" != "nobody" && "$username" != "nfsnobody" ]]; then
            users_to_nuke+=("$username")
        fi
    fi
done < /etc/passwd

if [[ ${#users_to_nuke[@]} -eq 0 ]]; then
    echo "No users with UID >= 1000 found. Nothing to do."
    exit 0
fi

echo "Found ${#users_to_nuke[@]} users to delete:"
printf '  %s\n' "${users_to_nuke[@]}"
echo ""

# Step 2: Brutally kill everything they own
echo "Killing all processes owned by target users..."
for u in "${users_to_nuke[@]}"; do
    pkill -u "$u" -9 2>/dev/null || true
done

sleep 3   # give processes a moment to actually die

# Step 3: Delete users + home + mail
echo "Deleting users..."
deleted=0
for u in "${users_to_nuke[@]}"; do
    if id "$u" &>/dev/null; then
        if userdel -r -f "$u" 2>/dev/null; then
            echo "  deleted: $u"
            ((deleted++))
        else
            echo "  FAILED: $u  (still locked?)"
        fi
    fi
done

echo ""
echo "Finished."
echo "Deleted: $deleted / ${#users_to_nuke[@]} users"
echo "Remaining non-system users:"
awk -F: '$3 >= 1000 && $3 < 65534 {print "  " $1 " (UID " $3 ")"}' /etc/passwd || echo "  (none)"

echo ""
echo "Done. Re-check your access NOW before closing this session."
echo "If you are locked out → reboot to snapshot or use console recovery."
