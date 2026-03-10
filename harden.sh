#!/usr/bin/env bash
#
# delete-metasploitable-users.sh
# Removes the intentional weak "human" users from Metasploitable3 Ubuntu
# (Star Wars themed accounts with guessable passwords)
#
# Usage: sudo bash delete-metasploitable-users.sh
#        or curl ... | sudo bash
#

set -euo pipefail

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' N='\033[0m'

log_i() { echo -e "${G}[INFO]${N} $1"; }
log_w() { echo -e "${Y}[WARN]${N} $1"; }
log_e() { echo -e "${R}[ERROR]${N} $1"; }

check_root() {
  [[ $EUID -eq 0 ]] || { log_e "This script must be run as root (sudo)."; exit 1; }
}

# Exact list from Metasploitable3 repo (users.rb) + your screenshot
# (han-solo and han_solo both appear in some builds → we cover both)
METASPLOIT_USERS=(
  leia_organa
  luke_skywalker
  han_solo
  han-solo
  artoo_detoo
  c_three_pio
  ben_kenobi
  darth_vader
  anakin_skywalker
  jarjar_binks
  lando_calrissian
  boba_fett
  jabba_hutt
  greedo
  chewbacca
  kylo_ren
)

to_delete=()

check_root

log_w "================================================================"
log_w "!!! DANGEROUS: Removing Metasploitable3 weak human users !!!"
log_w "This will permanently delete the following users (if they exist):"
log_w "  home dirs, mail spools, /etc/passwd & /etc/group entries"
log_w "================================================================"

echo -e "${Y}Planned deletions:${N}"
for user in "${METASPLOIT_USERS[@]}"; do
  if id "$user" >/dev/null 2>&1; then
    echo "  - $user"
    to_delete+=("$user")
  else
    echo "  - $user (already gone or never existed)"
  fi
done

if [[ ${#to_delete[@]} -eq 0 ]]; then
  log_i "No matching weak users found. Nothing to do."
  exit 0
fi

echo
log_w "This is IRREVERSIBLE without full backup."
read -p "Type YES (all caps) to DELETE these users: " confirm

if [[ "$confirm" != "YES" ]]; then
  log_i "Aborted. No users were deleted."
  exit 0
fi

deleted=0
failed=0

for user in "${to_delete[@]}"; do
  log_i "Deleting user: $user"
  # -r = remove home dir and mail spool
  # -f = force (ignore errors if files/processes missing)
  if userdel -r -f "$user" 2>/dev/null; then
    ((deleted++))
    log_i "  → Deleted successfully."
  else
    ((failed++))
    log_e "  → Failed to delete $user"
    log_w "     Possible reasons: logged in, running processes, or file locks."
    log_w "     Try:   sudo pkill -u $user ; sudo userdel -r -f $user"
  fi
done

log_i "Summary: $deleted user(s) deleted, $failed failed."

if [[ $failed -gt 0 ]]; then
  log_w "Some deletions failed. Check 'ps aux | grep <username>' or 'w' for active sessions."
  log_w "You may need to kill processes first, then rerun."
fi

log_i "Done. These weak credential-based attack vectors are now gone (or mostly gone)."
log_i "Consider also locking shells on any remaining users you want to keep:"
log_i "  sudo usermod -s /usr/sbin/nologin <username>"
