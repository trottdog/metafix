#!/usr/bin/env bash
#
# Linux Server Hardening Script (Updated for Metasploitable3 Common Vulns)
# Hardens against common weaknesses: open ports, MySQL misconfigs, unused services, etc.
# Allows web (80/443), FTP (21), SSH (22).
# Compatible with: Debian/Ubuntu, RHEL/CentOS/AlmaLinux, Fedora.
# Usage: sudo bash harden.sh [rollback [TIMESTAMP]]
#   - No args: Apply hardening.
#   - rollback: Restore from latest backup.
#   - rollback TIMESTAMP: Restore from specific backup (e.g., sshd_config.20260310_111500).
#

set -euo pipefail

readonly SSHD_CONFIG='/etc/ssh/sshd_config'
readonly BACKUP_DIR='/etc/security/backup'  # Changed dir for broader backups
readonly SSHD_RUNTIME_DIR='/run/sshd'
readonly SCRIPT_NAME="${0##*/}"

readonly FAIL2BAN_JAIL='sshd'
readonly FAIL2BAN_MAXRETRY=3
readonly FAIL2BAN_BANTIME=3600
readonly FAIL2BAN_FINDTIME=600
readonly FAIL2BAN_IGNOREIP='127.0.0.1/8 ::1'
readonly FAIL2BAN_JAIL_D='/etc/fail2ban/jail.d'
readonly FAIL2BAN_JAIL_CONF="${FAIL2BAN_JAIL_D}/sshd-hardening.conf"
readonly ADMIN_CREDS_FILE='/root/.new_admin_credentials'
readonly FIREWALL_TCP_PORTS='21 22 80 443'  # Allowed: FTP, SSH, HTTP, HTTPS
readonly VULN_PORTS_TO_DROP='135 139 445 161 3306 5432 6667 8080 8180 9200 4848 8585'  # Common Metasploitable3 vuln ports (RPC, SMB, SNMP, MySQL, PG, IRC, Tomcat, Jenkins, ES, GlassFish, phpMyAdmin)

readonly R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' N='\033[0m'

SSH_SERVICE='' PKG_MGR='' ADMIN_GROUP=''
HARDENING_APPLIED=0

# Logging functions
log_i() { echo -e "${G}[INFO]${N} $1"; }
log_w() { echo -e "${Y}[WARN]${N} $1"; }
log_e() { echo -e "${R}[ERROR]${N} $1"; }

# Check root
check_root() {
  [[ $EUID -eq 0 ]] || { log_e "Run as root or with sudo."; exit 1; }
}

# Generate random string
random_bytes() {
  local len="${1:-12}" cs="${2:-a-zA-Z0-9}"
  LC_ALL=C tr -dc "$cs" < /dev/urandom 2>/dev/null | head -c "$len"
}

# Get admin group (sudo or wheel)
get_admin_group() {
  [[ -n "${ADMIN_GROUP:-}" ]] && { echo "$ADMIN_GROUP"; return; }
  if getent group sudo >/dev/null; then ADMIN_GROUP='sudo'; elif getent group wheel >/dev/null; then ADMIN_GROUP='wheel'; fi
  echo "${ADMIN_GROUP:-}"
}

# Check for existing non-root admin
has_existing_admin_user() {
  local group members u uid
  group=$(get_admin_group)
  [[ -z "$group" ]] && return 1
  members=$(getent group "$group" 2>/dev/null | cut -d: -f4 | tr ',' ' ')
  for u in $members; do
    [[ -z "$u" || "$u" == "root" ]] && continue
    uid=$(id -u "$u" 2>/dev/null)
    [[ -n "$uid" && "$uid" -ne 0 ]] && return 0
  done
  return 1
}

# Get package manager
get_pkg_mgr() {
  [[ -n "${PKG_MGR:-}" ]] && { echo "$PKG_MGR"; return; }
  for p in apt-get dnf yum zypper; do
    command -v "$p" >/dev/null && { PKG_MGR=$p; echo "$PKG_MGR"; return; }
  done
  echo ""
}

# Install package
install_pkg() {
  local name="$1" update="${2:-}" pkg
  pkg=$(get_pkg_mgr)
  [[ -z "$pkg" ]] && { log_e "Unsupported package manager."; return 1; }
  export DEBIAN_FRONTEND=noninteractive
  case "$pkg" in
    apt-get) [[ -n "$update" ]] && apt-get update -qq; apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$name" ;;
    dnf|yum) "$pkg" install -y "$name" ;;
    zypper) zypper install -y "$name" ;;
    *) return 1 ;;
  esac
}

# Run service action (stop/disable/restart)
run_svc() {
  local name="$1" action="${2:-restart}" svc_action="restart"
  if command -v systemctl >/dev/null; then
    systemctl "$action" "$name" 2>/dev/null && return 0
  fi
  [[ "$action" == "enable" || "$action" == "disable" ]] && return 1
  [[ "$action" == "start" ]] && svc_action="start"
  [[ "$action" == "stop" ]] && svc_action="stop"
  command -v service >/dev/null && service "$name" "$svc_action" 2>/dev/null
}

# Get SSH service name
get_ssh_service() {
  [[ -n "${SSH_SERVICE:-}" ]] && { echo "$SSH_SERVICE"; return; }
  local u
  u=$(systemctl list-units --type=service --state=active --no-legend 2>/dev/null | awk '$1~/^ssh(d)?\.service$/ {sub(/\.service$/,"",$1); print $1; exit}')
  if [[ -n "$u" ]]; then SSH_SERVICE=$u; else SSH_SERVICE='ssh'; command -v systemctl >/dev/null && systemctl is-active sshd >/dev/null && SSH_SERVICE='sshd'; fi
  echo "$SSH_SERVICE"
}

# Create non-root admin if needed
create_admin_user() {
  if has_existing_admin_user; then log_i "Existing admin user found. Skipping."; return 0; fi
  if [[ -f "$ADMIN_CREDS_FILE" ]]; then
    username=$(head -n1 "$ADMIN_CREDS_FILE" 2>/dev/null)
    [[ -n "$username" ]] && id -u "$username" >/dev/null && { log_i "Admin exists: $username."; return 0; }
  fi
  username="adm_$(random_bytes 10 'a-zA-Z0-9')"
  password=$(random_bytes 20 'a-zA-Z0-9!@#$%&*+=')
  id "$username" >/dev/null && { log_w "User $username exists. Skipping."; return 0; }
  useradd -m -s /bin/bash "$username" || { log_e "Failed to create $username"; return 1; }
  echo "$username:$password" | chpasswd || { log_e "Failed to set password"; userdel -r "$username" 2>/dev/null; return 1; }
  group=$(get_admin_group)
  [[ -n "$group" ]] && usermod -aG "$group" "$username"
  printf '%s\n' "$username" "$password" >"$ADMIN_CREDS_FILE"
  chmod 600 "$ADMIN_CREDS_FILE"
  log_i "New admin: $username (creds in $ADMIN_CREDS_FILE). Use this for future logins with SSH keys."
}

# DANGEROUS: Remove all other human (non-system) users except the current one
remove_other_human_users() {
  local current_uid current_user human_users uid_min uid_max user line

  check_root

  current_uid=$(id -u)
  current_user=$(id -un)

  log_w "===================================================================="
  log_w "!!! DANGEROUS OPERATION: Removing all OTHER human users !!!"
  log_w "Current user: ${current_user} (UID ${current_uid})"
  log_w "This will delete ALL users with UID >=1000 (except current if applicable)"
  log_w "Their home directories, mail spools, and /etc/passwd/group entries WILL BE REMOVED."
  log_w "This is IRREVERSIBLE without full system backup."
  log_w "===================================================================="

  # Get UID_MIN / UID_MAX from /etc/login.defs (fallback to 1000/60000)
  uid_min=$(grep -E '^UID_MIN' /etc/login.defs | awk '{print $2}' || echo 1000)
  uid_max=$(grep -E '^UID_MAX' /etc/login.defs | awk '{print $2}' || echo 60000)

  # Collect human users: UID >= uid_min, <= uid_max, not nobody, has real shell
  human_users=()
  while IFS=: read -r user _ uid _ _ _ shell; do
    [[ -z "$user" || "$user" == "nobody" ]] && continue
    [[ "$uid" -lt "$uid_min" || "$uid" -gt "$uid_max" ]] && continue
    [[ "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" || -z "$shell" ]] && continue

    # Skip current user (though root is UID 0 anyway)
    [[ "$user" == "$current_user" ]] && continue

    human_users+=("$user")
  done < /etc/passwd

  if [[ ${#human_users[@]} -eq 0 ]]; then
    log_i "No other human users found to remove."
    return 0
  fi

  log_w "The following human users will be DELETED:"
  printf '  - %s\n' "${human_users[@]}"
  echo

  # Safety confirmation
  read -p "Type YES (all caps) to proceed with deletion: " confirm
  if [[ "$confirm" != "YES" ]]; then
    log_i "Aborted. No users were deleted."
    return 1
  fi

  local deleted=0 failed=0
  for user in "${human_users[@]}"; do
    log_i "Deleting user: $user"
    if userdel -r "$user" 2>/dev/null; then
      ((deleted++))
      log_i "  -> Deleted successfully."
    else
      ((failed++))
      log_e "  -> Failed to delete $user (may be logged in or have processes)."
      log_w "     Try: pkill -u $user ; userdel -r -f $user  (DANGEROUS)"
    fi
  done

  log_i "Summary: $deleted user(s) deleted, $failed failed."
  if [[ $failed -gt 0 ]]; then
    log_w "Some deletions failed — check for logged-in users or running processes."
  fi
}

# Ensure OpenSSH is installed
ensure_openssh() {
  [[ -f "$SSHD_CONFIG" ]] && return 0
  log_i "Installing OpenSSH..."
  install_pkg openssh-server 1 || { log_e "Install failed."; exit 1; }
  [[ -f "$SSHD_CONFIG" ]] || { log_e "$SSHD_CONFIG not found."; exit 1; }
}

# Install Fail2Ban
install_fail2ban() {
  command -v fail2ban-client >/dev/null && { log_i "Fail2Ban installed."; return 0; }
  log_i "Installing Fail2Ban..."
  install_pkg fail2ban 1 || { log_w "Install Fail2Ban manually."; return 1; }
}

# Configure Fail2Ban for SSH
setup_fail2ban() {
  install_fail2ban || return 0
  mkdir -p "$FAIL2BAN_JAIL_D"
  cat >"$FAIL2BAN_JAIL_CONF" <<EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = $FAIL2BAN_MAXRETRY
bantime = $FAIL2BAN_BANTIME
findtime = $FAIL2BAN_FINDTIME
ignoreip = $FAIL2BAN_IGNOREIP
EOF
  log_i "Fail2Ban configured for SSH."
  run_svc fail2ban enable || true
  run_svc fail2ban restart || run_svc fail2ban start || log_w "Start Fail2Ban manually."
}

# Configure firewall (ufw or firewalld) - Enhanced to drop common vuln ports
setup_firewall() {
  local port
  if command -v ufw >/dev/null; then
    log_i "Configuring ufw: allow ${FIREWALL_TCP_PORTS// /,}/tcp; deny common vuln ports..."
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    for port in $FIREWALL_TCP_PORTS; do ufw allow "${port}/tcp" >/dev/null 2>&1; done
    for port in $VULN_PORTS_TO_DROP; do ufw deny "${port}/tcp" >/dev/null 2>&1; done
    echo 'y' | ufw enable >/dev/null 2>&1
    ufw status | grep -q 'active' && { log_i "ufw enabled."; return 0; }
    log_w "ufw failed. Run manually."
    return 1
  elif command -v firewall-cmd >/dev/null; then
    run_svc firewalld start; run_svc firewalld enable
    if [[ $(firewall-cmd --state) == "running" ]]; then
      log_i "Configuring firewalld: allow ftp, ssh, http, https; drop vuln ports..."
      firewall-cmd --permanent --add-port=21/tcp >/dev/null 2>&1
      firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1
      firewall-cmd --permanent --add-service=http >/dev/null 2>&1
      firewall-cmd --permanent --add-service=https >/dev/null 2>&1
      for port in $VULN_PORTS_TO_DROP; do firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1; done
      firewall-cmd --reload && { log_i "firewalld configured."; return 0; }
    fi
  fi
  # Install if missing
  pkg=$(get_pkg_mgr)
  case "$pkg" in
    apt-get) install_pkg ufw 1; setup_firewall ;;
    dnf|yum) install_pkg firewalld; setup_firewall ;;
    *) log_w "Install ufw or firewalld manually and configure ports."; return 1 ;;
  esac
}

# Backup config file
backup_config() {
  local src="$1" f
  mkdir -p "$BACKUP_DIR"
  f="${BACKUP_DIR}/${src##*/}.$(date +%Y%m%d_%H%M%S)"
  cp -a "$src" "$f"
  log_i "Backup: $f"
  echo "$f"
}

# Apply SSH hardening
apply_hardening() {
  local c="$1"
  if grep -q '^[[:space:]]*PermitRootLogin[[:space:]]*no' "$c"; then log_i "SSH already hardened."; return 0; fi
  HARDENING_APPLIED=1
  backup_config "$c" >/dev/null
  local conf_d='/etc/ssh/sshd_config.d'
  mkdir -p "$conf_d"
  cat >"${conf_d}/hardening.conf" <<EOF
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
Protocol 2
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
IgnoreRhosts yes
HostbasedAuthentication no
SyslogFacility AUTH
LogLevel INFO
EOF
  log_i "SSH hardened: Disabled root/password login, secure ciphers. Use keys for auth."
  run_svc "$(get_ssh_service)" restart || { log_e "SSH restart failed. Check config."; exit 1; }
}

# System update (address outdated software vulns)
system_update() {
  log_i "Performing system update to patch known vulns..."
  local pkg
  pkg=$(get_pkg_mgr)
  case "$pkg" in
    apt-get) apt-get update -qq && apt-get upgrade -y ;;
    dnf|yum) "$pkg" update -y ;;
    zypper) zypper update -y ;;
    *) log_w "Update manually."; return 1 ;;
  esac
  log_i "System updated."
}

# Disable common vulnerable services (e.g., from Metasploitable3)
disable_vuln_services() {
  local services="postgresql elasticsearch ircd snmpd samba glassfish jenkins tomcat proftpd"  # Common ones; ProFTPD if not your FTP
  for svc in $services; do
    if run_svc "$svc" status >/dev/null 2>&1; then
      log_i "Disabling vulnerable service: $svc"
      run_svc "$svc" stop
      run_svc "$svc" disable
    fi
  done
  log_i "Unused vulnerable services disabled."
}

# Secure MySQL if installed (address weak creds, UDF, anon access)
secure_mysql() {
  if ! command -v mysql >/dev/null; then log_i "MySQL not detected. Skipping."; return 0; fi
  local root_pass=$(random_bytes 20 'a-zA-Z0-9!@#$%&*+=')
  log_i "Securing MySQL: Setting root password, removing anon users/test DB..."
  mysql -u root --skip-password -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$root_pass'; DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;" || { log_w "MySQL secure failed—run mysql_secure_installation manually."; return 1; }
  echo "MySQL root password: $root_pass" >> "$ADMIN_CREDS_FILE"
  log_i "MySQL secured (new root pass in $ADMIN_CREDS_FILE). Restrict remote access via firewall."
}

# Harden FTP (vsftpd assumed; disable anon, chroot)
harden_ftp() {
  local conf='/etc/vsftpd.conf'
  if [[ ! -f "$conf" ]]; then log_i "vsftpd not detected. Skipping FTP hardening."; return 0; fi
  if grep -q '^anonymous_enable=NO' "$conf"; then log_i "FTP already hardened."; return 0; fi
  backup_config "$conf" >/dev/null
  {
    echo 'anonymous_enable=NO'
    echo 'local_enable=YES'
    echo 'chroot_local_user=YES'
    echo 'allow_writeable_chroot=YES'
    echo 'userlist_enable=YES'
    echo 'userlist_deny=NO'
    echo 'userlist_file=/etc/vsftpd.userlist'
  } >> "$conf"
  echo "$(id -un)" > /etc/vsftpd.userlist  # Allow current admin
  run_svc vsftpd restart || log_w "Restart vsftpd manually."
  log_i "FTP hardened: Anon disabled, chroot enabled."
}

# Harden web server (Apache/Nginx: disable dir listing, remove defaults)
harden_web() {
  if command -v apache2 >/dev/null; then
    local conf='/etc/apache2/apache2.conf'
    backup_config "$conf" >/dev/null
    sed -i 's/Options Indexes FollowSymLinks/Options -Indexes FollowSymLinks/' "$conf"
    rm -f /var/www/html/index.html 2>/dev/null  # Remove defaults
    run_svc apache2 restart
    log_i "Apache hardened: Dir listing disabled."
  elif command -v nginx >/dev/null; then
    local conf='/etc/nginx/nginx.conf'
    backup_config "$conf" >/dev/null
    sed -i '/autoindex on;/s/on/off/' "$conf"
    rm -f /usr/share/nginx/html/index.html 2>/dev/null
    run_svc nginx restart
    log_i "Nginx hardened: Dir listing disabled."
  else
    log_w "No Apache/Nginx detected. Harden web server manually."
  fi
}

# Rollback function (expanded for more backups)
rollback() {
  local ts="${1:-}" f latest
  for file in sshd_config vsftpd.conf apache2.conf nginx.conf; do
    latest=$(ls -t "${BACKUP_DIR}"/${file}.* 2>/dev/null | head -n1)
    [[ -z "$latest" ]] && continue
    if [[ -n "$ts" ]]; then f="${BACKUP_DIR}/${file}.${ts}"; [[ -f "$f" ]] || continue; else f="$latest"; fi
    cp -a "$f" "/etc/${file%.*}/${file}"  # Approximate restore path
    log_i "Restored ${file} from $f."
  done
  rm -f /etc/ssh/sshd_config.d/hardening.conf 2>/dev/null
  if [[ -f "$FAIL2BAN_JAIL_CONF" ]]; then rm -f "$FAIL2BAN_JAIL_CONF"; run_svc fail2ban restart >/dev/null 2>&1; log_i "Removed Fail2Ban config."; fi
  run_svc "$(get_ssh_service)" restart
  log_i "Rollback complete. Firewall/services not fully reverted—check manually."
}

# Main logic
check_root
ensure_openssh
create_admin_user
remove_other_human_users  # Lock down users

if [[ "${1:-}" == "rollback" ]]; then rollback "${2:-}"; exit 0; fi

log_i "Applying hardening..."
system_update
disable_vuln_services
secure_mysql
harden_ftp
harden_web
apply_hardening "$SSHD_CONFIG"
setup_fail2ban
setup_firewall

log_i "Hardening complete. Addressed Metasploitable3 vulns: Closed extra ports, secured MySQL/FTP/web, disabled services, updated packages."
log_i "Test access before logging out. For FTP passive: Add ports (e.g., ufw allow 10000:11000/tcp)."
log_i "Review logs/firewall for any issues."
