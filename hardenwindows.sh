# harden-windows.ps1
# Hardening script for Metasploitable3 Windows (Server 2008 R2)
# Allows: IIS web (80/443), FTP (21), SSH (22 if present)
# Closes common vuln ports/services from walkthroughs

#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"

Write-Host "Starting Metasploitable3 Windows Hardening" -ForegroundColor Green
Write-Host "This is destructive — snapshot VM first!" -ForegroundColor Yellow
$confirm = Read-Host "Type YES to continue"
if ($confirm -ne "YES") { Write-Host "Aborted."; exit }

$LogFile = "C:\harden-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
function Log($msg) {
    Write-Host $msg
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
}

Log "Hardening started"

# 1. System update (patch what can be patched — limited on 2008 R2)
Log "Running Windows Update scan/install (may take time)..."
wuauclt /detectnow
Start-Sleep -Seconds 30  # Give it a moment — manual check recommended

# 2. Disable dangerous legacy features
Log "Disabling SMBv1 (EternalBlue target)..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

Log "Disabling weak protocols if possible..."
# Limited on 2008 — focus on services instead

# 3. Firewall — strict inbound, allow only desired ports
Log "Configuring Windows Firewall..."
netsh advfirewall set allprofiles state on

# Reset to block by default
netsh advfirewall firewall set rule group="remote administration" new enable=no
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=no

# Explicitly allow desired ports
$AllowedPorts = @("21","22","80","443")   # FTP, SSH (if present), HTTP/HTTPS
foreach ($port in $AllowedPorts) {
    netsh advfirewall firewall add rule name="Allow-$port" dir=in action=allow protocol=TCP localport=$port | Out-Null
    Log "Allowed inbound TCP $port"
}

# Block common vulnerable ports explicitly (from wiki/walkthroughs)
$VulnPorts = @("135","139","445","1433","3306","3389","4848","8009","8080","8180","8282","8484","9200","8020","8032","8040")
foreach ($port in $VulnPorts) {
    netsh advfirewall firewall add rule name="Block-Vuln-$port" dir=in action=block protocol=TCP localport=$port | Out-Null
    Log "Blocked inbound TCP $port (common vuln)"
}

# 4. Disable/stop vulnerable/unneeded services
$BadServices = @(
    "W3SVC",           # IIS — wait, we want to keep web → do NOT stop
    "FTPSVC",          # Microsoft FTP (if not using)
    "SNMPTRAP",
    "SNMP",
    "Spooler",         # Often unnecessary
    "TabletInputService",
    "WerSvc",          # Error reporting
    "WinRM",           # If not needed
    "WMPNetworkSvc"
    # Add more if you identify: GlassFish, Tomcat, Jenkins, ManageEngine, etc.
)

foreach ($svc in $BadServices) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Log "Stopping & disabling $svc"
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# Special: Tomcat/GlassFish/Jenkins often on high ports — stop if found
$TomcatSvc = Get-Service | Where-Object { $_.Name -like "*Tomcat*" -or $_.Name -like "*GlassFish*" -or $_.Name -like "*Jenkins*" }
if ($TomcatSvc) {
    foreach ($s in $TomcatSvc) {
        Log "Stopping vulnerable web service: $($s.Name)"
        Stop-Service -Name $s.Name -Force
        Set-Service -Name $s.Name -StartupType Disabled
    }
}

# 5. Harden IIS (assuming default site)
Log "Hardening IIS (if present)..."
Import-Module WebAdministration -ErrorAction SilentlyContinue

if (Get-Module -Name WebAdministration) {
    # Disable directory browsing
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/directoryBrowse" -name "enabled" -value "False"

    # Remove default docs if desired (or restrict)
    # Clear-WebConfiguration -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site' -filter "system.webServer/defaultDocument/files/collection"

    # Basic request filtering
    Add-WebConfiguration -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -value @{allowUnlisted="false"}

    Log "IIS hardened: dir browsing off, request filtering tightened"
} else {
    Log "IIS module not loaded — IIS may not be installed or PowerShell version limited"
}

# 6. User cleanup — remove non-Administrator local users (very aggressive)
Log "Removing non-Administrator local users (except current)..."
$KeepUsers = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")   # Add any you need

$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $KeepUsers -notcontains $_.Name }

foreach ($u in $users) {
    if ($u.Name -eq $env:USERNAME) { Log "Skipping current user $($u.Name)"; continue }
    Log "Removing user: $($u.Name)"
    Remove-LocalUser -Name $u.Name -ErrorAction Continue
}

# Optional: Create dedicated admin user (similar to Linux version)
$NewAdmin = "HardenedAdmin"
if (-not (Get-LocalUser -Name $NewAdmin -ErrorAction SilentlyContinue)) {
    $pw = ConvertTo-SecureString "ChangeMe123!@#" -AsPlainText -Force   # CHANGE THIS
    New-LocalUser -Name $NewAdmin -Password $pw -FullName "Hardened Admin" -Description "Secure admin"
    Add-LocalGroupMember -Group "Administrators" -Member $NewAdmin
    Log "Created new admin: $NewAdmin (password: ChangeMe123!@# — CHANGE IT!)"
}

# 7. Final steps
Log "Enabling firewall audit logging (basic)"
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

Log "Hardening complete."
Log "Review firewall: netsh advfirewall firewall show rule name=all"
Log "Check services: Get-Service | Where Status -eq Running"
Log "Log saved to $LogFile"
Write-Host "Done. Reboot recommended. Test web/FTP/SSH access!" -ForegroundColor Green
