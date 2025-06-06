# ----------  variables --------------------------
$ErrorActionPreference = 'Stop'             # abort on any unhandled error
$logFile   = "C:\security_hardening_{0}.log" -f (Get-Date -f 'yyyyMMdd') # log file path

function Write-Log {                                          # Function to write log entries
    param(
        [Parameter(Mandatory)][ValidateSet('INFO','SUCCESS','WARNING','ERROR')][string]$Level,   # log level
        [Parameter(Mandatory)][string]$Message                                                   # log message
    )
    $entry = "{0} [{1}] {2}" -f (Get-Date -f 'yyyy-MM-dd HH:mm:ss'), $Level, $Message            # format entry
    $entry | Tee-Object -FilePath $logFile -Append                                               # write to log file and console
}

Write-Log -Level INFO -Message  "=== Hardening script launched ==="

# ----------   Firewall -------------------------------------------
function Firewall {
Write-Log -Level "INFO" -Message "Starting hardening of Windows Firewall"

# Check if the firewall is enabled
$firewallStatus = Get-NetFirewallProfile -Profile Domain,Private,Public

try {   # Try  catch to handle errors
    # Retrrive the  profile status
    $firewallStatus = Get-NetFirewallProfile -Profile Domain,Private,Public

    foreach ($profile in $firewallStatus) {
        if ($profile.Enabled -eq $false) {
            Set-NetFirewallProfile -Profile $profile.Name -Enabled True -ErrorAction Stop          # Enable the firewall for the profile
            Write-Log -Level "SUCCESS" -Message "Firewall activated for $($profile.Name) profil."
        } else {
            Write-Log -Level "INFO" -Message "Firewall is already active for $($profile.Name) profil."
        }
    }

    # Set the standard firewall rules
    $null = Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    Write-Log -Level "SUCCESS" -Message "Incoming traffic blocked, outgoing allowd."

    # Allow RDP (TCP 3389) 
    $null = New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Domain,Private,Public -ErrorAction Stop
    Write-Log -Level "SUCCESS" -Message "Firewall rule for TCP 3389 created."

    # Allow HTTPS (TCP 443)
    $null = New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Domain,Private,Public -ErrorAction Stop
    Write-Log -Level "SUCCESS" -Message "Firewall rule for HTTPS TCP 443 created."

    Write-Log -Level "INFO" -Message "Hardening of firewall complete."
} catch {
    Write-Log -Level "ERROR" -Message "An error occured during the firewall configuration: $_"
}
}
Firewall

# ----------  Windows Defender -----------------------------------
function Defender {
    Write-Log -Level "INFO" -Message "Starting hardening of Windows Defender..."
    # See if Defender is active and signatures are up to date
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop

        if ($status.AntivirusEnabled -or $status.AMServiceEnabled) {   # AnitvirusEnabled and AMServiceEnabled are both true if Defender is active
            Write-Log -Level "SUCCESS" -Message "Defender is active"
        } else {
            Write-Log -Level "ERROR" -Message "Defender is not active"
        }

        if ($status.SignatureAge -gt 2) {    # if signature age is greater than 2 days update and start a full scan
            Write-Log -Level "WARNING" -Message "Signituers are older than 2 days. Uppdateing and starting scan."
            try {
                Update-MpSignature -ErrorAction Stop
                Start-Sleep -Seconds 10 
                Start-MpScan -ScanType FullScan -ErrorAction Stop
                Write-Log -Level "SUCCESS" -Message "Uppdate and full scan started successfully."
            } catch {
                Write-Log -Level "ERROR" -Message "Could not update or scan: $_"
            }
        } else {
            Write-Log -Level "INFO" -Message "Signatures are up to date."
        }

        Write-Log -Level "SUCCESS" -Message "Hardining av defender completed."
    } catch {
        Write-Log -Level "ERROR" -Message "Could not retrive defender status $_"
    }
}
Defender
# ----------    Admin-group check -------------------------------
function Clean-Admins {

    $approved   = Get-Content "$PSScriptRoot\approved_users.txt" -ErrorAction Stop        # check the approved users list
    $threshold  = (Get-Date).AddDays(-90)                                                  # 90 days threshold for inactivity
    Write-Log -Level "INFO" -Message "Scrubbing Administrators group against approved list"

    foreach ($m in Get-LocalGroupMember -Group 'Administrators') {

        # Skip built-in protected accounts
        if ($m.Name -in @('Administrator','NT AUTHORITY\SYSTEM')) { continue }

        if ($approved -notcontains $m.Name) {
            try {
                Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name -ErrorAction Stop   # if not an approved user, remove from Administrators group
                Write-Log -Level "SUCCESS" -Message "Removed unapproved admin $($m.Name)"
            }
            catch {
                Write-Log -Level "ERROR" -Message "Could not remove $($m.Name) : $_"
            }

            $acct = Get-LocalUser -Name $m.Name -ErrorAction SilentlyContinue # if inactive account, disable it
            if ($acct -and $acct.LastLogon -lt $threshold) {
                Disable-LocalUser -Name $m.Name
                Write-Log -Level "INFO" -Message "Disabled dormant account $($m.Name) (inactive >90 days)"
            }
        }
    }
}

Clean-Admins

# ----------  Disable insecure protocols ------------------------
function Disable-SMBv1 {                      
    Write-Log -Level "INFO" -Message "Disabling SMBv1 if present"
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0 -Force
    Write-Log -Level "SUCCESS" -Message "SMBv1 registry flag set to 0"
}
Disable-SMBv1

# ---------- remove bad services -----------------------------------
function Remove-BadServices {           #check for these old insecure services and disable them
    $legacy = @('Telnet','FTPSVC','RemoteRegistry')
    foreach ($svcName in $legacy) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq 'Running') { Stop-Service $svcName -Force }
            Set-Service  $svcName -StartupType Disabled | Out-Null
            Write-Log SUCCESS "Service $svcName stopped and disabled"
        } else {
            Write-Log -Level INFO -Message "Service $svcName not present (OK)" 
        }
    }
}
Remove-BadServices

# ---------- Disk & TEMP clean-up ------------------------------
function Check-Disk {

    
    $drive = Get-PSDrive -Name C # check the C: drive
    $size  = [double]$drive.Size  # get the total size of the drive
    $free  = [double]$drive.Free  # get the free space on the drive

    if ($size -lt 1) {                      # VM  had little disk space causeing error this was added to prevent it,    
        $cim  = Get-CimInstance -Class Win32_LogicalDisk `
                               -Filter "DeviceID='C:'"
        $size = [double]$cim.Size
        $free = [double]$cim.FreeSpace
    }                                           
    
    $freePercent = [math]::Round(($free / $size) * 100, 2) # calculate free space percentage
    Write-Log -Level INFO -Message "C: free space $freePercent %"

    if ($freePercent -lt 15) {    # if free space is less than 15%, move TEMP files to the archive directory
        $archivePath = 'C:\Archive_Temp'
        $null = New-Item -ItemType Directory -Path $archivePath -Force

        Get-ChildItem -Path 'C:\Windows\Temp' -Recurse -ErrorAction SilentlyContinue |
            Move-Item -Destination $archivePath -Force -ErrorAction SilentlyContinue |
            Out-Null

        Write-Log -Level WARNING -Message "Free <15 % TEMP files moved to $archivePath"
    }
    else {
        Write-Log -Level INFO -Message "Sufficient free space, no action needed"
    }
}

Check-Disk

# ----------  BitLocker -----------------------------------------
function Check-BitLocker {
    try {
        $vol = Get-BitLockerVolume -MountPoint 'C:'  # check the BitLocker status on C:
        if ($vol.ProtectionStatus -eq 1) {  # ProtectionStatus 1 means BitLocker is enabled
            Write-Log -Level "SUCCESS" -Message "BitLocker already enabled on C:"
        } else {
            Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 `  # enable BitLocker with XtsAes256 encryption
                             -UsedSpaceOnly -TpmProtector -ErrorAction Stop
            Write-Log -Level "SUCCESS" -Message "BitLocker enablement started on C:"
        }
    } catch {
        Write-Log -Level "ERROR" -Message "BitLocker check failed: $_"
    }
}
Check-BitLocker

# ---------- 8.   Wrap-up -------------------------------------------
Write-Log -Level "INFO" -Message "Hardening script completed"

