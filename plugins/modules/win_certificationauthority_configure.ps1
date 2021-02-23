#!powershell
# Copyright: (c) 2021 Sebastian Gruber (sgruber94), Boris Birneder (@borris70),dacoso GmbH All Rights Reserved.
# SPDX-License-Identifier: GPL-3.0-only
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options             = @{
        mode             = @{ type = "str"; choices = "install", "uninstall"; default = "install" }
        certauthname     = @{ type = "str"; aliases = "caname"; required = $true } # Name of new CA
        cname            = @{ type = "str"; default = "pki" } #DNS Alias for Webaccess, CRL and AIA Location
        keylength        = @{ type = "int"; choices = 2048, 4096, 8192; default = 4096 }
        validyears       = @{ type = "int"; default = 15 }# Root Cert Validity
        hash             = @{ type = "str"; choices = "SHA1", "SHA256", "SHA384", "SHA512"; default = "SHA512" }
        domaincontroller = @{ type = "str"; aliases = "dc"; required = $true }#specify DC
        zone             = @{ type = "str"; required = $true }#specify zone
        fqdn             = @{ type = "str"; required = $true }#specify fqdn
        log_path         = @{ type = "str" }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$log_path = $module.Params.log_path
$winca_mode = $module.Params.mode
$winca_caname = $module.Params.certauthname
$winca_cname = $module.Params.cname
$winca_keylength = $module.Params.keylength
$winca_validyears = $module.Params.validyears
$winca_hash = $module.Params.hash
$winca_dc = $module.Params.domaincontroller
$winca_zone = $module.Params.zone
$ErrorActionPreference = 'Stop'

$module.result = @{
    changed         = $true
    reboot_required = $false
}
$required_features = @("AD-Certificate", "ADCS-Web-Enrollment")
Function Write-DebugLog {
    Param(
        [string]$msg
    )

    $DebugPreference = "Continue"
    $ErrorActionPreference = "Continue"
    $date_str = Get-Date -Format u
    $msg = "$date_str $msg"

    Write-Debug $msg
    if ($log_path) {
        Add-Content $log_path $msg
    }
}
Function Get-MissingFeatures {
    Write-DebugLog "Checking for missing Windows features..."

    $features = @(Get-WindowsFeature $required_features)

    If ($features.Count -ne $required_features.Count) {
        Throw "One or more Windows features required for a domain controller are unavailable"
    }

    $missing_features = @($features | Where-Object InstallState -ne Installed)

    return , $missing_features # no, the comma's not a typo- allows us to return an empty array
}
Function Ensure-FeatureInstallation {
    Write-DebugLog "Ensuring required Windows features are installed..."
    $feature_result = Install-WindowsFeature $required_features -IncludeManagementTools
    $module.result.reboot_required = $feature_result.RestartNeeded

    If (-not $feature_result.Success) {
        $module.FailJson("Error installing AD-Domain-Services and RSAT-ADDS features: {0}" -f ($feature_result | Out-String))
    }
}
function Install-WindowsCertificationAuthority {
    param(
        [string]$dc, # Name of domaincontroller
        [string]$fqdn, # Name of fqdn from CA
        [string]$zone, # Name of dns zone
        [Parameter(Mandatory = $true)][string]$CAName, # Name of new CA
        [Parameter(Mandatory = $true)][string]$CNAME, # DNS Alias for Webaccess, CRL and AIA Location
        [Parameter(Mandatory = $true)][INT]$ValidYears, # Root Cert Validity
        [Parameter(Mandatory = $true)][ValidateSet(2048, 4096, 8192)][INT]$KeyLength, # Key Length Root Cert
        [Parameter(Mandatory = $true)][ValidateSet("SHA1", "SHA256", "SHA384", "SHA512")][STRING]$Hash 	# Hash Type Root Cert
    )
    $zone = $zone.tolower()
    $fqdn = $fqdn.tolower()
    # Other parameter
    # Every xx weeks a new CRL
    $crlweeks = 4
    # Every xx days a new Delta CRL
    $crldeltadays = 1
    # Overlap for xx hours
    $crloverlap = 12
    # Certs valid max. xx years
    $certsvalid = 5
    # Loaddefaulttemplates: 0 = no , 1=yes
    $defaulttemplates = 0

    ##########################################################################

    # Check if CApolicy exists
    $capolicypath = "C:\Windows\capolicy.inf"
    if (Test-Path -path $capolicypath) { Clear-Content $capolicypath -force }

    # Create CAPolicy.inf in c:\Windows
    Write-DebugLog "[INFO] Create $capolicypath"
    Add-Content -path $capolicypath -value '[Version]'
    Add-Content -path $capolicypath -value 'Signature="$Windows NT$"'
    Add-Content -path $capolicypath -value '[Certsrv_Server]'
    Add-Content -path $capolicypath -value ('RenewalKeyLength=' + $KeyLength)
    Add-Content -path $capolicypath -value 'RenewalValidityPeriod=Years'
    Add-Content -path $capolicypath -value ('RenewalValidityPeriodUnits=' + $ValidYears)
    Add-Content -path $capolicypath -value 'CRLPeriod=Weeks'
    Add-Content -path $capolicypath -value ('CRLPeriodUnits=' + $crlweeks)
    Add-Content -path $capolicypath -value 'CRLDeltaPeriod=Daily'
    Add-Content -path $capolicypath -value ('CRLDeltaPeriodUnits=' + $crldeltadays)
    Add-Content -path $capolicypath -value ('CNGHashAlgorithm=' + $Hash)
    Add-Content -path $capolicypath -value ('LoadDefaultTemplates=' + $defaulttemplates)
    Add-Content -path $capolicypath -value 'AlternateSignatureAlgorithm=0'

    # Set DNS ALIAS for AIA and CRL, if not exists

    Write-DebugLog "[INFO] Set ALIAS $Cname to $fqdn"
    #  add DNS record
    Add-DnsServerResourceRecordCName -ComputerName $dc -Name $CNAME -HostNameAlias $fqdn -ZoneName $zone
    # Install AD + Webenrollment feature
    Write-DebugLog "[INFO] Install CA and webserver Role if not exists"
    if ((Get-WindowsFeature AD-Certificate).installstate -ne "Installed") {
        Install-WindowsFeature AD-Certificate -IncludeManagementTools
    }
    if ((Get-WindowsFeature ADCS-Web-Enrollment).installstate -ne "Installed") {
        Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
    }
    # Install AD integrated CA
    Write-DebugLog "[INFO] Create CA $CAName"
    # Overwrite existing key, CA, Database etc,
    Install-AdcsCertificationAuthority -CACommonName $CAName -CAType EnterpriseRootCa -ValidityPeriod Years -ValidityPeriodUnits $validyears -HashAlgorithmName $Hash -KeyLength $keyLength -OverwriteExistingCAinDS -OverwriteExistingKey -OverwriteExistingDatabase -force
    Install-AdcsWebEnrollment -force
    # Configure CA
    Write-DebugLog "[INFO] Configure CA CRL, Cert and Audit settings"
    certutil.exe -setreg CA\CRLPeriodUnits $crlweeks | Out-Null
    certutil.exe -setreg CA\CRLPeriod "Weeks" | Out-Null
    certutil.exe -setreg CA\CRLDeltaPeriodUnits $crldeltadays | Out-Null
    certutil.exe -setreg CA\CRLDeltaPeriod "Days" | Out-Null
    certutil.exe -setreg CA\CRLOverlapPeriodUnits $crloverlap | Out-Null
    certutil.exe -setreg CA\CRLOverlapPeriod "Hours" | Out-Null
    certutil.exe -setreg CA\ValidityPeriodUnits $certsvalid | Out-Null
    certutil.exe -setreg CA\ValidityPeriod "Years" | Out-Null
    certutil.exe -setreg CA\AuditFilter 127 | Out-Null

    # Remove original CRL
    Write-DebugLog "[INFO] Configure CRL Distribution Points"
    $crllist = Get-CACrlDistributionPoint
    ForEach ($crl in $crllist) { Remove-CACrlDistributionPoint $crl.uri -Force }
    # Set new CRL local and to http ALIAS
    Add-CACRLDistributionPoint -Uri ("C:\Windows\System32\CertSrv\CertEnroll\" + $CAName.replace(" ", "-") + "%8%9.crl") -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri ("http://" + $CNAME + "." + ("$env:userdnsdomain").tolower() + "/CertEnroll/" + $CAName.replace(" ", "-") + "%8%9.crl") -AddToCertificateCDP -AddToFreshestCrl -Force

    # remove original AIA
    Write-DebugLog "[INFO] Configure AIA Information Access"
    $aialist = Get-CAAuthorityInformationAccess
    ForEach ($aia in $aialist) { Remove-CAAuthorityInformationAccess $aia.uri -Force }
    # Set new AIA local and to http ALIAS
    $aiafile = "C:\Windows\System32\CertSrv\CertEnroll\" + $CAName.replace(" ", "-") + ".crt"
    Certutil -setreg CA\CACertPublicationURLs $aiafile | Out-Null
    Add-CAAuthorityInformationAccess -AddToCertificateAia ("http://" + $CNAME + "." + ("$env:userdnsdomain").tolower() + "/CertEnroll/" + $CAName.replace(" ", "-") + ".crt") -Force

    # rename Certificate Name in AIA destination
    if (!(Test-Path -path $aiafile)) {
        Rename-Item -Path (Get-ChildItem -path "C:\Windows\System32\CertSrv\CertEnroll" -file -filter "*$CAName*.crt").fullname -NewName $aiafile -force 
    }
    # Restart CA Service
    Write-DebugLog "[INFO] Restart CA $CaName"
    Get-Service CertSvc | Restart-Service
    Start-Sleep 2
    # Create new CRL
    Write-DebugLog "[INFO] Create New CRL List"
    Certutil -crl | Out-Null
    Write-DebugLog "[INFO] Installation of new CA $CAName is finished"
}
#Ansible Values
$log_path = Get-AnsibleParam -obj $params -name "log_path"
$_ansible_check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -default $false
$global:log_path = $log_path
if ($winca_mode -eq "install") {
    #Install and configure CA
    Write-DebugLog "Mode: Install CertificationAuthority"
    $missing_features = Get-MissingFeatures
    If ($missing_features.Count -gt 0) {
        Write-DebugLog ("Missing Windows features ({0}), need to install" -f ($missing_features -join ", "))
        $result.changed = $true # we need to install features
        If ($_ansible_check_mode) {
            # bail out here- we can't proceed without knowing the features are installed
            Write-DebugLog "check-mode, exiting early"
            $module.ExitJson()
        }
        Ensure-FeatureInstallation | Out-Null
    }
    Install-WindowsCertificationAuthority -CAName $winca_caname -CNAME $winca_cname -ValidYears $winca_validyears -KeyLength $winca_keylength -Hash $winca_hash -dc $winca_dc -fqdn $winca_fqdn -zone $winca_zone
}
if ($winca_mode -eq "uninstall") {
    try {
        #uninstall CA for testing purpose
        Uninstall-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
        Uninstall-WindowsFeature AD-Certificate -IncludeManagementTools
        Uninstall-WindowsFeature Web-Server -IncludeManagementTools
        Get-ChildItem "Cert:\LocalMachine\" -Recurse | where-Object { $_.DnsNameList.unicode -eq $winca_caname } | Remove-Item -Force
        Get-Childitem -path C:\Windows\system32\certsrv -recurse -file | ForEach-Object { Remove-Item -path $_.fullname -force }
        Get-Childitem -path C:\Windows\system32\certlog -recurse -file | ForEach-Object { Remove-Item -path $_.fullname -force }
        $module.result.changed = $true
        $module.result.reboot_required = $true
    } catch {
        $module.FailJson("an exception occurred when removing the specified rule - $($_.Exception.Message)")
    }
}
$module.ExitJson()