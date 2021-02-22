#!powershell
# Copyright: (c) 2021 Sebastian Gruber / Boris Birneder ,dacoso GmbH All Rights Reserved.
# SPDX-License-Identifier: GPL-3.0-only
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#AnsibleRequires -CSharpUtil Ansible.Basic

#Error Action
$ErrorActionPreference = 'Stop'
$log_path = "C:\temp\ansible_winca.txt"
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

if (!(Get-Module ActiveDirectory))
	{
	Install-WindowsFeature -Name RSAT-AD-PowerShell
}
function Get-WinCaTemplate {
    param(
        [string]$domaincontroller # Specify DomainController of the domain
    )
    # read existing templates in AD
    $dc = $domaincontroller
    $LDAPFilter = '(objectClass=pKICertificateTemplate)'
    $ConfigNC = $((Get-ADRootDSE -Server $dc).configurationNamingContext)
    Write-DebugLog "Available templates in Active Directory"
    $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
    $templates = Get-ADObject -SearchScope Subtree -SearchBase $TemplatePath -LDAPFilter $LDAPFilter -Properties * -Server $dc | Select-Object -Property name, displayName, objectClass, flags, revision, *pki*
    $templates | Sort-Object Name | Format-Table Name, Displayname
}
function Set-WinCATemplate {
    param(
        [switch]$List, # list only existing templates
        [string]$Duplicate, # original Template Name to duplicate
        [string]$NewTemplate, # new duplicated template Name - only valid with parameter duplicate
        [ValidateSet(2048, 4096, 8192)][INT]$NewKeyLength,	# key Length 2048-8192 bit - only valid with parameter duplicate
        [ValidateRange(1, 5)][INT]$NewValidityYears, # Certificate Validity 1-5 years - only valid with parameter duplicate
        [string]$AddEnrollment, # Set for a AD Group read and enrollment rights
        [string]$AddAutoEnrollment, # Set for a AD Group read and enroll and autoenrollment rights
        [switch]$PublishAD ,# Publish the duplicated template to AD - only valid with parameter duplicate
        [string]$domaincontroller # Specify DomainController of the domain
    )
    $dc = $domaincontroller
    # Set Template Version of duplicated template to 2008R2
    $revision = 100
    $Template_Minor_Revision = 2
    $Template_Schema_Version = 2
    # $LDAPFilter = "(&(objectClass=pKICertificateTemplate)(displayName=$DisplayName))"
    $LDAPFilter = '(objectClass=pKICertificateTemplate)'
    $ConfigNC = $((Get-ADRootDSE -Server $dc).configurationNamingContext)
    $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
    $templates = Get-ADObject -SearchScope Subtree -SearchBase $TemplatePath -LDAPFilter $LDAPFilter -Properties * -Server $dc | Select-Object -Property name, displayName, objectClass, flags, revision, *pki*

    if ($duplicate) {
        # Check if template to duplicate exists
        if ($templates.Name -notcontains $duplicate) {
            $module.FailJson("[ERROR] Template $duplicate not found")
            break
        } else {
            Write-DebugLog "[INFO] Template $duplicate found"
        }
        # Check if new template Name not exists
        if (($templates.Name -contains $NewTemplate) -or ($templates.DisplayName -contains $NewTemplate)) {
            $module.FailJson("[ERROR] New Template Name $NewTemplate already exists")
            break
        } else {
            Write-DebugLog "[INFO] New Template Name: $NewTemplate "
        }

        # Create New OID
        $TemplateOIDPath = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
        do {
            # make random OID
            $OID_Part_1 = Get-Random -Minimum 10000000 -Maximum 99999999
            $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
            $Hex = "0123456789ABCDEF"
            $OID_Part_3 = ""
            Foreach ($i in (1..32)) { $OID_Part_3 = $OID_Part_3 + $Hex.Substring((Get-Random -Minimum 0 -Maximum 16), 1) }
            $OID_Forest = Get-ADObject -Server $dc -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID
            $msPKICertTemplateOID = "$OID_Forest.$OID_Part_1.$OID_Part_2"
            $TemplateName = "$OID_Part_2.$OID_Part_3"
        }
        # Repeat until OIDs are unique
        while (Get-ADObject -Server $dc -SearchBase $TemplateOIDPath -Filter { (cn -eq $TemplateName) -and (msPKI-Cert-Template-OID -eq $msPKICertTemplateOID) })

        Write-DebugLog "[INFO] $NewTemplate Unique OID: $msPKICertTemplateOID"
        Write-DebugLog "[INFO] $NewTemplate Unique TemplateName: $TemplateName"

        # write new OID as object
        $oa = @{
            'DisplayName'             = $NewTemplate
            'flags'                   = [System.Int32]'1'
            'msPKI-Cert-Template-OID' = $msPKICertTemplateOID
        }

        Write-DebugLog "[INFO] Write OID Unique Object to $dc"
        New-ADObject -Path $TemplateOIDPath -OtherAttributes $oa -Name $TemplateName -Type 'msPKI-Enterprise-Oid' -Server $dc

        # create new template
        # Duplicate existing template object, workaround with json
        Write-DebugLog "[INFO] Duplicate Template"
        $duplicatetemplate = $templates | Where-Object { $_.Name -eq $duplicate } | ConvertTo-Json | ConvertFrom-Json

        # Check if $NewKeyLength is set and change value
        if ($NewKeyLength) {
            Write-DebugLog "[INFO] Set Keylength to $NewKeyLength"
            $duplicatetemplate.'msPKI-Minimal-Key-Size' = $NewKeyLength
        }

        # create Array Years to Byte Array for ValidityYears 1-5 - there is no way to calculate - manual values
        $YearsByte = @()
        $object = New-Object -TypeName PSObject
        $object | Add-Member -Name "Year" -MemberType Noteproperty -Value "1"
        $object | Add-Member -Name "Bytes" -MemberType Noteproperty -Value "0,64,57,135,46,225,254,255"
        $YearsByte = $YearsByte + $object
        $object = New-Object -TypeName PSObject
        $object | Add-Member -Name "Year" -MemberType Noteproperty -Value "2"
        $object | Add-Member -Name "Bytes" -MemberType Noteproperty -Value "0,128,114,14,93,194,253,255"
        $YearsByte = $YearsByte + $object
        $object = New-Object -TypeName PSObject
        $object | Add-Member -Name "Year" -MemberType Noteproperty -Value "3"
        $object | Add-Member -Name "Bytes" -MemberType Noteproperty -Value "0,192,171,149,139,163,252,255"
        $YearsByte = $YearsByte + $object
        $object = New-Object -TypeName PSObject
        $object | Add-Member -Name "Year" -MemberType Noteproperty -Value "4"
        $object | Add-Member -Name "Bytes" -MemberType Noteproperty -Value "0,0,229,28,186,132,251,255"
        $YearsByte = $YearsByte + $object
        $object = New-Object -TypeName PSObject
        $object | Add-Member -Name "Year" -MemberType Noteproperty -Value "5"
        $object | Add-Member -Name "Bytes" -MemberType Noteproperty -Value "0,64,30,164,232,101,250,255"
        $YearsByte = $YearsByte + $object

        # Check if $NewValidityYears is set and change value
        # Convert Year to Byte Array
        $array = Foreach ($b in (($YearsByte | Where-Object { $_.Year -eq $NewValidityYears }).Bytes.Split(","))) { [INT]::parse($b) }
        $bytes = [byte[]]$array
        if ($NewValidityYears) {
            Write-DebugLog "[INFO] Set Validiy to $NewValidityYears years"
            $duplicatetemplate.pKIExpirationPeriod = $bytes
        }
        # Set Template Revision
        $duplicatetemplate.revision = $revision
        $duplicatetemplate.'msPKI-Template-Minor-Revision' = $Template_Minor_Revision
        $duplicatetemplate.'msPKI-Template-Schema-Version' = $Template_Schema_Version

        # Test for msPKI-Certificate-Application-Policy
        if ([bool]($duplicatetemplate.PSobject.Properties.name -notmatch 'msPKI-Certificate-Application-Policy')) {
            $duplicatetemplate | Add-Member -MemberType NoteProperty -Name 'msPKI-Certificate-Application-Policy' -TypeName ADPropertyValueCollection -value $null
            # Copy attribute for compatibility
            $duplicatetemplate.'msPKI-Certificate-Application-Policy' = $duplicatetemplate.pKIExtendedKeyUsage
        }

        $oa = @{ 'msPKI-Cert-Template-OID' = $msPKICertTemplateOID }
        ForEach ($prop in ($duplicatetemplate | Get-Member -MemberType NoteProperty)) {
            Switch ($prop.Name) {
                { $_ -in 'flags',
                    'msPKI-Certificate-Name-Flag',
                    'msPKI-Enrollment-Flag',
                    'msPKI-Minimal-Key-Size',
                    'msPKI-Private-Key-Flag',
                    'msPKI-Template-Minor-Revision',
                    'msPKI-Template-Schema-Version',
                    'msPKI-RA-Signature',
                    'pKIMaxIssuingDepth',
                    'pKIDefaultKeySpec',
                    'revision'
                }
                { $oa.Add($_, [System.Int32]$duplicatetemplate.$_); break }

                { $_ -in 'msPKI-Certificate-Application-Policy',
                    'pKICriticalExtensions',
                    'pKIDefaultCSPs',
                    'pKIExtendedKeyUsage'
                }
                { $oa.Add($_, [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]$duplicatetemplate.$_); break }

                { $_ -in 'pKIExpirationPeriod',
                    'pKIKeyUsage',
                    'pKIOverlapPeriod'
                }
                { $oa.Add($_, [System.Byte[]]$duplicatetemplate.$_); break }
            }
        }
        # Write template Object
        Write-DebugLog "[INFO] Write new template Object $NewTemplate to $dc"
        New-ADObject -Path $TemplatePath -OtherAttributes $oa -Name $NewTemplate.Replace(' ', '') -DisplayName $NewTemplate -Type pKICertificateTemplate -Server $dc
    }

    Write-DebugLog "[INFO] Sleeping 30 seconds for replication"
    Start-Sleep 30

    # Path to new Template
    $TemplatePath = "AD:\CN=" + $NewTemplate.Replace(' ', '') + "," + $TemplatePath

    # if AddEnrollment is set -> Set ACL read, enroll, autoenroll
    if ($AddEnrollment) {
        $group = Get-ADGroup -filter "Name -eq '$AddEnrollment'" -server $dc
        if (!($group)) {
            # AD Group not exists
            Write-DebugLog "[ERROR] AD Group $AddEnrollment does not exist in domain"
            $module.FailJson("[ERROR] AD Group $AddEnrollment does not exist in domain")
        } else {
            Write-DebugLog "[INFO] Set read and Enrollment Permission for $AddEnrollment on Template $NewTemplate" -foregroundcolor green
            # read ACL
            $acl = Get-ACL $TemplatePath
            $InheritedObjectType = [GUID]'00000000-0000-0000-0000-000000000000'
            # Set AccessRules
            $ObjectType = [GUID]'00000000-0000-0000-0000-000000000000'
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $group.SID, 'GenericRead', 'Allow' , $ObjectType, 'None', $InheritedObjectType
            $acl.AddAccessRule($ace)
            $ObjectType = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $group.SID, 'ExtendedRight', 'Allow' , $ObjectType, 'None', $InheritedObjectType
            $acl.AddAccessRule($ace)
            # Write Access Rules
            Set-ACL $TemplatePath -AclObject $acl
        }
    }

    # if AddAutoEnrollment is set -> Set ACL read, enroll, autoenroll
    if ($AddAutoEnrollment) {
        $group = Get-ADGroup -filter "Name -eq '$AddAutoEnrollment'" -server $dc
        if (!($group)) {
            # AD Group not exists
            $module.FailJson("[ERROR] AD Group $AddAutoEnrollment does not exist in domain")
        } else {
            Write-DebugLog "[INFO] Set read and Enroll and AutoEnrollment Permission for $AddAutoEnrollment on Template $NewTemplate" -foregroundcolor green

            # read ACL
            $acl = Get-ACL $TemplatePath
            $InheritedObjectType = [GUID]'00000000-0000-0000-0000-000000000000'
            # Set AccessRules
            $ObjectType = [GUID]'00000000-0000-0000-0000-000000000000'
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $group.SID, 'GenericRead', 'Allow' , $ObjectType, 'None', $InheritedObjectType
            $acl.AddAccessRule($ace)
            $ObjectType = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $group.SID, 'ExtendedRight', 'Allow' , $ObjectType, 'None', $InheritedObjectType
            $acl.AddAccessRule($ace)
            $ObjectType = [GUID]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $group.SID, 'ExtendedRight', 'Allow' , $ObjectType, 'None', $InheritedObjectType
            $acl.AddAccessRule($ace)
            # Write Access Rules
            Set-ACL $TemplatePath -AclObject $acl
        }
    }

    # If PuplishAD is set - > publish to AD
    $count = 1
    $max = 50
    if ($publishAD) {
        Write-DebugLog "[INFO] Publish $NewTemplate in AD"
        do {
            try {
                $ok = $true
                Add-CATemplate -Name $NewTemplate.Replace(' ', '') -force
            } catch {
                Write-DebugLog "[WARNING] [$count..$max] - Can't publish $NewTemplate - waiting 15 seconds for replication"
                Start-Sleep 15
                $ok = $false
            }
            $count++
            if ($count -eq $max) {
                Write-DebugLog "[ERROR] Give up - Can't publish $NewTemplate"
                $ok = $true
            }
        }
        until ($ok -eq $true)
    }
}
$result = @{
    changed = $false
}
$spec = @{
    options             = @{
        mode             = @{ type = "str"; choices = "query", "manage"; default = "manage" }
        originaltemplate = @{ type = "str" } # original Template Name to duplicate
        newtemplatename  = @{ type = "str"; required = $true } #DNS Alias for Webaccess, CRL and AIA Location
        newkeylength     = @{ type = "int"; choices = 2048, 4096, 8192; default = 4096 }
        validyears       = @{ type = "int" ; choices = 1, 2, 3, 4, 5; default = 1 } #Cert Validity 1-5
        enrollment       = @{ type = "str" } #Set for a AD Group read and enrollment rights
        autoenrollment   = @{ type = "str" } #Set for a AD Group read and enroll and autoenrollment rights
        log_path         = @{ type = "str" } #Set loggingpath
        publishad        = @{ type = "bool"; default = $false } #Set for a AD Group read and enroll and autoenrollment rights
        domaincontroller = @{ type = "str"; aliases = @("dc"); $required = $true} #Defines domaincontroller
    }
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$check_mode = $module.CheckMode
$global:log_path = $module.Params.log_path
$winca_mode = $module.Params.mode
$winca_template_duplicate = $module.Params.originaltemplate
$winca_template_name = $module.Params.templatename
$winca_template_newkeylength = $module.Params.newkeylength
$winca_template_validyears = $module.Params.validyears
$winca_template_enrollment = $module.Params.enrollment
$winca_template_autoenrollment = $module.Params.autoenrollment
$winca_template_publishad = $module.Params.publishad
$winca_template_domaincontroller = $module.Params.domaincontroller

$missing_features = Get-MissingFeatures
If ($missing_features.Count -gt 0) {
    Write-DebugLog ("Missing Windows features ({0}), need to install" -f ($missing_features -join ", "))
    $module.result.changed = $true # we need to install features
    If ($check_mode) {
        # bail out here- we can't proceed without knowing the features are installed
        Write-DebugLog "check-mode, exiting early"
        $module.ExitJson()
    }
    Ensure-FeatureInstallation | Out-Null
}
if ($winca_mode -eq "manage") {
    If (-not $winca_template_duplicate) {
        #no Duplicate is specified
        $module.FailJson("duplicate is required when desired state is 'manage'")
    }
    $before = Get-WinCATemplate #get all existing templates
    if ($before.DisplayName -contains $winca_template_duplicate) {
        # Template for duplicating exists
        if ($before.DisplayName -notcontains $winca_template_name) {
            try {
                #Manage Windows CA Templates
                Set-WinCATemplate -Duplicate $winca_template_duplicate -NewTemplate $winca_template_name -NewKeyLength $winca_template_newkeylength -NewValidityYears $winca_template_validyears -AddEnrollment $winca_template_enrollment -AddAutoEnrollment $winca_template_autoenrollment -PublishAD $winca_template_publishad -domaincontroller $winca_template_domaincontroller
                $result.changed = $true
            } catch {
                $module.FailJson("an exception occurred when setting the Windows Certification Templates - $($_.Exception.Message)")
            }
        } else {
            #Template exists already
            $changes = $false
            #check argument
            $record = $before | Where-Object { $_.DisplayName -match $winca_template_name }
            if ($changes) {
                #ToDo Compare Changes
                if ($record.DisplayName ) {
                    #Set Stuff

                } else {
                    $module.result.changed = $false #nothing change
                }
            } else {
                $module.result.changed = $false #nothing change
            }
        }
    } else {
        #NO template for Duplicate found
        $module.FailJson("No Template for duplication found.")
    }
}
if ($winca_mode -eq "query") {
    try {
        # list only existing templates
        $output = Get-WinCATemplate
        $module.result.query_results = $output
        $module.result.changed = $false
    } catch {
        $module.FailJson("an exception occurred when listing the Windows Certification Template- $($_.Exception.Message)")
    }
}
$module.ExitJson()
