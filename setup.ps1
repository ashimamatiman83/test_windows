# PSScriptInfo
# .VERSION 1.0
# .DESCRIPTION
# Upgrades PowerShell version, installs WinRM hotfixes and activates WinRM.
# Execution trace is logged in $env:SystemRoot\Temp\ansible_setup_requirements.log
# 
# .PARAMETER AdminUserName
#   [string] - Administrator user name to execute the script. When user doesn't exist, it will be created. Default is AnsibleAdministrator. It is possible to assign the parameter with the environment variable ASR_ADMINUSERNAME.
#   
# .PARAMETER AdminPassword
#     [string] - Administrator password to execute the script. When not set, a random password is assigned to the user created. It is possible to assign the parameter with the environment variable ASR_ADMINPASSWORD.
#
# .PARAMETER AdminPasswordLenght
#     [int] - Administrator password length when the random password is assigned. Default is 32. It is possible to assign the parameter with the environment variable ASR_ADMINPASSWORDLENGTH.
#
# .PARAMETER Interactive
#     [switch] - Enable interactive prompts. Default is False. It is possible to assign the parameter with the environment variable ASR_INTERACTIVE.
#
# .PARAMETER SkipPowerShellUpgrade
#     [switch] - Skip PowerShell update. Default is False. It is possible to assign the parameter with the environment variable ASR_SKIP_POWERSHELLUPGRADE.
#
# .PARAMETER PowerShellUpgradeVersion
#     [string] - PowerShell upgrade version. Default is 5.1. It is possible to assign the parameter with the environment variable ASR_POWERSHELL_UPGRADEVERSION.
#
# .PARAMETER SkipWinRMHotfix
#     [switch] - Skip WinRM Hotfix installation. Default is False. It is possible to assign the parameter with the environment variable ASR_SKIP_POWERSHELLHOTFIX.
#
# .PARAMETER SkipWinRMSetup
#     [switch] - Skip WinRM configuration. Default is False. It is possible to assign the parameter with the environment variable ASR_SKIP_WINRMSETUP.
#
# .PARAMETER WinRMSetupSubjectName
#     [string] - SubjectName of the Certificate created for the WinRM listener. Default is %COMPUTERNAME%. It is possible to assign the parameter with the environment variable ASR_WINRMSETUP_SUBJECTNAME.
#
# .PARAMETER WinRMSetupCertValidityDays
#     [int] - Validity days of the certificate created for the WinRM listener.Default is 2 days. It is possible to assign the parameter with the environment variable ASR_WINRMSETUP_CERTVALIDITYDAYS.
#
# .PARAMETER WinRMSetupSkipNetworkProfileCheck
#     [switch] - Skip network profile check for the WinRM inbound firewall rules. Default is True. It is possible to assign the parameter with the environment variable ASR_WINRMSETUP_SKIPNETWORKPROFILECHECK.
#
# .PARAMETER WinRMSetupForceNewSSLCert
#     [switch] - Force the creation of a new certificate for the WinRM listener. Default is True. It is possible to assign the parameter with the environment variable ASR_WINRMSETUP_FORCENEWSSLCERT.
#
# .PARAMETER WinRMSetupGlobalHttpFirewallAccess
#     [switch] - Create a global HTTP firewall rule for the WinRM listener (ASR_WINRMSETUP_GLOBALHTTPFIREWALLACCESS). Default is False. It is possible to assign the parameter with the environment variable ASR_WINRMSETUP_GLOBALHTTPFIREWALLACCESS.
#
# .PARAMETER WinRMSetupDisableBasicAuth
#     [switch] - Disables Basic Authentication for the WinRM service. Default is True. It is possible to assign the parameter with the environment variable ASR_WINRMSETUP_DISABLEBASICAUTH.
#
# .PARAMETER WinRMSetupEnableCredSSP
#     [switch] - Enables CredSSP for the WinRM service. Default is False. It is possible to assign the parameter with the environment variable ASR_WINRMSETUP_ENABLECREDSSP.
#
# .PARAMETER SkipPowerShellOptimization
#     [switch] - Skip PowerShell optimization. Default is False. It is possible to assign the parameter with the environment variable ASR_SKIP_POWERSHELLOPTIMIZATION.
#
# .EXAMPLE
#     # upgrade from powershell 1.0 to 3.0 with automatic login and reboots
#     powershell.exe -ExecutionPolicy ByPass -File setup.ps1 -AdminUserName Administrator -AdminPassword Passw0rd! -PowerShellUpgradeVersion 3.0 -SkipWinRMHotfix -SkipWinRMSetup -Verbose
# .EXAMPLE
#     # upgrade to 5.1 with defaults and manual login and reboots
#     powershell.exe -ExecutionPolicy ByPass -File setup.ps1 -AdminUserName Administrator -AdminPassword Passw0rd! -SkipWinRMHotfix -SkipWinRMSetup -Verbose
# .EXAMPLE
#     # upgrade to 5.1 with defaults with default user and random password
#     powershell.exe -ExecutionPolicy ByPass -File setup.ps1 -SkipWinRMHotfix -SkipWinRMSetup -Verbose
# .EXAMPLE
#     # configure WinRM and install hotfixes with default user and random password
#     powershell.exe -ExecutionPolicy ByPass -File setup.ps1 -SkipPowerShellUpgrade -Verbose
# .EXAMPLE
#     # configure WinRM with a specific certificate subject name (vm.example.com) and with default user and random password
#     powershell.exe -ExecutionPolicy ByPass -File setup.ps1 -SkipPowerShellUpgrade -SkipWinRMHotfix -WinRMSetupSubjectName vm.example.com -Verbose

Param(
    # Common
    [Parameter(Mandatory=$false,HelpMessage="Administrator user name to execute the script (ASR_ADMINUSERNAME). When user doesn't exist, it will be created. Default is AnsibleAdministrator.")]
    [Alias("a")]
    [ValidateScript({($_).Length -gt 0})]
    [string]$AdminUserName = $(if($env:ASR_ADMINUSERNAME) {$env:ASR_ADMINUSERNAME} else {"AnsibleAdministrator"}),

    [Parameter(Mandatory=$false,HelpMessage="Administrator password to execute the script (ASR_ADMINPASSWORD). When not set, a random password is assigned to the user created.")]
    [Alias("p")]
    [ValidateScript({($_).Length -gt 0})]
    [string]$AdminPassword = $(if($env:ASR_ADMINPASSWORD) {$env:ASR_ADMINPASSWORD} else {$null}),

    [Parameter(Mandatory=$false,HelpMessage="Administrator password length (ASR_ADMINPASSWORDLENGTH) when the random password is assigned. Default is 32.")]
    [Alias("l")]
    [ValidateScript({($_).Length -gt 0})]
    [int]$AdminPasswordLenght = $(if($env:ASR_ADMINPASSWORDLENGTH) {$env:ASR_ADMINPASSWORDLENGTH} else {32}),

    [Parameter(Mandatory=$false,HelpMessage="Enable interactive prompts (ASR_INTERACTIVE). Default is False.")]
    [Alias("i")]
    [switch]$Interactive = $(if($env:ASR_INTERACTIVE) {if($env:ASR_INTERACTIVE -eq "True") {$true} else {$false}} else {$false}),

    # Upgrading PowerShell and .NET Framework
    [Parameter(Mandatory=$false,HelpMessage="Skip PowerShell update (ASR_SKIP_POWERSHELLUPGRADE). Default is False.")]
    [Alias("ps")]
    [switch]$SkipPowerShellUpgrade = $(if($env:ASR_SKIP_POWERSHELLUPGRADE) {if($env:ASR_SKIP_POWERSHELLUPGRADE -eq "True") {$true} else {$false}} else {$false}),

    [Parameter(Mandatory=$false,HelpMessage="PowerShell upgrade version (ASR_POWERSHELL_UPGRADEVERSION). Default is 5.1.")]
    [string]$PowerShellUpgradeVersion = $(if($env:ASR_POWERSHELL_UPGRADEVERSION) {$env:ASR_POWERSHELL_UPGRADEVERSION} else {"5.1"}),
    # WinRM Memory Hotfix
    [Parameter(Mandatory=$false,HelpMessage="Skip WinRM Hotfix installation (ASR_SKIP_POWERSHELLHOTFIX). Default is False.")]
    [Alias("hf")]
    [switch]$SkipWinRMHotfix = $(if($env:ASR_SKIP_POWERSHELLHOTFIX) {if($env:ASR_SKIP_POWERSHELLHOTFIX -eq "True") {$true} else {$false}} else {$false}),

    # WinRM Setup
    [Parameter(Mandatory=$false,HelpMessage="Skip WinRM configuration (ASR_SKIP_WINRMSETUP). Default is False.")]
    [Alias("wrm")]
    [switch]$SkipWinRMSetup = $(if($env:ASR_SKIP_WINRMSETUP) {if($env:ASR_SKIP_WINRMSETUP -eq "True") {$true} else {$false}} else {$false}),

    [Parameter(Mandatory=$false,HelpMessage="SubjectName of the Certificate created for the WinRM listener (ASR_WINRMSETUP_SUBJECTNAME). Default is %COMPUTERNAME%.")]
    [ValidateScript({($_).Length -gt 0})]
    [string]$WinRMSetupSubjectName = $(if($env:ASR_WINRMSETUP_SUBJECTNAME) {$env:ASR_WINRMSETUP_SUBJECTNAME} else {$env:COMPUTERNAME}),

    [Parameter(Mandatory=$false,HelpMessage="Validity days of the certificate created for the WinRM listener (ASR_WINRMSETUP_CERTVALIDITYDAYS).Default is 2 days.")]
    [ValidateScript({($_).Length -gt 0})]
    [int]$WinRMSetupCertValidityDays = $(if($env:ASR_WINRMSETUP_CERTVALIDITYDAYS) {$env:ASR_WINRMSETUP_CERTVALIDITYDAYS} else {2}),

    [Parameter(Mandatory=$false,HelpMessage="Skip network profile check for the WinRM inbound firewall rules (ASR_WINRMSETUP_SKIPNETWORKPROFILECHECK). Default is True.")]
    [switch]$WinRMSetupSkipNetworkProfileCheck = $(if($env:ASR_WINRMSETUP_SKIPNETWORKPROFILECHECK) {if($env:ASR_WINRMSETUP_SKIPNETWORKPROFILECHECK -eq "True") {$true} else {$false}} else {$false}),

    [Parameter(Mandatory=$false,HelpMessage="Force the creation of a new certificate for the WinRM listener (ASR_WINRMSETUP_FORCENEWSSLCERT). Default is True.")]
    [switch]$WinRMSetupForceNewSSLCert = $(if($env:ASR_WINRMSETUP_FORCENEWSSLCERT) {if($env:ASR_WINRMSETUP_FORCENEWSSLCERT -eq "True") {$true} else {$false}} else {$false}),

    [Parameter(Mandatory=$false,HelpMessage="Create a global HTTP firewall rule for the WinRM listener (ASR_WINRMSETUP_GLOBALHTTPFIREWALLACCESS). Default is False.")]
    [switch]$WinRMSetupGlobalHttpFirewallAccess = $(if($env:ASR_WINRMSETUP_GLOBALHTTPFIREWALLACCESS) {if($env:ASR_WINRMSETUP_GLOBALHTTPFIREWALLACCESS -eq "True") {$true} else {$false}} else {$false}),

    [Parameter(Mandatory=$false,HelpMessage="Disables Basic Authentication for the WinRM service (ASR_WINRMSETUP_DISABLEBASICAUTH). Default is True.")]
    [switch]$WinRMSetupDisableBasicAuth = $(if($env:ASR_WINRMSETUP_DISABLEBASICAUTH) {if($env:ASR_WINRMSETUP_DISABLEBASICAUTH -eq "True") {$true} else {$false}} else {$true}),

    [Parameter(Mandatory=$false,HelpMessage="Enables CredSSP for the WinRM service (ASR_WINRMSETUP_ENABLECREDSSP). Default is False.")]
    [switch]$WinRMSetupEnableCredSSP = $(if($env:ASR_WINRMSETUP_ENABLECREDSSP) {if($env:ASR_WINRMSETUP_ENABLECREDSSP -eq "True") {$true} else {$false}} else {$false}),

    # PowerShell Optimization
    [Parameter(Mandatory=$false,HelpMessage="Skip PowerShell optimization (ASR_SKIP_POWERSHELLOPTIMIZATION). Default is False.")]
    [Alias("pso")]
    [switch]$SkipPowerShellOptimization = $(if($env:ASR_SKIP_POWERSHELLOPTIMIZATION) {if($env:ASR_SKIP_POWERSHELLOPTIMIZATION -eq "True") {$true} else {$false}} else {$false})
)

# Get execution folder
$executionFolder = $script:MyInvocation.MyCommand.Path.Replace($script:MyInvocation.MyCommand.Name, "")

# Helper functions
function Optimize-PowershellAssemblies {
# NGEN powershell assembly, improves startup time of powershell by 10x
$old_path = $env:path
    try {
        $env:path = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
        [AppDomain]::CurrentDomain.GetAssemblies() | % {
            if (! $_.location) {continue}
            $Name = Split-Path $_.location -leaf
            if ($Name.startswith("Microsoft.PowerShell.")) {
                Write-Progress -Activity "Native Image Installation" -Status "$name"
                ngen install $_.location | % {"`t$_"}
            }
        }
    } finally {
        $env:path = $old_path
    }
}
  
Function Generate-Strong-Password ([Parameter(Mandatory=$true)][int]$PasswordLenght) {
    Add-Type -AssemblyName System.Web
    $PassComplexCheck = $false
    do {
        $newPassword=[System.Web.Security.Membership]::GeneratePassword($PasswordLenght,1)
        If ( ($newPassword -cmatch "[A-Z\p{Lu}\s]") `
        -and ($newPassword -cmatch "[a-z\p{Ll}\s]") `
        -and ($newPassword -match "[\d]") `
        -and ($newPassword -match "[^\w]")
        ) {
            $PassComplexCheck=$True
        }
    } While ($PassComplexCheck -eq $false)
    return $newPassword
}

Function Get-ServiceAndWait ($serviceName) {
    $retries = 7
    $waitTime = 14

    $service = $null
    $ret = 0
    do {
        try {
            $service = Get-Service $serviceName
        } catch {
            $error_msg = "Service not responding."
            Write-Log -message "Service manager not responding..."
        }
        $ret++
        if ($service -ne $null) {sleep $waitTime}
    } while (($ret -le $retries) -And ($service -eq $null))
    Write-Log -message $service
    Write-Log -message $service.Status
    return $service
}

Function Write-Log($message, $level="INFO") {
    # Create Temp folder when it does not exists
    $tmp_dir = "$env:SystemRoot\Temp\"
    # Poor man's implementation of Log4Net
    $date_stamp = Get-Date -Format s
    $log_entry = "$date_stamp - $level - $message"
    $log_file = "$tmp_dir\ansible_setup_requirements.log"
    Write-Verbose -Message $log_entry
    Add-Content -Path $log_file -Value $log_entry
}

Function Reboot-AndResume ($username, $password, $interactive, $scriptParams) {
    Write-Log -message "adding script to run on next logon"
    $script_path = $script:MyInvocation.MyCommand.Path
    $ps_path = "$env:SystemDrive\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    Write-Host $scriptParams
    $command = "$ps_path -ExecutionPolicy ByPass -File $script_path " + $scriptParams
    Write-Log -message "next logon execution $command"
    $reg_key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $reg_property_name = "ps-upgrade"
    Set-ItemProperty -Path $reg_key -Name $reg_property_name -Value $command

    if ($username -and $password) {
        $reg_winlogon_path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty -Path $reg_winlogon_path -Name AutoAdminLogon -Value 1
        Set-ItemProperty -Path $reg_winlogon_path -Name DefaultUserName -Value $username
        Set-ItemProperty -Path $reg_winlogon_path -Name DefaultPassword -Value $password
        Write-Log -message "rebooting server to continue ansible requirements setup"
    } else {
        Write-Log -message "need to reboot server to continue ansible requirements setup"
        $reboot_confirmation = "y"
        if ($interactive -eq $true) {
            $reboot_confirmation = Read-Host -Prompt "need to reboot server to continue with ansible requirements setup, do you wish to proceed (y/n)"
        }
        if ($reboot_confirmation -ne "y") {
            $error_msg = "please reboot server manually and login to continue upgrade process, the script will restart on the next login automatically"
            Write-Log -message $error_msg -level "ERROR"
            throw $error_msg
        }
    }
    if (Get-Command -Name Restart-Computer -ErrorAction SilentlyContinue) {
        Restart-Computer -Force
        exit 0
    } else {
        # PS v1 (Server 2008) doesn't have the cmdlet Restart-Computer, use el-traditional
        shutdown /r /t 0
        exit 0
    }
}

Function Run-Process($executable, $arguments) {
    $process = New-Object -TypeName System.Diagnostics.Process
    $psi = $process.StartInfo
    $psi.FileName = $executable
    $psi.Arguments = $arguments

    Write-Log -message "starting new process '$executable $arguments'"
    $process.Start() | Out-Null
    
    $process.WaitForExit() | Out-Null
    $exit_code = $process.ExitCode
    Write-Log -message "process completed with exit code '$exit_code'"

    return $exit_code
}

Function Download-File($url, $path) {
    Write-Log -message "downloading url '$url' to '$path'"
    $client = New-Object -TypeName System.Net.WebClient
    $client.DownloadFile($url, $path)
}

Function Clear-AutoLogon {
    $reg_winlogon_path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Write-Log -message "clearing auto logon registry properties"
    Set-ItemProperty -Path $reg_winlogon_path -Name AutoAdminLogon -Value 0
    Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultUserName -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultPassword -ErrorAction SilentlyContinue
}

Function Download-Wmf5Server2008($dir, $architecture) {
    if ($architecture -eq "x64") {
        $zip_url = "http://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip"
        $file = "$dir\Win7AndW2K8R2-KB3191566-x64.msu"
    } else {
        $zip_url = "http://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7-KB3191566-x86.zip"
        $file = "$dir\Win7-KB3191566-x86.msu"
    }
    if (Test-Path -Path $file) {
        return $file
    }

    $filename = $zip_url.Split("/")[-1]
    $zip_file = "$dir\$filename"
    Download-File -url $zip_url -path $zip_file

    Write-Log -message "extracting '$zip_file' to '$dir'"
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem > $null
        $legacy = $false
    } catch {
        $legacy = $true
    }

    if ($legacy) {
        $shell = New-Object -ComObject Shell.Application
        $zip_src = $shell.NameSpace($zip_file)
        $zip_dest = $shell.NameSpace($dir)
        $zip_dest.CopyHere($zip_src.Items(), 1044)
    } else {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zip_file, $dir)
    }
    return $file
}

Function New-LegacySelfSignedCert($SubjectName, $ValidDays = 1095)
{
    $hostnonFQDN = $env:computerName
    $hostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname
    $SignatureAlgorithm = "SHA256"

    $name = New-Object -COM "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$SubjectName", 0)

    $key = New-Object -COM "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 4096
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.Create()

    $serverauthoid = New-Object -COM "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = New-Object -COM "X509Enrollment.CObjectIds.1"
    $ekuoids.Add($serverauthoid)
    $ekuext = New-Object -COM "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = New-Object -COM "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = (Get-Date).AddDays(-1)
    $cert.NotAfter = $cert.NotBefore.AddDays($ValidDays)

    $SigOID = New-Object -ComObject X509Enrollment.CObjectId
    $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)

    [string[]] $AlternativeName  += $hostnonFQDN
    $AlternativeName += $hostFQDN
    $IAlternativeNames = New-Object -ComObject X509Enrollment.CAlternativeNames

    foreach ($AN in $AlternativeName) {
        $AltName = New-Object -ComObject X509Enrollment.CAlternativeName
        $AltName.InitializeFromString(0x3,$AN)
        $IAlternativeNames.Add($AltName)
    }

    $SubjectAlternativeName = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $SubjectAlternativeName.InitializeEncode($IAlternativeNames)

    [String[]]$KeyUsage = ("DigitalSignature", "KeyEncipherment")
    $KeyUsageObj = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
    $KeyUsageObj.InitializeEncode([int][Security.Cryptography.X509Certificates.X509KeyUsageFlags]($KeyUsage))
    $KeyUsageObj.Critical = $true

    $cert.X509Extensions.Add($KeyUsageObj)
    $cert.X509Extensions.Add($ekuext)
    $cert.SignatureInformation.HashAlgorithm = $SigOID
    $CERT.X509Extensions.Add($SubjectAlternativeName)
    $cert.Encode()

    $enrollment = New-Object -COM "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")

    # extract/return the thumbprint from the generated cert
    $parsed_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $parsed_cert.Import([System.Text.Encoding]::UTF8.GetBytes($certdata))

    return $parsed_cert.Thumbprint
}

Function Enable-GlobalHttpFirewallAccess {
    Write-Log -message "Forcing global HTTP firewall access"
    # this is a fairly naive implementation; could be more sophisticated about rule matching/collapsing
    $fw = New-Object -ComObject HNetCfg.FWPolicy2

    # try to find/enable the default rule first
    $add_rule = $false
    $matching_rules = $fw.Rules | Where-Object  { $_.Name -eq "Windows Remote Management (HTTP-In)" }
    $rule = $null
    If ($matching_rules) {
        If ($matching_rules -isnot [Array]) {
            Write-Log -message "Editing existing single HTTP firewall rule"
            $rule = $matching_rules
        }
        Else {
            # try to find one with the All or Public profile first
            Write-Log -message "Found multiple existing HTTP firewall rules..."
            $rule = $matching_rules | ForEach-Object { $_.Profiles -band 4 }[0]

            If (-not $rule -or $rule -is [Array]) {
                Write-Log -message "Editing an arbitrary single HTTP firewall rule (multiple existed)"
                # oh well, just pick the first one
                $rule = $matching_rules[0]
            }
        }
    }

    If (-not $rule) {
        Write-Log -message "Creating a new HTTP firewall rule"
        $rule = New-Object -ComObject HNetCfg.FWRule
        $rule.Name = "Windows Remote Management (HTTP-In)"
        $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]"
        $add_rule = $true
    }

    $rule.Profiles = 0x7FFFFFFF
    $rule.Protocol = 6
    $rule.LocalPorts = 5985
    $rule.RemotePorts = "*"
    $rule.LocalAddresses = "*"
    $rule.RemoteAddresses = "*"
    $rule.Enabled = $true
    $rule.Direction = 1
    $rule.Action = 1
    $rule.Grouping = "Windows Remote Management"

    If ($add_rule) {
        $fw.Rules.Add($rule)
    }

    Write-Log -message "HTTP firewall rule $($rule.Name) updated"
}

# Set error handling.
Trap {
    $_
    Exit 1
}
# Set default action on error
$ErrorActionPreference = 'Stop'

# Set default action on verbose
if ($verbose -eq $true) {
    $VerbosePreference = "Continue"
}

# Save script args for reboots
$scriptArguments = ""
foreach($psbp in $PSBoundParameters.GetEnumerator()) {
     $scriptArguments += "-{0} {1} " -f $psbp.Key,$psbp.Value
}

# Create Temp folder if does not exist
$tempDirectory = "$env:SystemRoot\Temp\"
if (-not (Test-Path -Path $tempDirectory)) {
    Write-Log -dir  -message "creating temp folder"
    New-Item -Path $tempDirectory -ItemType Directory > $null
}

# Main
Write-Log -message "starting script"

# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

# Check to see if we are currently running "as Administrator"
if (-Not $myWindowsPrincipal.IsInRole($adminRole)) {
    $error_msg = "Required elevated Administrator privileges in order to run this script."
    Write-Log -message $error_msg -level "ERROR"
    throw $error_msg
}

# Create Admin user when it does not exists
$UserExistsWMI = [bool](Get-WMIObject -ClassName Win32_UserAccount -Computername $env:ComputerName | Where-Object Name -eq $AdminUserName)
if(-not ($UserExistsWMI)) {
    # Generate random password when not set
    if (-not ($AdminPassword)) {
        $AdminPassword = Generate-Strong-Password($AdminPasswordLenght)
    }
    # Convert AdminPassword to SecureString
    $AdminPasswordSecure = $AdminPassword | ConvertTo-SecureString -AsPlainText -Force
    # Create admin user
    Write-Log -message "creating user $AdminUserName"
    New-LocalUser $AdminUserName -Password $AdminPasswordSecure > $null
    # Add user to administrators
    Write-Log -message "Including user $AdminUserName in Administrators"
    Add-LocalGroupMember -Group "Administrators" -Member $AdminUserName > $null
}

#
# Upgrading PowerShell and .NET Framework
#
if($SkipPowerShellUpgrade -eq $false) {
    Write-Log -message "Upgrading PowerShell and .NET Framework"
    $PowerShellUpgradeFinished = $false
    # on PS v1.0, upgrade to 2.0 and then run the script again
    if ($PSVersionTable -eq $null) {
        Write-Log -message "upgrading powershell v1.0 to v2.0"
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($architecture -eq "AMD64") {
            $url = "https://download.microsoft.com/download/2/8/6/28686477-3242-4E96-9009-30B16BED89AF/Windows6.0-KB968930-x64.msu"
        } else {
            $url = "https://download.microsoft.com/download/F/9/E/F9EF6ACB-2BA8-4845-9C10-85FC4A69B207/Windows6.0-KB968930-x86.msu"
        }
        $filename = $url.Split("/")[-1]
        $file = "$tmp_dir\$filename"
        Download-File -url $url -path $file
        $exit_code = Run-Process -executable $file -arguments "/quiet /norestart"
        if ($exit_code -ne 0 -and $exit_code -ne 3010) {
            $error_msg = "failed to update Powershell from 1.0 to 2.0: exit code $exit_code"
            Write-Log -message $error_msg -level "ERROR"
            throw $error_msg
        }
    }

    # skip if the target version is the same as the actual version
    $current_ps_version = [version]"$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
    if ($current_ps_version -eq [version]$PowerShellUpgradeVersion) {
        Write-Log -message "current and target PS version are the same, no action is required"
        Clear-AutoLogon
    }
    else {
        $os_version = [Version](Get-Item -Path "$env:SystemRoot\System32\kernel32.dll").VersionInfo.ProductVersion
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($architecture -eq "AMD64") {
            $architecture = "x64"
        } else {
            $architecture = "x86"
        }

        $actions = @()
        switch ($PowerShellUpgradeVersion) {
            "3.0" {
                $actions += "3.0"
                break
            }
            "4.0" {
                if ($os_version -lt [version]"6.1") {
                    $error_msg = "cannot upgrade Server 2008 to Powershell v4, v3 is the latest supported"
                    Write-Log -message $error_msg -level "ERROR"
                    throw $error_msg
                }
                $actions += "4.0"
                break
            }
            "5.1" {
                if ($os_version -lt [version]"6.1") {
                    $error_msg = "cannot upgrade Server 2008 to Powershell v5.1, v3 is the latest supported"
                    Write-Log -message $error_msg -level "ERROR"
                    throw $error_msg
                }
                # check if WMF 3 is installed, need to be uninstalled before 5.1
                if ($os_version.Minor -lt 2) {
                    $wmf3_installed = Get-Hotfix -Id "KB2506143" -ErrorAction SilentlyContinue
                    if ($wmf3_installed) {
                        $actions += "remove-3.0"
                    }
                }
                $actions += "5.1"
                break
            }
            default {
                $error_msg = "version '$PowerShellUpgradeVersion' is not supported in this upgrade script"
                Write-Log -message $error_msg -level "ERROR"
                throw $error_msg
            }
        }

        # detect if .NET 4.5.2 is not installed and add to the actions
        $dotnet_path = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        if (-not (Test-Path -Path $dotnet_path)) {
            $dotnet_upgrade_needed = $true
        } else {
            $dotnet_version = Get-ItemProperty -Path $dotnet_path -Name Release -ErrorAction SilentlyContinue
            if ($dotnet_version) {
                # 379893 == 4.5.2
                if ($dotnet_version.Release -lt 379893) {
                    $dotnet_upgrade_needed = $true
                }        
            } else {
                $dotnet_upgrade_needed = $true
            }
        }
        if ($dotnet_upgrade_needed) {
            $actions = @("dotnet") + $actions
        }

        Write-Log -message "The following actions will be performed: $($actions -join ", ")"
        foreach ($action in $actions) {
            $url = $null
            $file = $null
            $arguments = "/quiet /norestart"

            switch ($action) {
                "dotnet" {
                    Write-Log -message "running .NET update to 4.5.2"
                    $url = "https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe"
                    $error_msg = "failed to update .NET to 4.5.2"
                    $arguments = "/q /norestart"
                    break
                }
                "remove-3.0" {
                    # this is only run before a 5.1 install on Windows 7/2008 R2, the
                    # install zip needs to be downloaded and extracted before
                    # removing 3.0 as then the FileSystem assembly cannot be loaded
                    Write-Log -message "downloading WMF/PS v5.1 and removing WMF/PS v3 before version 5.1 install"
                    Download-Wmf5Server2008 -dir $tempDirectory -architecture $architecture > $null

                    $file = "wusa.exe"
                    $arguments = "/uninstall /KB:2506143 /quiet /norestart"
                    break
                }
                "3.0" {
                    Write-Log -message "running powershell update to version 3"    
                    if ($os_version.Minor -eq 1) {
                        $url = "https://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-$($architecture).msu"
                    } else {
                        $url = "https://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.0-KB2506146-$($architecture).msu"
                    }
                    $error_msg = "failed to update Powershell to version 3"
                    break
                }
                "4.0" {
                    Write-Log -message "running powershell update to version 4"
                    if ($os_version.Minor -eq 1) {
                        $url = "https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-$($architecture)-MultiPkg.msu"
                    } else {
                        $url = "https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows8-RT-KB2799888-x64.msu"
                    }
                    $error_msg = "failed to update Powershell to version 4"
                    break
                }
                "5.1" {
                    Write-Log -message "running powershell update to version 5.1"
                    if ($os_version.Minor -eq 1) {
                        # Server 2008 R2 and Windows 7, already downloaded in remove-3.0
                        $file = Download-Wmf5Server2008 -dir $tempDirectory -architecture $architecture
                    } elseif ($os_version.Minor -eq 2) {
                        # Server 2012
                        $url = "http://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/W2K12-KB3191565-x64.msu"
                    } else {
                        # Server 2012 R2 and Windows 8.1
                        if ($architecture -eq "x64") {
                            $url = "http://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu"
                        } else {
                            $url = "http://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1-KB3191564-x86.msu"
                        }
                    }
                    break
                }
                default {
                    $error_msg = "unknown action '$action'"
                    Write-Log -message $error_msg -level "ERROR"
                }
            }

            if ($file -eq $null) {
                $filename = $url.Split("/")[-1]
                $file = "$tmp_dir\$filename"
            }
            if ($url -ne $null) {
                Download-File -url $url -path $file
            }
    
            $exit_code = Run-Process -executable $file -arguments $arguments
            if ($exit_code -ne 0 -and $exit_code -ne 3010) {
                $error_msg = "$($error_msg): exit code $exit_code"
                Write-Log -message $error_msg -level "ERROR"
                throw $error_msg
            }
            if ($exit_code -eq 3010) {
                Reboot-AndResume -username $AdminUserName -password $AdminPassword -interactive $Interactive -scriptParams $scriptArguments
                break
            }
        }
    }
}
#
# WinRM Memory Hotfix
#
if(-not $SkipWinRMHotfix -eq $false) {
    $kb = "KB2842230"
    if ($PSVersionTable.PSVersion.Major -ne 3) {
        Write-Log -message "$kb is only applicable with Powershell v3, no action required"
    }
    else
    {
        $hotfix_installed = Get-Hotfix -Id $kb -ErrorAction SilentlyContinue
        if ($hotfix_installed -ne $null) {
            Write-Log -message "$kb is already installed"
            Clear-AutoLogon
        }
        else {
            $os_version = [Version](Get-Item -Path "$env:SystemRoot\System32\kernel32.dll").VersionInfo.ProductVersion
            $host_string = "$($os_version.Major).$($os_version.Minor)-$($env:PROCESSOR_ARCHITECTURE)"
            switch($host_string) {
                # These URLS point to the Ansible Core CI S3 bucket, MS no longer provide a link to Server 2008 so we need to
                # rely on this URL. There are no guarantees this will stay up in the future.
                "6.0-x86" {
                    $url = "https://s3.amazonaws.com/ansible-ci-files/hotfixes/KB2842230/464091_intl_i386_zip.exe"
                }
                "6.0-AMD64" {
                    $url = "https://s3.amazonaws.com/ansible-ci-files/hotfixes/KB2842230/464090_intl_x64_zip.exe"
                }
                "6.1-x86" {
                    $url = "https://s3.amazonaws.com/ansible-ci-files/hotfixes/KB2842230/463983_intl_i386_zip.exe"
                }
                "6.1-AMD64" {
                    $url = "https://s3.amazonaws.com/ansible-ci-files/hotfixes/KB2842230/463984_intl_x64_zip.exe"
                }
                "6.2-x86" {
                    $url = "https://s3.amazonaws.com/ansible-ci-files/hotfixes/KB2842230/463940_intl_i386_zip.exe"
                }
                "6.2-AMD64" {
                    $url = "https://s3.amazonaws.com/ansible-ci-files/hotfixes/KB2842230/463941_intl_x64_zip.exe"
                }
            }
            $filename = $url.Split("/")[-1]
            $compressed_file = "$tempDirectory\$($filename).zip"
            Download-File -url $url -path $compressed_file
            Extract-Zip -zip $compressed_file -dest $tmp_dir
            $file = Get-Item -Path "$tempDirectory\*$kb*.msu"
            if ($file -eq $null) {
                $error_msg = "unable to find extracted msu file for hotfix KB"
                Write-Log -message $error_msg -level "ERROR"
                throw $error_msg
            }

            $exit_code = Run-Process -executable $file.FullName -arguments "/quiet /norestart"
            if ($exit_code -eq 3010) {
                Write-Log -message "need to restart computer after hotfix $kb install"
                Reboot-AndResume -username $AdminUserName -password $AdminPassword -interactive $Interactive -scriptParams $scriptArguments
            } elseif ($exit_code -ne 0) {
                $error_msg = "failed to install hotfix $($kb): exit code $exit_code"
                Write-Log -message $error_msg -level "ERROR"
                throw $error_msg
            } else {
                Write-Log -message "hotfix $kb install complete"
            }
        }
    }
}
#
# WinRM Setup
#
if($SkipWinRMSetup -eq $false) {
    # Detect PowerShell version.
    If ($PSVersionTable.PSVersion.Major -lt 3) {
        $error_msg = "PowerShell version 3 or higher is required."
        Write-Log -message $error_msg -level "ERROR"
        throw $error_msg
    }

    # Find and start the WinRM service.
    Write-Log -message "Verifying WinRM service."
    $service = Get-ServiceAndWait ("WinRM")
    If (-not $service) {
        $error_msg = "Unable to find the WinRM service."
        Write-Log -message $error_msg -level "ERROR"
        throw $error_msg
    } elseIf ($service.Status -ne "Running") {
        Write-Log -message "Setting WinRM service to start automatically on boot."
        Set-Service -Name "WinRM" -StartupType Automatic
        Write-Log -message "Starting WinRM service."
        Start-Service -Name "WinRM" -ErrorAction Stop
    }
    Write-Log -message "Get-PSSessionConfiguration"
    # WinRM should be running; check that we have a PS session config.
    If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener))) {
      If ($WinRMSetupSkipNetworkProfileCheck -eq $false) {
        Write-Log -message "Enabling PS Remoting without checking Network profile."
        $VerbosePreference = "SilentlyContinue"
        Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
        $VerbosePreference = "Continue"
      } else {
        Write-Log -message "Enabling PS Remoting."
        $VerbosePreference = "SilentlyContinue"
        Enable-PSRemoting -Force -ErrorAction Stop
        $VerbosePreference = "Continue"
      }
    } else {
        Write-Log -message "PS Remoting is already enabled."
    }

    # Ensure LocalAccountTokenFilterPolicy is set to 1
    # https://github.com/ansible/ansible/issues/42978
    $token_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $token_prop_name = "LocalAccountTokenFilterPolicy"
    $token_key = Get-Item -Path $token_path
    $token_value = $token_key.GetValue($token_prop_name, $null)
    if ($token_value -ne 1) {
        Write-Log -message "Setting LocalAccountTOkenFilterPolicy to 1"
        if ($null -ne $token_value) {
            Remove-ItemProperty -Path $token_path -Name $token_prop_name
        }
        New-ItemProperty -Path $token_path -Name $token_prop_name -Value 1 -PropertyType DWORD > $null
    }

    # Make sure there is a SSL listener.
    $listeners = Get-ChildItem WSMan:\localhost\Listener
    If (!($listeners | Where-Object {$_.Keys -like "TRANSPORT=HTTPS"})) {
        # We cannot use New-SelfSignedCertificate on 2012R2 and earlier
        $thumbprint = New-LegacySelfSignedCert -SubjectName $WinRMSetupSubjectName -ValidDays $WinRMSetupCertValidityDays
        Write-Log -message "Self-signed SSL certificate generated; thumbprint: $thumbprint"

        # Create the hashtables of settings to be used.
        $valueset = @{
            Hostname = $WinRMSetupSubjectName
            CertificateThumbprint = $thumbprint
        }
        $selectorset = @{
            Transport = "HTTPS"
            Address = "*"
        }

        Write-Log -message "Enabling SSL listener."
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
    } else {
        Write-Log -message "SSL listener is already active."

        # Force a new SSL cert on Listener if the $ForceNewSSLCert
        If ($WinRMSetupForceNewSSLCert -eq $true)
        {
            # We cannot use New-SelfSignedCertificate on 2012R2 and earlier
            $thumbprint = New-LegacySelfSignedCert -SubjectName $WinRMSetupSubjectName -ValidDays $WinRMSetupCertValidityDays
            Write-Log -message "Self-signed SSL certificate generated; thumbprint: $thumbprint"

            $valueset = @{
                CertificateThumbprint = $thumbprint
                Hostname = $WinRMSetupSubjectName
            }
            # Delete the listener for SSL
            $selectorset = @{
                Address = "*"
                Transport = "HTTPS"
            }
            Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset
            # Add new Listener with new SSL cert
            New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
        }
    }

    # Check for basic authentication.
    $basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object {$_.Name -eq "Basic"}

    If ($WinRMSetupDisableBasicAuth -eq $true)
    {
        If (($basicAuthSetting.Value) -eq $true)
        {
            Write-Log -message "Disabling basic auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false
        } else {
            Write-Log -message "Basic auth is already disabled."
        }
    } else {
        If (($basicAuthSetting.Value) -eq $false) {
            Write-Log -message "Enabling basic auth support."
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
        } else {
            Write-Log -message "Basic auth is already enabled."
        }
    }

    # If EnableCredSSP if set to true
    If ($WinRMSetupEnableCredSSP -eq $true) {
        # Check for CredSSP authentication
        $credsspAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object {$_.Name -eq "CredSSP"}
        If (($credsspAuthSetting.Value) -eq $false) {
            Write-Log -message "Enabling CredSSP auth support."
            Enable-WSManCredSSP -role server -Force
        }
    }

    If ($WinRMSetupGlobalHttpFirewallAccess -eq $true) {
        Enable-GlobalHttpFirewallAccess
    }

    # Configure firewall to allow WinRM HTTPS connections.
    $fwtest1 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS"
    $fwtest2 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS" profile=any
    If ($fwtest1.count -lt 5) {
        Write-Log -message "Adding firewall rule to allow WinRM HTTPS."
        netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow
    } elseIf (($fwtest1.count -ge 5) -and ($fwtest2.count -lt 5)) {
        Write-Log -message "Updating firewall rule to allow WinRM HTTPS for any profile."
        netsh advfirewall firewall set rule name="Allow WinRM HTTPS" new profile=any
    } else {
        Write-Log -message "Firewall rule already exists to allow WinRM HTTPS."
    }

    # Test a remoting connection to localhost, which should work.
    $httpResult = Invoke-Command -ComputerName "localhost" -ScriptBlock {$env:COMPUTERNAME} -ErrorVariable httpError -ErrorAction SilentlyContinue
    $httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

    $httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions -ErrorVariable httpsError -ErrorAction SilentlyContinue

    If ($httpResult -and $httpsResult) {
        Write-Log -message "HTTP: Enabled | HTTPS: Enabled"
    } elseIf ($httpsResult -and !$httpResult) {
        Write-Log -message "HTTP: Disabled | HTTPS: Enabled"
    } elseIf ($httpResult -and !$httpsResult) {
        Write-Log -message "HTTP: Enabled | HTTPS: Disabled"
    } else {
        Write-Log -message "Unable to establish an HTTP or HTTPS remoting session."
        Throw "Unable to establish an HTTP or HTTPS remoting session."
    }
    Write-Log -message "PS Remoting has been successfully configured for Ansible."
}
#
# PowerShell Optimization
#
if($SkipPowerShellOptimization -eq $false) {
    Write-Log -message "Optimizing PowerShell"
    Optimize-PowershellAssemblies
    Write-Log -message "PowerShell optimized"
}
