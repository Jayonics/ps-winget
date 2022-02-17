function InstallIdes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,ValueFromPipeline = $true,Position = 0)]
        [String]
        $IdeName,
        [Parameter()]
        [Switch]
        $Interactive,
        [Parameter()]
        [Switch]
        $Background
    )
    [string]$Command = "winget install "
    $Command += $IdeName
    switch ($Interactive) {
        $true {
            $Command += " -i"
            Write-Host "Command is: $Command"
        }
        $false {
            Write-Host "Command unchanged."
            Write-Host "Command is: $Command"
        }
    }
    switch ($Background) {
        $true {
            $Command = "Start-Job { $Command }"
            Write-Host "Command is: $Command"
        }
        $false {
            Write-Host "Command unchanged."
            Write-Host "Command is: $Command"
        }
    }
    & Invoke-Expression -Command $Command
    Write-Host -ForegroundColor:Blue "Installing $($IdeName)"

    if ($Background -eq $true) {
        return $Command
    }
}

$Jobs = @()
$IdesToInstall = @('"JetBrains.IntelliJIDEA.Ultimate"','"Microsoft.VisualStudio.2019.Community"')
ForEach ($Ide in $IdesToInstall) {
    $Ide | InstallIdes -Interactive -Background
    if ($null -ne $Command) { $Jobs += $Command }
}

if ($Jobs.Count -gt 0) {
    $Jobs | ForEach-Object {
        $_ | Wait-Job
    }
}

$ProgramProperties = @()# Object for storing information about the installed IDEs based on 2 registry searches.

# Goes through all 32bit programs and locates the IDEs,adds the properties DisplayName and InstallLocation to program properties
$UninstallRegPath32Bit = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\"
Set-Location "$UninstallRegPath32Bit"
$32BitPrograms = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\" -Recurse -Force
ForEach ($Program in $32BitPrograms) {
    $ProgramProperties += Get-ItemProperty -Path "$PWD\$($Program.PSChildName)" -Name DisplayName,InstallLocation -ErrorAction:SilentlyContinue | Where-Object {
        ($_.DisplayName -Like "IntelliJ IDEA*" `
                -or $_.DisplayName -EQ "Microsoft Visual Studio Code" `
                -or $_.DisplayName -Like "Visual Studio*")
    }
}

# Goes through all 64bit programs and locates the IDEs,adds the properties DisplayName and InstallLocation to program properties
$UninstallRegPath64Bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set-Location "$UninstallRegPath64Bit"
$64BitPrograms = Get-ChildItem -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -Recurse -Force
ForEach ($Program in $64BitPrograms) {
    $ProgramProperties += Get-ItemProperty -Path "$PWD\$($Program.PSChildName)" -Name DisplayName,InstallLocation -ErrorAction:SilentlyContinue | Where-Object {
        ($_.DisplayName -Like "IntelliJ IDEA*" `
                -or $_.DisplayName -EQ "Microsoft Visual Studio Code" `
                -or $_.DisplayName -Like "Visual Studio*")
    }
}

Write-Host -ForegroundColor:Yellow "Would you like to add compatibility flags 'Always Run as Administrator' for the IDEs?"
$UserInput = Read-Host -Prompt "Y or N"

# Appends the IDE main process executable names to the InstallLocation property.
ForEach ($Program in $ProgramProperties) {
    if ($Program.DisplayName -like "IntelliJ IDEA*") {
        $Program.InstallLocation += "\idea64.exe"
    }
    if ($Program.DisplayName -EQ "Microsoft Visual Studio Code") {
        $Program.InstallLocation += "code.exe"
    }
    if ($Program.DisplayName -Like "Visual Studio*") {
        $Program.InstallLocation += "\devenv.exe"
    }
}

Switch ($UserInput) {
    "Y" {
        # Adds the compatibility flags for 'Always Run as Administrator' to the registry (for all users)
        $AppCompatLocation = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
        ForEach ($Program in $ProgramProperties) {
            New-ItemProperty -Path "$AppCompatLocation\" -Name "$($Program.InstallLocation)"`
                -PropertyType "String" -Value ('~ RUNASADMIN') -Force
        }
    }
    "N" {
        Exit
    }
}
Set-Location -Path $PSScriptRoot
if(!$?){ Set-Location "C:\" }

Write-Host -ForegroundColor:Yellow "Would you like to add Windows Defender exclusions and/or remove mitigation protections for the IDEs?"
function Get-IdeSecurityPreferences {
    $ExclusionOptionsTable = @{
        "1" = "DefenderProcessExclusion - Excludes realtime scanning of paths opened by the IDE process."
        "2" = "DefenderPathExclusion - Excludes the IDE process its self."
        "3" = "ProcessMitigationExclusion - Adds the IDE process to exclusion of Security Mitigations (such as Spectre and Meltdown)"
    }
    $ExclusionOptionsTable | Format-Table
}
function Set-SecurityPreferences {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]
        $DisplayName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]
        $InstallLocation,
        [Parameter()]
        [Switch]
        $DefenderProcessExclusion,
        [Parameter()]
        [Switch]
        $DefenderPathExclusion,
        [Parameter()]
        [Switch]
        $ProcessMitigationExclusion,
        [Parameter()]
        [Switch]
        $AllExclusions
    )
    #Split the install location down to the process name.
    [string]$ProcessPath = ""
    [string]$ProcessName = ""
    $SplitInstallLocation = $InstallLocation.Split('\')
    For ($i = 0; $i -lt $SplitInstallLocation.Length; $i++) {
        if ($i -eq $SplitInstallLocation.Length - 1) {
            $ProcessName = $($SplitInstallLocation[$i])
        }
        else {
            $ProcessPath += $($SplitInstallLocation[$i]+"\")
        }
    }

    if ($AllExclusions -eq $true) {
        $DefenderPathExclusion,$DefenderProcessExclusion,$ProcessMitigationExclusion = $true
    } # Set all exclusion params to true if All is true


    Get-IdeSecurityPreferences

    Write-Host "$([Environment]::NewLine)"
    Write-Host -ForegroundColor:Red "Security preferences for $($DisplayName)"
    Write-Host -ForegroundColor:Yellow "Process Name: $($ProcessName)"
    Write-Host -ForegroundColor:Blue "Process path: $($ProcessPath)"

    # Start of exclusion tasks
    Switch ($DefenderProcessExclusion) {
        $true {
            Add-MpPreference -ExclusionProcess ($ProcessName) -Verbose -Force
        }
        $false {
            Remove-MpPreference -ExclusionProcess ($ProcessName) -Verbose -Force
        }
    }
    Switch ($DefenderPathExclusion) {
        $true {
            Add-MpPreference -ExclusionPath $ProcessPath -Verbose -Force
        }
        $false {
            Remove-MpPreference -ExclusionPath $ProcessPath -Verbose -Force
        }
    }
    Switch ($ProcessMitigationExclusion) {
        $true {
            Set-ProcessMitigation "$ProcessName" -Verbose -Disable DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess
        }
        $false {
            Set-ProcessMitigation "$ProcessName" -Verbose -Enable DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess
        }
    }
}

ForEach ($Program in $ProgramProperties) {
    $Program | Set-SecurityPreferences -DefenderProcessExclusion -DefenderPathExclusion -ProcessMitigationExclusion
}