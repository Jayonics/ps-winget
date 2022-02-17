Start-Job -ScriptBlock { Start-Process winget -ArgumentList ("install Microsoft.Powershell -i") -PassThru -ErrorAction:SilentlyContinue } | Wait-Job
Do {
    Start-Sleep -Seconds 1
} Until ($null -eq (Get-Process -Name "AppInstallerCli" -ErrorAction:SilentlyContinue))

$ProgramProperties = @()# Object for storing information about the installed IDEs based on 2 registry searches.

# Goes through all 32bit programs and locates the IDEs, adds the properties DisplayName and InstallLocation to program properties
$UninstallRegPath32Bit = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\"
Set-Location "$UninstallRegPath32Bit"
$32BitPrograms = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\" -Recurse -Force
ForEach ($Program in $32BitPrograms){
    $ProgramProperties += Get-ItemProperty -Path "$PWD\$($Program.PSChildName)" -Name DisplayName,InstallLocation -ErrorAction:SilentlyContinue | Where-Object {
    ($_.DisplayName -Like "Powershell 7*")
    }
}

# Goes through all 64bit programs and locates the IDEs, adds the properties DisplayName and InstallLocation to program properties
$UninstallRegPath64Bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Set-Location "$UninstallRegPath64Bit"
$64BitPrograms = Get-ChildItem -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -Recurse -Force
ForEach ($Program in $64BitPrograms){
    $ProgramProperties += Get-ItemProperty -Path "$PWD\$($Program.PSChildName)" -Name DisplayName,InstallLocation -ErrorAction:SilentlyContinue | Where-Object {
    ($_.DisplayName -Like "Powershell 7*")
    }
}

foreach($Program in $ProgramProperties){
    if($Program.InstallLocation.Length -gt 1){
        $Program.InstallLocation +=  "\pwsh.exe"
    } else {
        Write-Host -ForegroundColor:Yellow "The installer did not provide an install location registry key."
        Write-Host -ForegroundColor:Yellow "Adding a RUNASADMIN flag with the default install location."
        $Program.InstallLocation = "$env:ProgramFiles\Powershell\7\pwsh.exe"
    }
}

$AppCompatLocation = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
ForEach ($Program in $ProgramProperties) {
    New-ItemProperty -Path "$AppCompatLocation\" -Name "$($Program.InstallLocation)"`
    -PropertyType "String" -Value ('~ RUNASADMIN') -Force
}