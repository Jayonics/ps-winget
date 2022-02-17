$ProgrammingLanguagesNI = @('Microsoft.dotnetFramework','Microsoft.dotnetRuntime','Microsoft.dotnet')
$ProgrammingLanguagesI=@('Oracle.JavaRuntimeEnvironment','Python.Python','OpenJS.NodeJS')
$WindowsKits = @('Microsoft.WindowsADK', 'Microsoft.WindowsSDK', 'Microsoft.WindowsWDK')
$Editors = @('Notepad++.Notepad++', 'vim.vim')
$Shell = @('HermannSchinagl.LinkShellExtension')
$Filesystem = @('WinDirStat.WinDirStat', 'WinFsp.WinFsp', 'SSHFS-Win.SSHFS-Win')
$GitI = @('Git.Git')
$GitNI = @('TortoiseGit.TortoiseGit', 'TortoiseSVN.TortoiseSVN', 'Axosoft.GitKraken', 'PuTTY.PuTTY')
$IDEs = @('Microsoft.VisualStudio.2021.Community','Microsoft.VisualStudio.Code','JetBrains.IntelliJIDEA.Ultimate','JetBrains.CLion','JetBrains.dotUltimate')
$Consoles = @('Microsoft.Powershell')
$Networking = @('WiresharkFoundation.Wireshark', 'DebaucheeOpenSourceGroup.Barrier')
$Browsers = @('Mozilla.Firefox', 'Google.Chrome')
$Media = @('Spotify.Spotify', 'VideoLAN.VLC')
$FilesI = @('RARLab.WinRAR')
$FilesNI = @('PowerSoftware.PowerISO')
$Spelling = @('grammarly.GrammarlyForWindows', 'grammarly.grammarlyforoffice')
$Messaging = @('WhatsApp.WhatsApp', 'Discord.Discord')
$Games = @('Valve.Steam', 'EpicGames.EpicGamesLauncher')
$Drivers = @('SteelSeries.SteelSeriesEngine','Nvidia.GeForceExperience')
# Begin the installs.
function ProcessGroup {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        $Group,
        [Parameter()]
        [switch]$Interactive,
        [Parameter()]
        [int]$Limit,
        [Parameter()]
        [switch]$Hidden
    )
    function InstallApplication {
        param (
            [Parameter(Mandatory = $true)]
            $Application,
            [Parameter()]
            [switch]$Interactive,
            [Parameter()]
            [switch]$Hidden
        )
        Write-Host -ForegroundColor:Blue "Installing $Application"
        if (($Interactive -eq $true) -and ($hidden -eq $true)) {
            Write-Host -ForegroundColor:Red "Switches interactive and hidden cannot be run together."
            Throw
        } elseif (($Interactive -eq $true) -and ($hidden -ne $true)) {
            & Start-Process winget -ArgumentList ("install $Application -i") -PassThru -ErrorAction:SilentlyContinue
        } elseif (($Interactive -ne $true) -and ($hidden -eq $true)) {
            & Start-Process winget -ArgumentList ("install $Application -h") -PassThru -ErrorAction:SilentlyContinue
        } else {
            & Start-Process winget -ArgumentList ("install $Application") -PassThru -ErrorAction:SilentlyContinue
        }

        if ($?) {
            Write-Host -ForegroundColor:Green "$Application Installed."
        }
        elseif (!$?) {
            Write-Host -ForegroundColor:Red "$Application Failed installation."
        }
    }
    function InstallLimiter {
        param (
            [Parameter(Mandatory = $false)]
            [int]$Limit = $(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
        )
        if ($Limit -ge 1) {
            do {
                if($((Get-Process -Name "AppInstallerCli" -ErrorAction:SilentlyContinue).Count) -ge $Limit){
                    Start-Sleep -Seconds 1
                    Write-Host -ForegroundColor:Red "$((Get-Process -Name "AppInstallerCli" -ErrorAction:SilentlyContinue).Count)/$Limit installers running."
                } else {
                    Write-Host -ForegroundColor:Yellow "$((Get-Process -Name "AppInstallerCli" -ErrorAction:SilentlyContinue).Count)/$Limit installers running."
                }
            }
            until ((Get-Process -Name "AppInstallerCli" -ErrorAction:SilentlyContinue).Count -lt $Limit)
        }
        else {
            Write-Host -ForegroundColor:Blue "Install cap unlimited."
        }
    }

    foreach ($Application in $Group) {
        Write-Host -ForegroundColor:Blue "Installing $Application"
        if (($Interactive -eq $true) -and ($hidden -eq $true)) {
            Write-Host -ForegroundColor:Red "Switches interactive and hidden cannot be run together."
            Throw
        } elseif (($Interactive -eq $true) -and ($hidden -ne $true)) {
            InstallApplication -Application $Application -Interactive
        } elseif (($Interactive -ne $true) -and ($hidden -eq $true)) {
            InstallApplication -Application $Application -Hidden
        } else {
            InstallApplication -Application $Application
        }
        if ($null -ne $Limit) {
            InstallLimiter($Limit)
        }
    }
}

ProcessGroup -Group $ProgrammingLanguagesI -Limit 1 -Interactive
ProcessGroup -Group $ProgrammingLanguagesNI -Limit 1
ProcessGroup -Group $Consoles -Limit 1
ProcessGroup -Group $IDEs -Limit 1 -Interactive
ProcessGroup -Group $FilesI -Limit 1 -Interactive
ProcessGroup -Group $FilesNI -Limit 1
ProcessGroup -Group $Browsers -Limit 1
ProcessGroup -Group $Editors -Limit 1
ProcessGroup -Group $Media -Limit 2
ProcessGroup -Group $Spelling -Limit 2
ProcessGroup -Group $Messaging -Limit 2
ProcessGroup -Group $Games -Limit 2
ProcessGroup -Group $Networking -Limit 1
ProcessGroup -Group $Filesystem -Limit 1
ProcessGroup -Group $Shell -Limit 2
ProcessGroup -Group $GitI -Limit 1 -Interactive
ProcessGroup -Group $GitNI -Limit 1
ProcessGroup -Group $Drivers -Limit 1
ProcessGroup -Group $WindowsKits -Limit 1 -Interactive
