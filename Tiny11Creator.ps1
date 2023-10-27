[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$Source,
    [uint16]$ImageIndex = 0,
    [string]$ScratchDir = 'C:\scratchdir',
    [string]$BuildDir = 'C:\tiny11',
    [string]$Output = (Join-Path $PSScriptRoot 'tiny11.iso'),
    [int]$MaxRegOperationAttempts = 100,
    [int]$MaxImageOperationAttempts = 10,
    [switch]$Cleanup
)
begin {
    Push-Location $PSScriptRoot -StackName Tiny11Creator

    $OldTitle = $Host.UI.RawUI.WindowTitle
    $Host.UI.RawUI.WindowTitle = 'Tiny11 builder'

    $ImageFiles = @(
        'sources\boot.wim'
        'sources\install.wim'
    )

    $AppXProvisionedToRemove = @(
        @{ Name = 'Clipchamp'; Filter = 'Clipchamp\.Clipchamp_.+_neutral_~_yxz26nhyzhsrt' }
        @{ Name = 'Bing News'; Filter = 'Microsoft\.BingNews_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Bing Weather'; Filter = 'Microsoft\.BingWeather_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Xbox'; Filter = 'Microsoft\.GamingApp_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Get Help'; Filter = 'Microsoft\.GetHelp_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Get Started'; Filter = 'Microsoft\.Getstarted_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Office Hub'; Filter = 'Microsoft\.MicrosoftOfficeHub_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Solitaire'; Filter = 'Microsoft\.MicrosoftSolitaireCollection_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'People App'; Filter = 'Microsoft\.People_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'PowerAutomate'; Filter = 'Microsoft\.PowerAutomateDesktop_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'ToDo'; Filter = 'Microsoft\.Todos_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Alarms'; Filter = 'Microsoft\.WindowsAlarms_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Mail'; Filter = 'microsoft\.windowscommunicationsapps_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Feedback Hub'; Filter = 'Microsoft\.WindowsFeedbackHub_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Maps'; Filter = 'Microsoft\.WindowsMaps_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Sound Recorder'; Filter = 'Microsoft\.WindowsSoundRecorder_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'XboxTCUI'; Filter = 'Microsoft\.Xbox\.TCUI_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'XboxGamingOverlay'; Filter = 'Microsoft\.XboxGamingOverlay_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'XboxGameOverlay'; Filter = 'Microsoft\.XboxGameOverlay_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'XboxSpeechToTextOverlay'; Filter = 'Microsoft\.XboxSpeechToTextOverlay_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Your Phone App'; Filter = 'Microsoft\.YourPhone_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Zune Music'; Filter = 'Microsoft\.ZuneMusic_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Zune Video'; Filter = 'Microsoft\.ZuneVideo_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Microsoft Family'; Filter = 'MicrosoftCorporationII\.MicrosoftFamily_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'QuickAssist'; Filter = 'MicrosoftCorporationII\.QuickAssist_.+_neutral_~_8wekyb3d8bbwe' }
        @{ Name = 'Teams'; Filter = 'MicrosoftTeams_.+_x64__8wekyb3d8bbwe' }
        @{ Name = 'Cortana'; Filter = 'Microsoft\.549981C3F5F10_.+_neutral_~_8wekyb3d8bbwe' }
    )

    $FeaturesToRemove = @(
        @{ Name = 'Internet Explorer'; Filter = 'Microsoft-Windows-InternetExplorer-Optional-Package~' }
        @{ Name = 'Intel 5-level paging (LA57)'; Filter = 'Microsoft-Windows-Kernel-LA57-FoD-Package~' }
        @{ Name = 'Handwriting Language Features'; Filter = 'Microsoft-Windows-LanguageFeatures-Handwriting-\w{2}-\w{2}-Package~' }
        @{ Name = 'OCR Language Features'; Filter = 'Microsoft-Windows-LanguageFeatures-OCR-\w{2}-\w{2}-Package~' }
        @{ Name = 'Speech Language Features'; Filter = 'Microsoft-Windows-LanguageFeatures-Speech-\w{2}-\w{2}-Package~' }
        @{ Name = 'TTS Language Features'; Filter = 'Microsoft-Windows-LanguageFeatures-TextToSpeech-\w{2}-\w{2}-Package~' }
        @{ Name = 'Windows Media Player Legacy'; Filter = 'Microsoft-Windows-MediaPlayer-Package~' }
        @{ Name = 'Tablet PC Math'; Filter = 'Microsoft-Windows-TabletPCMath-Package~' }
        @{ Name = 'Extended Wallpapers'; Filter = 'Microsoft-Windows-Wallpaper-Content-Extended-FoD-Package~' }
    )

    $RegInstallAndBoot = @(
        @{Operation = 'Bypassing hardware requirements'; Path = 'HKLM:\tiny11_DEFAULT\Control Panel\UnsupportedHardwareNotificationCache'; Values = @(
                @{Name = 'SV1'; Type = 'DWord'; Value = 0 }
                @{Name = 'SV2'; Type = 'DWord'; Value = 0 }
            )
        }
        @{Operation = 'Bypassing hardware requirements'; Path = 'HKLM:\tiny11_USERDEFAULT\Control Panel\UnsupportedHardwareNotificationCache'; Values = @(
                @{Name = 'SV1'; Type = 'DWord'; Value = 0 }
                @{Name = 'SV2'; Type = 'DWord'; Value = 0 }
            )
        }
        @{Operation = 'Bypassing hardware requirements'; Path = 'HKLM:\tiny11_SYSTEM\Setup\LabConfig'; Values = @(
                @{Name = 'BypassCPUCheck'; Type = 'DWord'; Value = 1 }
                @{Name = 'BypassRAMCheck'; Type = 'DWord'; Value = 1 }
                @{Name = 'BypassSecureBootCheck'; Type = 'DWord'; Value = 1 }
                @{Name = 'BypassStorageCheck'; Type = 'DWord'; Value = 1 }
                @{Name = 'BypassTPMCheck'; Type = 'DWord'; Value = 1 }
            )
        }
        @{Operation = 'Bypassing hardware requirements'; Path = 'HKLM:\tiny11_SYSTEM\Setup\MoSetup'; Values = @(
                @{Name = 'AllowUpgradesWithUnsupportedTPMOrCPU'; Type = 'DWord'; Value = 1 }
            )
        }
    )

    $RegInstallOnly = @(
        @{Operation = 'Disable Teams Auto-install'; Path = 'HKLM:\tiny11_SOFTWARE\Microsoft\Windows\CurrentVersion\Communications'; Values = @(
                @{Name = 'ConfigureChatAutoInstall'; Type = 'DWord'; Value = 0 }
            )
        }
        @{Operation = 'Disable Sponsored UWP Apps'; Path = 'HKLM:\tiny11_USERDEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Values = @(
                @{Name = 'OemPreInstalledAppsEnabled'; Type = 'DWord'; Value = 0 }
                @{Name = 'PreInstalledAppsEnabled'; Type = 'DWord'; Value = 0 }
                @{Name = 'SilentInstalledAppsEnabled'; Type = 'DWord'; Value = 0 }
            )
        }
        @{Operation = 'Disable Sponsored UWP Apps'; Path = 'HKLM:\tiny11_SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Values = @(
                @{Name = 'DisableWindowsConsumerFeatures'; Type = 'DWord'; Value = 1 }
            )
        }
        @{Operation = 'Disable Sponsored UWP Apps in Start Menu'; Path = 'HKLM:\tiny11_SOFTWARE\Microsoft\PolicyManager\current\device\Start'; Values = @(
                @{Name = 'ConfigureStartPins'; Type = 'String'; Value = '{"pinnedList": [{}]}' }
            )
        }
        @{Operation = 'Allow Local Accounts in OOBE'; Path = 'HKLM:\tiny11_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE'; Values = @(
                @{Name = 'BypassNRO'; Type = 'DWord'; Value = 1 }
            )
        }
        @{Operation = 'Disable Reserved Storage'; Path = 'HKLM:\tiny11_SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager'; Values = @(
                @{Name = 'ShippedWithReserves'; Type = 'DWord'; Value = 0 }
            )
        }
        @{Operation = 'Disable Chat Icon'; Path = 'HKLM:\tiny11_SOFTWARE\Policies\Microsoft\Windows\Windows Chat'; Values = @(
                @{Name = 'ChatIcon'; Type = 'DWord'; Value = 3 }
            )
        }
        @{Operation = 'Disable Taskbar Chat Icon'; Path = 'HKLM:\tiny11_USERDEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Values = @(
                @{Name = 'TaskbarMn'; Type = 'DWord'; Value = 0 }
            )
        }
    )

    $RegHives = @{
        'HKLM' = [Microsoft.Win32.Registry]::LocalMachine
        'HKCU' = [Microsoft.Win32.Registry]::CurrentUser
        'HKU'  = [Microsoft.Win32.Registry]::Users
        'HKCC' = [Microsoft.Win32.Registry]::CurrentConfig
        'HKCR' = [Microsoft.Win32.Registry]::ClassesRoot
        'HKPD' = [Microsoft.Win32.Registry]::PerformanceData
    }

    $MaxRegAttemptsStrLen = $MaxRegOperationAttempts.ToString().Length + 1
    $MaxImageAttemptsStrLen = $MaxImageOperationAttempts.ToString().Length + 1
    $script:DidCleanup = $false

    # Adapted from https://social.technet.microsoft.com/Forums/en-US/e718a560-2908-4b91-ad42-d392e7f8f1ad/take-ownership-of-a-registry-key-and-change-permissions?forum=winserverpowershell
    function Enable-Privilege {
        param(
            # One of the text enums from: https://learn.microsoft.com/en-gb/windows/win32/secauthz/privilege-constants
            [string]$Privilege,
            [switch]$Disable
        )

        # Originally from pinvoke.net
        $Definition = @'
using System;
using System.Runtime.InteropServices;

public class AdjPriv
{
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
        ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid
    {
        public int Count;
        public long Luid;
        public int Attr;
    }

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
    {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = new IntPtr(processHandle);
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        if(disable)
        {
            tp.Attr = SE_PRIVILEGE_DISABLED;
        }
        else
        {
            tp.Attr = SE_PRIVILEGE_ENABLED;
        }
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
    }
}
'@

        $ProcessHandle = (Get-Process -Id $PID).Handle
        (Add-Type $Definition -PassThru)[0]::EnablePrivilege($ProcessHandle, $Privilege, $Disable)
    }

    $AdminFullControl = [System.Security.AccessControl.RegistryAccessRule]::new('BUILTIN\Administrators', 'FullControl', 'ContainerInherit', 'None', 'Allow')
    $AdministratorsGroup = [System.Security.Principal.NTAccount]::new('BUILTIN\Administrators')
    function WriteRegValues {
        param (
            [hashtable]$RegPath
        )
        Write-Host -ForegroundColor Cyan "    Registry Operation: $($RegPath.Operation)"
        if (-not (Test-Path $RegPath.Path)) { $null = New-Item -Path $RegPath.Path -Force }
        foreach ($RegValue in $RegPath.Values) {
            Set-ItemProperty -Path $RegPath.Path @RegValue -Force -ErrorAction:SilentlyContinue
            $Succeeded = $?
            if (-not $Succeeded) {
                Write-Host -ForegroundColor Yellow '        Registry write failed. Trying to grant full control to Administrators group...'
                $RegHive = $RegHives[$RegPath.Path -replace '^(HK\w{1,2}):?\\.+', '$1']
                $SubKey = $RegPath.Path -replace '^HK(?:LM|CU|U|CR|CC|PD):?\\'
                try {
                    # Use admin rights to take ownership of locked key for administrators
                    $GotPrivilege = $false
                    $Counter = 0
                    while (-not $GotPrivilege -and $Counter -lt $MaxRegOperationAttempts) {
                        $GotPrivilege = Enable-Privilege SeTakeOwnershipPrivilege
                        Start-Sleep -Milliseconds 100
                        $Counter++
                    }
                    if (-not $GotPrivilege) {
                        throw 'Couldn''t get take ownership permission'
                    }
                    # Set administrators as owner
                    $LockedKey = $RegHive.OpenSubKey($SubKey, 'ReadWriteSubTree', 'TakeOwnership')
                    $KeyAcl = $LockedKey.GetAccessControl('None')
                    $KeyAcl.SetOwner($AdministratorsGroup)
                    $LockedKey.SetAccessControl($KeyAcl)
                    # Grant administrators full control
                    $KeyAcl = $LockedKey.GetAccessControl()
                    $KeyAcl.SetAccessRule($AdminFullControl)
                    $LockedKey.SetAccessControl($KeyAcl)
                    $LockedKey.Close()
                    # Set key values with new permissions
                    $LockedKey = $RegHive.OpenSubKey($SubKey, 'ReadWriteSubTree', 'WriteKey')
                    $LockedKey.SetValue($RegValue.Name, $RegValue.Value, $RegValue.Type)
                    Start-Sleep 1
                    $CheckValue = Get-ItemPropertyValue -Path $RegPath.Path -Name $RegValue.Name
                    $Succeeded = ($CheckValue -eq $RegValue.Value)
                } catch {
                    Write-Host -ForegroundColor Red "        Couldn't open subkey '$SubKey' to change permissions"
                    Write-Host -ForegroundColor Red "        Error: $($_.Exception.Message)"
                } finally {
                    # Release privilege after use
                    $null = Enable-Privilege SeTakeOwnershipPrivilege -Disable
                }
            }
            if ($Succeeded) {
                Write-Host -ForegroundColor Green '        Registry Operation Succeeded'
            } else {
                Write-Host -ForegroundColor Red '        Registry Operation Failed'
            }
        }
    }

    function UnmountRegKey {
        param (
            [Parameter(Mandatory)]
            [string]$RegKey
        )
        $RegExeKey = $RegKey -replace ':\\', '\'
        $Counter = 1
        $LastCounterLen = 1
        Write-Host -ForegroundColor Cyan "`nUnload hive '${RegExeKey}': Attempt 1/$MaxRegOperationAttempts" -NoNewline
        while ((Test-Path $RegKey) -and $Counter -le $MaxRegOperationAttempts) {
            Write-Host -ForegroundColor Gray ("`u{08}" * ($LastCounterLen + $MaxRegAttemptsStrLen) + $Counter.ToString() + "/$MaxRegOperationAttempts") -NoNewline
            $null = reg.exe unload $RegExeKey *>&1
            Start-Sleep -Milliseconds 100
            $LastCounterLen = $Counter.ToString().Length
            $Counter++
        }
        if ($Counter -gt $MaxRegOperationAttempts) { return $false }
        return $true
    }

    function UnmountImage {
        param (
            [string]$Scratch
        )
        Write-Host -ForegroundColor Cyan 'Unmounting image...'
        $Counter = 1
        $LastCounterLen = 1
        Write-Host -ForegroundColor Cyan "`nUnmount image '${Scratch}': Attempt 1/$MaxImageOperationAttempts" -NoNewline
        while ((-not [string]::IsNullOrWhiteSpace($ScratchInfo) -or (Test-Path $Scratch)) -and $Counter -le $MaxImageOperationAttempts) {
            Write-Host -ForegroundColor Gray ("`u{08}" * ($LastCounterLen + $MaxImageAttemptsStrLen) + $Counter.ToString() + "/$MaxImageOperationAttempts") -NoNewline
            $ScratchInfo = dism /Get-MountedWimInfo | Select-String -SimpleMatch -Raw ("Mount Dir : $Scratch")
            dism.exe /Unmount-Image /MountDir:"${Scratch}" /Discard
            Start-Sleep 2
            dism.exe /Cleanup-MountPoints
            Start-Sleep 2
            Remove-Item $Scratch -Force -Recurse -ErrorAction:Ignore
            Start-Sleep 2
            $LastCounterLen = $Counter.ToString().Length
            $Counter++
        }
        if ($Counter -gt $MaxImageOperationAttempts) { return $false }
        return $true
    }

    function UnmountIso {
        [CmdletBinding(DefaultParameterSetName = 'CIM')]
        param (
            [Parameter(Mandatory, Position = 0, ParameterSetName = 'CIM')]
            [ciminstance]$Volume,
            [Parameter(Mandatory, Position = 0, ParameterSetName = 'String')]
            [string]$Path
        )
        if ($PSCmdlet.ParameterSetName -eq 'String') {
            $Volume = Get-DiskImage -ImagePath $Path -StorageType ISO
        }
        if ($Volume.CimClass.CimClassName -ne 'MSFT_DiskImage') {
            Write-Error 'Volume is not a CIM DiskImage'
            return
        }
        $IsoPath = $Volume.ImagePath
        Write-Host -ForegroundColor Cyan "`nUnmount ISO '$IsoPath': Attempt 1/$MaxImageOperationAttempts" -NoNewline
        $LastCounterLen = 1
        $Counter = 1
        while ($Volume.Attached -and $Counter -le $MaxImageOperationAttempts) {
            Write-Host ("`u{08}" * ($LastCounterLen + $MaxImageAttemptsStrLen) + $Counter.ToString() + "/$MaxImageOperationAttempts") -NoNewline
            $Volume = $Volume | Dismount-DiskImage
            Start-Sleep 2
            $LastCounterLen = $Counter.ToString().Length
            $Counter++
        }
        if ($Counter -gt $MaxImageOperationAttempts) { return $false }
        return $true
    }

    function DoCleanup {
        Write-Host -ForegroundColor Cyan "`nPerforming cleanup..."
        $Dirty = $false
        [System.GC]::Collect()

        Write-Host -ForegroundColor Cyan "`nLooking for loaded registry keys from image..."
        if (-not (UnmountRegKey 'HKLM:\tiny11_DEFAULT')) { $Dirty = $true }
        if (-not (UnmountRegKey 'HKLM:\tiny11_SOFTWARE')) { $Dirty = $true }
        if (-not (UnmountRegKey 'HKLM:\tiny11_SYSTEM')) { $Dirty = $true }
        if (-not (UnmountRegKey 'HKLM:\tiny11_USERDEFAULT')) { $Dirty = $true }

        Write-Host -ForegroundColor Cyan "`nCleanup scratch directory..."
        if (-not (UnmountImage $ScratchDir)) { $Dirty = $true }

        if (Test-Path -PathType Container $ScratchDir) {
            $Dirty = $true
            Write-Warning "Couldn't clean up scratch directory '$ScratchDir'. You may have to manually remove remaining temporary files."
        }

        Write-Host -ForegroundColor Cyan "`nCleanup build directory..."
        $Counter = 0
        while ((Test-Path $BuildDir) -and $Counter -lt $MaxImageOperationAttempts) {
            Remove-Item $BuildDir -Force -Recurse -ErrorAction:SilentlyContinue
            Start-Sleep 2
            $Counter++
        }
        if ($Counter -ge $MaxImageOperationAttempts) { $Dirty = $true }

        if (Test-Path -PathType Container $BuildDir) {
            $Dirty = $true
            Write-Warning "Couldn't clean up build directory '$BuildDir'. You may have to manually remove remaining temporary files."
        }

        Write-Host -ForegroundColor Cyan "`nLooking for mounted source ISO..."
        if (-not (UnmountIso $Source)) { $Dirty = $true }

        if ($Dirty) {
            Write-Host -ForegroundColor Red 'Cleanup was incomplete. Try running the script in cleanup mode:'
            Write-Host -ForegroundColor White "$(Join-Path $PSScriptRoot 'Tiny11Creator.ps1') -Source ""$Source"" -ScratchDir ""$ScratchDir"" -BuildDir ""$BuildDir"" -Cleanup"
            Write-Host -ForegroundColor Magenta "`n`nOther commands that may help in cleaning up manually:"
            Write-Host -ForegroundColor White '    reg.exe unload HKLM\tiny11_DEFAULT'
            Write-Host -ForegroundColor Gray '    reg.exe unload HKLM\tiny11_SOFTWARE'
            Write-Host -ForegroundColor White '    reg.exe unload HKLM\tiny11_SYSTEM'
            Write-Host -ForegroundColor Gray '    reg.exe unload HKLM\tiny11_USERDEFAULT'
            Write-Host -ForegroundColor White "    dism.exe /Unmount-Image /MountDir:""$ScratchDir"" /Discard"
            Write-Host -ForegroundColor Gray '    dism.exe /Cleanup-MountPoints'
            Write-Host -ForegroundColor White "    powershell.exe -c Remove-Item ""$ScratchDir"" -Force -Recurse"
            Write-Host -ForegroundColor Gray "    powershell.exe -c ""$BuildDir"" -Force -Recurse"
        } else {
            Write-Host -ForegroundColor Green "`nCleanup complete. Finished."
        }
        Write-Host -ForegroundColor Magenta "`n`nPress Enter to exit the script..."
        $null = Read-Host

        Pop-Location -StackName Tiny11Creator
        $Host.UI.RawUI.WindowTitle = $OldTitle

        $script:DidCleanup = $true
    }
}

process {
    if ($Cleanup) {
        DoCleanup
        return
    }
    try {
        :ProcessSection
        while ($true) {
            #region Setup
            Write-Host -ForegroundColor White "Welcome to the tiny11 image creator!`n`nColours: " -NoNewline
            Write-Host -ForegroundColor Cyan 'Operations ' -NoNewline
            Write-Host -ForegroundColor Red 'Errors ' -NoNewline
            Write-Host -ForegroundColor Green 'Success ' -NoNewline
            Write-Host -ForegroundColor Yellow 'Warnings ' -NoNewline
            Write-Host -ForegroundColor Magenta 'Input needed'
            Write-Host ''

            if (-not (Test-Path $Source -PathType Leaf)) {
                Write-Error "Source ISO '$Source' not found"
                return
            }

            $Mount = Mount-DiskImage -ImagePath $Source -StorageType ISO -Access ReadOnly -PassThru
            if (-not $? -or -not $Mount.Attached) {
                Write-Error "Mounting ISO image '$Source' failed"
                return
            }
            $SourceDrive = ($Mount | Get-Volume).DriveLetter, ':' -join ''


            foreach ($SourceFile in $ImageFiles) {
                if (-not (Test-Path (Join-Path $SourceDrive $SourceFile))) {
                    Write-Error "Can't find Windows image file '$SourceFile' in drive letter $SourceDrive`n`nPlease enter the drive letter of a windows installation medium."
                    return
                }
            }
            $ScratchDir = $ScratchDir.TrimEnd('\')
            $BuildDir = $BuildDir.TrimEnd('\')

            if (Test-Path $ScratchDir) {
                $Dir = Get-Item $ScratchDir
                if ($Dir -is [System.IO.FileInfo] -or ($Dir.EnumerateDirectories().Count + $Dir.EnumerateFiles().Count) -gt 0) {
                    Write-Error "Scratch path '$ScratchDir' is a file or is not empty"
                    return
                }
            }
            if (Test-Path $BuildDir) {
                Write-Warning "Build directory path '$BuildDir' exists and will be overwritten."
                Write-Host -ForegroundColor Magenta "`nContinue? (Y/N) " -NoNewline
                $KeyRes = @{ Character = '' }
                while ($KeyRes.Character -inotin 'y', 'n') { $KeyRes = $Host.UI.RawUI.ReadKey() }
                if ($KeyRes.Character -ine 'y') {
                    return
                }
                Write-Host -ForegroundColor Yellow "`nWill overwrite build directory."
            }

            $null = New-Item -ItemType Directory -Path $BuildDir -Force
            Write-Host -ForegroundColor Cyan "`nCopying non-image Windows OS files from source..."
            $null = xcopy.exe /E /I /H /R /Y /J /Q /V /EXCLUDE:$(Join-Path $PSScriptRoot 'xcopy_excludes.txt') $SourceDrive $BuildDir *>&1
            Write-Host -ForegroundColor Green "`nCopy complete"

            Write-Host -ForegroundColor Cyan "`nGetting OS image (install.wim) information..."
            $ImageInfo = dism.exe /Get-ImageInfo /ImageFile:"${SourceDrive}\sources\install.wim"
            $LastIndex = (($ImageInfo | Select-String 'Index : ' -Raw | Select-Object -Last 1) -replace 'Index : (\d+)', '$1') -as [uint16]
            if ($ImageIndex -lt 1) {
                Write-Output $ImageInfo
                Write-Host -ForegroundColor Magenta "`n`nSelect image index to use (1-$LastIndex): " -NoNewline
                $ImageIndex = Read-Host
            }
            if ($ImageIndex -gt $LastIndex) {
                Write-Error "Index $ImageIndex doesn't exist in this OS image file. Highest index in file: $LastIndex"
                return
            }

            $IndexInfoOffset = $ImageInfo.IndexOf("Index : $ImageIndex")
            $IndexName = $ImageInfo[$IndexInfoOffset + 1] -replace '^Name : '
            $IndexDesc = $ImageInfo[$IndexInfoOffset + 2] -replace '^Description : '
            #endregion

            #region OS Install Image
            Write-Host -ForegroundColor White "`nSection: Windows OS image (install.wim)"
            Write-Host -ForegroundColor Cyan "`n`nMounting source Windows image (index $ImageIndex)... This may take a while.`n"
            $null = New-Item -ItemType Directory -Path $ScratchDir -Force
            dism.exe /Mount-Image /ImageFile:"${SourceDrive}\sources\install.wim" /index:$ImageIndex /MountDir:"${ScratchDir}" /ReadOnly

            Write-Host -ForegroundColor Green "`nMounting complete."

            Write-Host -ForegroundColor Cyan "`nGetting list of UWP Apps (AppX packages) from image..."
            $ImgPackages = dism.exe /Image:"${ScratchDir}" /Get-ProvisionedAppxPackages |
                Select-String 'PackageName : (.+)' | ForEach-Object { $_.Matches[0].Groups[1].Value }
            Write-Host -ForegroundColor Green "`nFinished reading UWP apps."

            Write-Host -ForegroundColor White "`nRemoving UWP apps (AppX packages)"
            foreach ($Package in $AppXProvisionedToRemove) {
                Write-Host -ForegroundColor Cyan "    Removing $($Package.Name)..."
                $ImgPackages.Where{ $_ -match $Package.Filter }.ForEach{
                    $null = dism.exe /Image:"${ScratchDir}" /Remove-ProvisionedAppxPackage /PackageName:"$_"
                }
            }
            Write-Host -ForegroundColor Green "`nRemoval of UWP apps complete."

            Write-Host -ForegroundColor Cyan "`nGetting list of system feature packages from image..."
            $ImgFeatures = dism.exe /Image:"${ScratchDir}" /Get-Packages |
                Select-String 'Package Identity : (.+)' | ForEach-Object { $_.Matches[0].Groups[1].Value }
            Write-Host -ForegroundColor Green "`nFinished reading feature packages."

            Write-Host -ForegroundColor White "`nRemoving system feature packages"
            foreach ($Package in $FeaturesToRemove) {
                Write-Host -ForegroundColor Cyan "    Removing $($Package.Name)..."
                $ImgFeatures.Where{ $_ -match $Package.Filter }.ForEach{
                    $null = dism.exe /Image:"${ScratchDir}" /Remove-Package /PackageName:"$_"
                }
            }
            Write-Host -ForegroundColor Green "`nRemoval of system feature packages complete."

            Write-Host -ForegroundColor Cyan "`nRemoving Edge..."
            Remove-Item "${ScratchDir}\Program Files (x86)\Microsoft\Edge" -Force -Recurse
            Remove-Item "${ScratchDir}\Program Files (x86)\Microsoft\EdgeUpdate" -Force -Recurse
            Write-Host -ForegroundColor Green "`nRemoved Edge."

            Write-Host -ForegroundColor Cyan "`nRemoving OneDrive..."
            $null = takeown.exe /f "${ScratchDir}\Windows\System32\OneDriveSetup.exe"
            $null = icacls.exe "${ScratchDir}\Windows\System32\OneDriveSetup.exe" /grant Administrators:F /T /C
            Remove-Item "${ScratchDir}\Windows\System32\OneDriveSetup.exe" -Force
            Write-Host -ForegroundColor Green "`nRemoved OneDrive."

            Write-Host -ForegroundColor Green "`nFilesystem removals complete."

            Write-Host -ForegroundColor Cyan "`nLoading OS image registry keys..."
            $null = reg.exe load HKLM\tiny11_DEFAULT "${ScratchDir}\Windows\System32\config\default"
            $null = reg.exe load HKLM\tiny11_SOFTWARE "${ScratchDir}\Windows\System32\config\SOFTWARE"
            $null = reg.exe load HKLM\tiny11_SYSTEM "${ScratchDir}\Windows\System32\config\SYSTEM"
            $null = reg.exe load HKLM\tiny11_USERDEFAULT "${ScratchDir}\Users\Default\ntuser.dat"
            Write-Host -ForegroundColor Green "`nRegistry keys loaded."

            foreach ($RegPath in $RegInstallAndBoot) {
                WriteRegValues $RegPath
            }

            foreach ($RegPath in $RegInstallOnly) {
                WriteRegValues $RegPath
            }

            Write-Host -ForegroundColor Green "`nOS image registry changes complete."
            Write-Host -ForegroundColor Magenta "`nIf desired, make any further changes to the OS image registry (under HKLM\tiny11_*)`nthen press Enter to continue..."
            $null = Read-Host

            Write-Host -ForegroundColor Cyan "`nUnloading OS image registry keys... This may take many attempts."
            $null = UnmountRegKey 'HKLM:\tiny11_DEFAULT'
            $null = UnmountRegKey 'HKLM:\tiny11_SOFTWARE'
            $null = UnmountRegKey 'HKLM:\tiny11_SYSTEM'
            $null = UnmountRegKey 'HKLM:\tiny11_USERDEFAULT'

            Write-Host -ForegroundColor Green "`nFinished unloading registry."

            Write-Host -ForegroundColor Cyan "`nAdding unattend file to bypass Microsoft account requirements"
            Copy-Item (Join-Path $PSScriptRoot 'autounattend.xml') "${ScratchDir}\Windows\System32\Sysprep\autounattend.xml"

            Write-Host -ForegroundColor Cyan "`nCleaning up image..."
            dism.exe /Image:"${ScratchDir}" /Cleanup-Image /StartComponentCleanup /ResetBase
            Write-Host -ForegroundColor Green "`nCleanup complete."

            Write-Host -ForegroundColor Cyan "`nSaving changes to new install.wim image... This may take a while."
            dism.exe /Capture-Image /ImageFile:"${BuildDir}\sources\install.wim" /CaptureDir:"${ScratchDir}" /Compress:Max /Name:"${IndexName} (tiny11)" /Description:"${IndexDesc} (tiny11)"
            Write-Host -ForegroundColor Green "`nOS image saved."

            Start-Sleep 5

            Write-Host -ForegroundColor Cyan "`nUnmounting source OS image... This may take a while."
            $null = UnmountImage $ScratchDir
            Write-Host -ForegroundColor Green "`nFinished unmounting source OS image."
            Write-Host -ForegroundColor Green "`n`nWindows OS image complete."
            #endregion

            #region Boot Image
            Write-Host -ForegroundColor White "`nSection: Installer boot image (boot.wim)"

            Write-Host -ForegroundColor Cyan "`nCreating scratch directory"
            $null = New-Item -ItemType Directory -Path $ScratchDir -Force

            Write-Host -ForegroundColor Cyan "`nMounting boot image..."
            dism.exe /Mount-Image /ImageFile:"${SourceDrive}\sources\boot.wim" /index:2 /MountDir:"${ScratchDir}" /ReadOnly
            Write-Host -ForegroundColor Green "`nMounting complete."

            Write-Host -ForegroundColor Cyan "`nLoading boot image registry keys..."
            $null = reg.exe load HKLM\tiny11_DEFAULT "${ScratchDir}\Windows\System32\config\default"
            $null = reg.exe load HKLM\tiny11_SYSTEM "${ScratchDir}\Windows\System32\config\SYSTEM"
            $null = reg.exe load HKLM\tiny11_USERDEFAULT "${ScratchDir}\Users\Default\ntuser.dat"
            Write-Host -ForegroundColor Green "`nRegistry keys loaded."

            foreach ($RegPath in $RegInstallAndBoot) {
                WriteRegValues $RegPath
            }

            Write-Host -ForegroundColor Green "`nBoot image registry changes complete."
            Write-Host -ForegroundColor Magenta "`nIf desired, make any further changes to the boot image registry (under HKLM\tiny11_*)`nthen press Enter to continue..."
            $null = Read-Host

            Write-Host -ForegroundColor Cyan "`nUnloading boot image registry... This may take many attempts."
            $null = UnmountRegKey 'HKLM:\tiny11_DEFAULT'
            $null = UnmountRegKey 'HKLM:\tiny11_SYSTEM'
            $null = UnmountRegKey 'HKLM:\tiny11_USERDEFAULT'
            Write-Host -ForegroundColor Green "`nFinished unloading registry."

            Write-Host -ForegroundColor Cyan "`nCopying WinPE image (boot.wim index 1) from source to new boot image..."
            dism.exe /Export-Image /SourceImageFile:"$SourceDrive\sources\boot.wim" /SourceIndex:1 /DestinationImageFile:"${BuildDir}\sources\boot.wim" /Compress:Max
            Write-Host -ForegroundColor Green "`nFinished copying WinPE."

            Write-Host -ForegroundColor Cyan "`nAppending modified boot image (boot.wim index 2)..."
            $BootImgInfo = dism.exe /Get-ImageInfo /ImageFile:"${SourceDrive}\sources\boot.wim"
            $InstallInfoOffset = $BootImgInfo.IndexOf('Index : 2')
            $InstallName = $BootImgInfo[$InstallInfoOffset + 1]
            $InstallDesc = $BootImgInfo[$InstallInfoOffset + 2]
            dism.exe /Append-Image /ImageFile:"${BuildDir}\sources\boot.wim" /CaptureDir:"${ScratchDir}" /Name:"${InstallName} (tiny11)" /Description:"${InstallDesc} (tiny11)" /Bootable
            Write-Host -ForegroundColor Green "`nFinished appending modified boot image."

            Write-Host -ForegroundColor Cyan "`nUnmounting source boot image... This may take a while."
            $null = UnmountImage $ScratchDir
            Write-Host -ForegroundColor Green "`nFinished unmounting source boot image."
            #endregion

            #region Build ISO
            Write-Host -ForegroundColor White "`nSection: Create new ISO`n"

            Write-Host -ForegroundColor Cyan "`nUnmounting source ISO..."
            $null = UnmountIso $Mount
            Write-Host -ForegroundColor Green "`nFinished unmounting source ISO."

            Write-Host -ForegroundColor Cyan "`nCopying unattend file to bypass Microsoft account requirements"
            Copy-Item (Join-Path $PSScriptRoot 'autounattend.xml') "${BuildDir}\autounattend.xml"
            Write-Host -ForegroundColor Green "`nCopy complete."

            Write-Host -ForegroundColor Cyan "`nBuilding new ISO image..."
            & (Join-Path $PSScriptRoot 'oscdimg.exe') -m -o -u2 -udfver102 "-bootdata:2#p0,e,b${BuildDir}\boot\etfsboot.com#pEF,e,b${BuildDir}\efi\microsoft\boot\efisys.bin" ${BuildDir} $Output
            Write-Host -ForegroundColor Green "`nISO build complete."

            Write-Host -ForegroundColor Green "`n`ntiny11 image creation finished."
            #endregion

            break ProcessSection
        }
    } catch {
        Write-Host -ForegroundColor Red 'Script failed or was terminated'
    } finally {
        DoCleanup
    }
}

end {
    if (-not $script:DidCleanup) { DoCleanup }
}
