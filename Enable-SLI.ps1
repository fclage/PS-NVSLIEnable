#Requires -Version 5
#Requires -RunAsAdministrator

<#
.SYNOPSIS
  Patches the Nvidia driver to enable SLI on all cards
.DESCRIPTION
  This script patches the Nvidia driver to enable SLI on all cards (including those without an SLI bridge, such as a GTX 1060 6GB)
.INPUTS
    SliDataFind             # find SLI patch location using the provided bytes such as "84:C0:75:05:0F:BA:6B"
    SliDataReplace          # patch values "C7:43:24:00:00:00:00"
    Originalfile            # original compressed driver file name, ex. "nvlddmkm.sy_"
    DontSearchSystem        # switch that will not search the system for the driver so you dont have to copy the source file
    EnableTestSigning       # Enables Windows driver test signing on boot
.OUTPUTS
  Console log
.NOTES
  Version:        1.0
  Author:         Filipe Lage
  Creation Date:  2019-04-14
  Purpose/Change: This code is free for development and private use only
  Copyright:      (c)2019 Filipe Lage under Beerware License
    ----------------------------------------------------------------------------
    "THE BEER-WARE LICENSE" (Revision 42 originally created by Poul-Henning Kamp - http://people.freebsd.org/~phk/):
    <fclage@gmail.com> wrote this file.  As long as you retain this notice you can do whatever you want with this stuff. 
    If we meet some day, and you think this stuff is worth it, you can buy me a beer in return.
    Thanks.
    Filipe Lage
    ----------------------------------------------------------------------------
  
.EXAMPLE
  # runs automated script with defaults
  Enable-SLI.ps1 

  # Specify patch values and search for the right file in your system driverstore
  Enable-SLI.ps1 -searchInSystem -sliDataFind "84:C0:75:05:0F:BA:6B" -sliDataReplace "C7:43:24:00:00:00:00"
#>

# Settings (can be provided on runtime if necessary)
param(
    $sliDataFind    = "84:C0:75:05:0F:BA:6B",
    $sliDataReplace = "C7:43:24:00:00:00:00",
    $originalfile   = "nvlddmkm.sy_",
    [switch]$DontSearchSystem,
    [switch]$NoTestSigning
)

if ($PSVersionTable.PSVersion.Major -lt 5) { 
    write-error "This script requires Powershell 5. Please update to the latest version of Powershell and try again" -Category NotInstalled -RecommendedAction "Update Powershell"
    write-host "You can download Powershell 5.1 from:" -ForegroundColor Cyan
    Write-host "https://www.microsoft.com/en-us/download/details.aspx?id=54616" -ForegroundColor Yellow -BackgroundColor Blue
    return;
    }
write-host "SLI Enabler v1.0 (c) 2019 Filipe Lage" -ForegroundColor DarkYellow

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $FALSE) {
    write-error "You need to run this script as administrator"
    write-host "Please run the script with administrative access to this computer" -ForegroundColor Cyan
    return;
    }


Push-Location $PSScriptRoot  # ensure we're in the same path as the script from now on

# Some initial variable handling
$expandedFileName = $originalfile.Replace("sy_","sys")
$file = Join-Path $PWD $originalfile
$expandedfile = Join-Path $PWD $expandedFileName

#List pending file replace after reboot
$sessionManagerPath = "HKLM:\System\CurrentControlSet\Control\Session Manager"
$pendingReplacements =  Get-ItemProperty $sessionManagerPath | Select -ExpandProperty PendingFileRenameOperations -ErrorAction SilentlyContinue
$createKey = [string]::IsNullOrEmpty($pendingReplacements)

# Check existing pending file rename after reboot
if ($createKey -eq $false) {
    if (([string]$pendingReplacements).IndexOf($expandedfile) -gt 0) {
        write-warning "A replacement operation is already pending after reboot!!!"
        write-host "Please reboot now. Cheers! :)" -ForegroundColor Green
        return
        }
    }

# Some aliases and tools for signing the files
Set-Alias checksumfix "tools\ChecksumFix.exe"
Set-Alias signtool "tools\signtool.exe"

if (!(Test-Path $file) -and $DontSearchSystem -eq $FALSE) {
    # tries to find the current version of the file and if the user copied to the current path... If not try to get from the system
    $files = @(
        Get-ChildItem -Path "$($ENV:SystemRoot)\System32\DriverStore\FileRepository" -Filter $expandedFileName -Recurse -ErrorAction SilentlyContinue `
        | Where { $_.FullName.IndexOf("nv_dispi") -gt 0 })
    Write-Host "$($files.count) files found in your driver store" -ForegroundColor Cyan
    $files | foreach-object { 
        $t = "[ {0} ] `t version {1}`t Location: {2}" -f ([int]$files.IndexOf($_) + 1), ([Float]::Parse((Get-Item $_.fullname).VersionInfo.FileVersion.Substring(7).Replace(".","")) /100).ToString("0.00"), $_.fullname
        write-host -foregroundColor Yellow $t -BackgroundColor Blue
        }
    $targetFile = $files | Sort-Object LastWriteTime -Descending | Select -First 1
    if ($targetFile -ne $NULL) { copy-item $targetFile.FullName $expandedfile -Force }
    }

if (!(Test-Path $file) -and !(Test-Path $expandedfile)) {
    Write-host "Please copy the file $file to this folder and run again" -ForegroundColor Red;return
    }

if ((Test-Path $file) -and !(Test-Path $expandedfile)) {
    # expand the original file (sy_ to sys)
    write-host "Expanding $file ..." -ForegroundColor Yellow
    expand $file $expandedFile | Out-Null
    }

$matchHash = Get-FileHash $expandedfile
write-host "Original file hash is $($matchHash.Hash) [ $($matchHash.Algorithm) ]" -ForegroundColor Cyan

write-host "Reading $expandedfile ..." -ForegroundColor Yellow
$fileData = [System.IO.File]::ReadAllBytes($expandedFile)
write-host "$($filedata.Length) bytes read" -ForegroundColor Cyan

write-host "Searching for SLI configuration data block ..." -ForegroundColor Yellow
$sigBytes = @($sliDataFind -split ":" | ForEach-Object { [byte][char]([convert]::toint16($_,16))} )
$sigReplaceBytes = @($sliDataReplace -split ":" | ForEach-Object { [byte][char]([convert]::toint16($_,16))} )

$tData = [System.Text.Encoding]::Ascii.GetString($sigBytes,0, $sigBytes.Length)
$text = [System.Text.Encoding]::ASCII.GetString($fileData, 0, $filedata.Length)

$tLocation = $text.IndexOf($tData)
if ($tLocation -le 0) { write-error "Couldn't locate data to patch"; return }

write-host "Patching at location $(('{0:x}' -f $tLocation).ToUpper())" -ForegroundColor Green

for($i=0;$i -lt $sigReplaceBytes.Length; $i++) {
    $byteFrom = $fileData[$tLocation + $i]
    $byteTo = $sigReplaceBytes[$i]
    write-host "Location: $(('{0:x}' -f ($tLocation + $i)).ToUpper()) : $('{00:x}' -f $byteFrom) to $('{0:x}' -f $byteTo)"  -ForegroundColor Cyan
    $fileData[$tLocation + $i] = $sigReplaceBytes[$i]
    }
Write-Host "Byte patching done!" -ForegroundColor Yellow

$backupfile = "$($expandedFile).backup"
if (Test-Path -path $backupfile) { Remove-Item $backupfile }
write-host "Backing up original file to $backupfile" -ForegroundColor Cyan
Rename-Item $expandedFile $backupfile

Write-Host "Writing output file to $expandedfile" -ForegroundColor Yellow
[io.file]::WriteAllBytes($expandedFile,$fileData)

$patchedHash = Get-FileHash -Path $expandedFile

write-host "Searching installed Windows driver..." -ForegroundColor Yellow
$installedFileLocations = Get-ChildItem -Path "$env:SystemRoot\system32" -Filter $expandedFileName -recurse -ErrorAction SilentlyContinue
write-host "Found $($installedFileLocations.Count) $expandedfilename in your system."

$matchingFiles = $installedFileLocations | Where { (Get-FileHash $_.fullname).Hash -eq $matchHash.Hash }
if ($matchingFiles -eq $NULL) { 
    $patchedFiles = $installedFileLocations | Where { (Get-FileHash $_.fullname).Hash -eq $patchedHash.Hash }
    if ($patchedFiles.Count -gt 0) {
        write-host "Already patched!" -ForegroundColor Cyan
        $patchedFiles | % { get-filehash -path $_.fullname }
        $patchedHash
        } else {
        write-host "The $expandedFileName doesn't match the installed nvidia driver in your system." -ForegroundColor Red
        write-host "Please install the driver first and then run this application again" -ForegroundColor Red
        }
    return
    }


write-host "Checking for existing SLI-Enabler codesign certificate" -ForegroundColor Cyan
$Cert = Get-ChildItem Cert:\LocalMachine -Recurse | ? { $_.FriendlyName -like "*SLIenabler*" } | Select -First 1

if ($Cert -eq $NULL) {
    write-host "Generating necessary certificates in Certificate store"
    $c1 = @{
        Extension = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $true, 0, $true)
        Subject =  "CN=MyCustomRootCertificate"
        NotAfter = (Get-Date).AddYears(2)
        KeyUsage = "CertSign"
        Type = "Custom"
        KeyExportPolicy = "NonExportable"
        }
    $sliRoot = New-SelfSignedCertificate @c1

    $c2 = @{
        Signer = $sliroot
        Subject =  "CN=SLIenabler"
        NotAfter = (Get-Date).AddYears(2)
        KeyUsageProperty = "All"
        Type = "Custom"
        FriendlyName = "SLIenabler"
        }
    
    $Cert = New-SelfSignedCertificate @c2

    # Add root to trusted authorities in local machine
    Move-Item $sliRoot.pspath Cert:\LocalMachine\Root\

    if ($Cert -eq $NULL) { 
        write-error "Couldn't generate SliAuto certificate. Make sure you have access to the local machine store and have Powershell 5.0 or later installed."; 
        return
        }
    }

write-host "Certificate $($Cert.FriendlyName) found with thumbprint $($Cert.Thumbprint)" -ForegroundColor Green

write-host "Fixing checksum for $expandedfile"
checksumfix "$expandedFile"

write-host "Signing file with SLIEnabler certificate"
signtool sign /v /sm /n "SLIenabler" /t http://timestamp.verisign.com/scripts/timstamp.dll "$expandedFile"

write-host "$($matchingFiles.count) files unpatched (original) in your system" -foreground Green
$matchingFiles | % { get-filehash -path $_.fullname }

write-host "Replacing with $expandedFileName" -ForegroundColor Green
get-filehash -path $expandedFileName

$confirm = Read-Host -Prompt "Replace system driver with patched one? (type 'yes' to confirm)" 
if ($confirm -ne "yes") { Write-Warning "Canceled"; return; }

write-host "Preparing to replace with patched version" -ForegroundColor Green

write-host "Taking ownership of existing system files in order to patch them:"
$matchingFiles | % { 
    $f = $_.FullName
    $folder = $_.Directory.FullName

    write-host "Preparing $f" -ForegroundColor cyan
    write-host "Taking ownership..." -ForegroundColor Yellow
    takeown /f "$f" /a
    write-host "Applying security settings..." -ForegroundColor Yellow
    icacls "$f" /grant "$ENV:USERNAME`:f"
    write-host "Checking locks..."

    try {
        write-host "Copying patched file to $f"
        Copy-Item -Path $expandedfile -Destination $f -Force
        } catch {
        write-warning "File is locked! Adding to the queue to be replaced on reboot"
        $pendingReplacements += "`\??`\$($f)`0`0"
        $pendingReplacements += "`\??`\$($expandedFile)`0`\??`\$f`0"
        }
    }
if ($createKey) {
    New-ItemProperty -Path $sessionManagerPath -Name PendingFileRenameOperations -Value $pendingReplacements -PropertyType MultiString | Out-Null
    } else {
    Set-ItemProperty -Path $sessionManagerPath -Name PendingFileRenameOperations -Value $pendingReplacements -PropertyType MultiString | Out-Null
    }

if ($NoTestSigning -eq $FALSE) {
    write-host "Enabling windows TestSigning for next boot" -ForegroundColor Cyan
    bcdedit /set TESTSIGNING ON
    }

write-host "Done!" -ForegroundColor Green
write-host "You can reboot now for changes to applied!" -ForegroundColor Cyan
write-host "If the driver doesn't get replaced after reboot, try running this script again in Safe Mode!" -ForegroundColor Cyan

