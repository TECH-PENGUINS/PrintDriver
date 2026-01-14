<#
.SYNOPSIS
    Manage-Printer.ps1 - Samlet script til installation og fjernelse af netværksprintere

.DESCRIPTION
    Script til at installere eller fjerne en netværksprinter.
    Bruger -Action parameter til at vælge mellem "Install" og "Remove".
    INF filen kan hentes fra et GitHub repository eller være lokal.
    Hvis GitHubRepoUrl er angivet, downloades INF filen og relaterede driver filer fra GitHub.

.PARAMETER Action
    Handling der skal udføres: "Install" eller "Remove"

.PARAMETER PrinterName
    Navnet på printeren som den skal vises i Windows (påkrævet for begge handlinger)

.PARAMETER PortName
    Navnet på printer porten (f.eks. "IP_10.10.1.1") - kun ved Install

.PARAMETER PrinterIP
    IP adressen på printeren (f.eks. "10.1.1.1") - kun ved Install

.PARAMETER DriverName
    Navnet på printer driveren fra INF filen - kun ved Install

.PARAMETER INFFile
    Navnet på INF filen (f.eks. "CNLB0MA64.inf") - kun ved Install

.PARAMETER GitHubRepoUrl
    URL til GitHub repository mappen med driver filer.
    Brug raw format: "https://raw.githubusercontent.com/OWNER/REPO/BRANCH/PATH"
    Eller standard GitHub URL: "https://github.com/OWNER/REPO/tree/BRANCH/PATH"

.PARAMETER DriverFiles
    Array af ekstra driver filer der skal downloades sammen med INF filen (f.eks. @("driver.cab", "driver.dll"))

.PARAMETER RemovePort
    Hvis sat, fjernes printer porten også - kun ved Remove

.PARAMETER RemoveDriver
    Hvis sat, fjernes printer driveren også - kun ved Remove

.NOTES
    Filename:     Manage-Printer.ps1
    Version:      2.0
    Author:       NHC IT
    Requires:     Administrator rettigheder

#### Win32 app Commands ####

Install (lokal INF fil):
powershell.exe -executionpolicy bypass -file .\Manage-Printer.ps1 -Action Install -PortName "IP_10.10.1.1" -PrinterIP "10.1.1.1" -PrinterName "Canon Printer Upstairs" -DriverName "Canon Generic Plus UFR II" -INFFile "CNLB0MA64.inf"

Install (fra GitHub):
powershell.exe -executionpolicy bypass -file .\Manage-Printer.ps1 -Action Install -PortName "IP_10.10.1.1" -PrinterIP "10.1.1.1" -PrinterName "Canon Printer Upstairs" -DriverName "Canon Generic Plus UFR II" -INFFile "CNLB0MA64.inf" -GitHubRepoUrl "https://raw.githubusercontent.com/TECH-PENGUINS/PrinterDrivers/main/Canon" -DriverFiles @("CNLB0MA64.CAB")

Uninstall:
powershell.exe -executionpolicy bypass -file .\Manage-Printer.ps1 -Action Remove -PrinterName "Canon Printer Upstairs"

Detection:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Print\Printers\Canon Printer Upstairs
Name = "Canon Printer Upstairs"

.EXAMPLE
    # Installer printer (lokal INF fil)
    .\Manage-Printer.ps1 -Action Install -PortName "IP_10.10.1.1" -PrinterIP "10.1.1.1" -PrinterName "Canon Printer Upstairs" -DriverName "Canon Generic Plus UFR II" -INFFile "CNLB0MA64.inf"

.EXAMPLE
    # Installer printer (fra GitHub)
    .\Manage-Printer.ps1 -Action Install -PortName "IP_10.10.1.1" -PrinterIP "10.1.1.1" -PrinterName "Canon Printer Upstairs" -DriverName "Canon Generic Plus UFR II" -INFFile "CNLB0MA64.inf" -GitHubRepoUrl "https://raw.githubusercontent.com/TECH-PENGUINS/PrinterDrivers/main/Canon" -DriverFiles @("CNLB0MA64.CAB")

.EXAMPLE
    # Fjern printer
    .\Manage-Printer.ps1 -Action Remove -PrinterName "Canon Printer Upstairs"

.EXAMPLE
    # Fjern printer med port og driver
    .\Manage-Printer.ps1 -Action Remove -PrinterName "Canon Printer Upstairs" -RemovePort -RemoveDriver
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Handling: Install eller Remove")]
    [ValidateSet("Install", "Remove")]
    [string]$Action,

    [Parameter(Mandatory = $true, HelpMessage = "Visningsnavn for printeren")]
    [ValidateNotNullOrEmpty()]
    [string]$PrinterName,

    [Parameter(Mandatory = $false, HelpMessage = "Navn på printer port (f.eks. IP_10.10.1.1)")]
    [string]$PortName,

    [Parameter(Mandatory = $false, HelpMessage = "IP adresse på printeren")]
    [string]$PrinterIP,

    [Parameter(Mandatory = $false, HelpMessage = "Driver navn fra INF fil")]
    [string]$DriverName,

    [Parameter(Mandatory = $false, HelpMessage = "INF fil navn")]
    [string]$INFFile,

    [Parameter(Mandatory = $false, HelpMessage = "GitHub repository URL til driver filer (raw.githubusercontent.com format)")]
    [string]$GitHubRepoUrl,

    [Parameter(Mandatory = $false, HelpMessage = "Array af ekstra driver filer der skal downloades (f.eks. CAB filer)")]
    [string[]]$DriverFiles = @(),

    [Parameter(Mandatory = $false, HelpMessage = "Fjern også printer porten")]
    [switch]$RemovePort,

    [Parameter(Mandatory = $false, HelpMessage = "Fjern også printer driveren")]
    [switch]$RemoveDriver
)

#region Initialization
# Indlæs NHC basis funktioner
$BaseFunctionsPath = Join-Path -Path $PSScriptRoot -ChildPath "..\Get-NHCBasicFunctions.ps1"
if (Test-Path -Path $BaseFunctionsPath) {
    . $BaseFunctionsPath
}
else {
    # Fallback til standard lokation
    $BaseFunctionsPath = "C:\Scripts\Get-NHCBasicFunctions.ps1"
    if (Test-Path -Path $BaseFunctionsPath) {
        . $BaseFunctionsPath
    }
    else {
        Write-Warning "NHC Basic Functions ikke fundet. Bruger indbyggede funktioner."
        # Minimal fallback logging
        function Write-NHCLog { param($Message, $LogName, $Level = "Info") Write-Host "[$Level] $Message" }
        function Write-NHCLogHeader { param($LogName, $ScriptName, $Action) Write-Host "=== $ScriptName - $Action ===" }
        function Write-NHCLogFooter { param($LogName, $Success) Write-Host "=== Completed: $Success ===" }
    }
}

# Sæt log navn baseret på handling og printer navn (fjern ugyldige tegn)
$LogName = "Printer-$Action-$($PrinterName -replace '[^\w\-]', '_')"
$ScriptSuccess = $true
#endregion

#region Parameter Validation
if ($Action -eq "Install") {
    # Valider påkrævede parametre for installation
    $MissingParams = @()

    if ([string]::IsNullOrWhiteSpace($PortName)) { $MissingParams += "PortName" }
    if ([string]::IsNullOrWhiteSpace($PrinterIP)) { $MissingParams += "PrinterIP" }
    if ([string]::IsNullOrWhiteSpace($DriverName)) { $MissingParams += "DriverName" }
    if ([string]::IsNullOrWhiteSpace($INFFile)) { $MissingParams += "INFFile" }

    if ($MissingParams.Count -gt 0) {
        Write-Error "Følgende parametre er påkrævet for installation: $($MissingParams -join ', ')"
        exit 1
    }

    # Valider IP format
    if ($PrinterIP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        Write-Error "Ugyldig IP adresse format: $PrinterIP"
        exit 1
    }

    # Valider INF fil
    if ($INFFile -notmatch '\.inf$') {
        Write-Error "INF fil skal have .inf extension: $INFFile"
        exit 1
    }
}
#endregion

#region 64-bit Check
# Kør script i 64bit PowerShell for at få korrekt sti til pnputil
if ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    try {
        Write-NHCLog -Message "Genstarter i 64-bit PowerShell..." -LogName $LogName

        $Arguments = @(
            "-File", $PSCOMMANDPATH,
            "-Action", $Action,
            "-PrinterName", $PrinterName
        )

        if ($Action -eq "Install") {
            $Arguments += @("-PortName", $PortName, "-PrinterIP", $PrinterIP, "-DriverName", $DriverName, "-INFFile", $INFFile)
            if ($GitHubRepoUrl) { $Arguments += @("-GitHubRepoUrl", $GitHubRepoUrl) }
            if ($DriverFiles.Count -gt 0) { $Arguments += @("-DriverFiles", ($DriverFiles -join ",")) }
        }

        if ($RemovePort) { $Arguments += "-RemovePort" }
        if ($RemoveDriver) { $Arguments += "-RemoveDriver" }

        &"$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" @Arguments
        exit $LASTEXITCODE
    }
    catch {
        Write-NHCLog -Message "Fejl ved start af 64-bit PowerShell: $($_.Exception.Message)" -LogName $LogName -Level Error
        exit 1
    }
}
#endregion

#region Functions
function Get-DriverFilesFromGitHub {
    <#
    .SYNOPSIS
        Downloader alle driver filer fra GitHub repository mappe automatisk
    #>
    [CmdletBinding()]
    param(
        [string]$RepoUrl,
        [string]$INFFileName,
        [string[]]$ExtraFiles
    )

    $TempPath = $null

    try {
        # Opret temp mappe til driver filer
        $TempPath = Join-Path -Path $env:TEMP -ChildPath "PrinterDriver_$($PrinterName -replace '[^\w\-]', '_')_$(Get-Date -Format 'yyyyMMddHHmmss')"
        if (Test-Path -Path $TempPath) {
            Remove-Item -Path $TempPath -Recurse -Force
        }
        New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
        Write-NHCLog -Message "Temp mappe oprettet: $TempPath" -LogName $LogName

        # Sæt TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Normaliser GitHub URL og udtræk repository info
        $RepoUrl = $RepoUrl.TrimEnd('/')
        $owner = $null
        $repo = $null
        $branch = $null
        $path = $null

        # Parse forskellige GitHub URL formater
        if ($RepoUrl -match "raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)") {
            $owner = $Matches[1]
            $repo = $Matches[2]
            $branch = $Matches[3]
            $path = $Matches[4]
        }
        elseif ($RepoUrl -match "github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.+)") {
            $owner = $Matches[1]
            $repo = $Matches[2]
            $branch = $Matches[3]
            $path = $Matches[4]
        }
        elseif ($RepoUrl -match "github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)") {
            $owner = $Matches[1]
            $repo = $Matches[2]
            $branch = $Matches[3]
            $path = $Matches[4]
            # Fjern filnavn fra path for at få mappe
            $pathParts = $path -split '/'
            $path = ($pathParts[0..($pathParts.Length - 2)]) -join '/'
        }
        else {
            throw "Kunne ikke parse GitHub URL: $RepoUrl"
        }

        Write-NHCLog -Message "GitHub Repository: $owner/$repo, Branch: $branch, Path: $path" -LogName $LogName

        # Brug GitHub API til at liste alle filer i mappen
        $apiUrl = "https://api.github.com/repos/$owner/$repo/contents/$path`?ref=$branch"
        Write-NHCLog -Message "Henter filliste fra GitHub API: $apiUrl" -LogName $LogName

        $headers = @{
            "Accept"     = "application/vnd.github.v3+json"
            "User-Agent" = "PowerShell-PrinterInstaller"
        }

        $filesResponse = Invoke-RestMethod -Uri $apiUrl -Headers $headers -UseBasicParsing -ErrorAction Stop

        # Filtrer kun filer (ikke mapper) og ekskluder unødvendige filer
        $filesToDownload = $filesResponse | Where-Object {
            $_.type -eq "file" -and
            $_.name -notmatch '\.(ps1|md|txt)$' -and
            $_.name -ne "README.md"
        }

        Write-NHCLog -Message "Fundet $($filesToDownload.Count) driver filer at downloade" -LogName $LogName

        # Download alle filer
        foreach ($file in $filesToDownload) {
            $fileName = $file.name
            $downloadUrl = $file.download_url
            $fileLocalPath = Join-Path -Path $TempPath -ChildPath $fileName

            Write-NHCLog -Message "Downloader: $fileName" -LogName $LogName

            Invoke-WebRequest -Uri $downloadUrl -OutFile $fileLocalPath -UseBasicParsing -ErrorAction Stop

            if (Test-Path -Path $fileLocalPath) {
                $fileSize = (Get-Item $fileLocalPath).Length
                Write-NHCLog -Message "Downloadet: $fileName ($fileSize bytes)" -LogName $LogName
            }
            else {
                throw "Fil '$fileName' blev ikke downloadet korrekt"
            }
        }

        # Verificer at INF filen blev downloadet
        $INFLocalPath = Join-Path -Path $TempPath -ChildPath $INFFileName
        if (-not (Test-Path -Path $INFLocalPath)) {
            throw "INF fil '$INFFileName' blev ikke fundet i repository"
        }

        Write-NHCLog -Message "Alle $($filesToDownload.Count) driver filer downloadet succesfuldt" -LogName $LogName
        return $TempPath
    }
    catch {
        Write-NHCLog -Message "Fejl ved download af driver filer: $($_.Exception.Message)" -LogName $LogName -Level Error

        # Ryd op ved fejl
        if ($TempPath -and (Test-Path -Path $TempPath)) {
            Remove-Item -Path $TempPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        return $null
    }
}

function Install-NetworkPrinter {
    <#
    .SYNOPSIS
        Installerer en netværksprinter
    #>
    [CmdletBinding()]
    param()

    $Success = $true
    $DriverTempPath = $null
    $INFFilePath = $INFFile

    Write-NHCLogHeader -LogName $LogName -ScriptName "Manage-Printer.ps1" -Action "Printer Installation"

    # Log parametre
    Write-NHCLog -Message "Parametre:" -LogName $LogName
    Write-NHCLog -Message "  Port Name: $PortName" -LogName $LogName
    Write-NHCLog -Message "  Printer IP: $PrinterIP" -LogName $LogName
    Write-NHCLog -Message "  Printer Name: $PrinterName" -LogName $LogName
    Write-NHCLog -Message "  Driver Name: $DriverName" -LogName $LogName
    Write-NHCLog -Message "  INF File: $INFFile" -LogName $LogName
    if ($GitHubRepoUrl) {
        Write-NHCLog -Message "  GitHub URL: $GitHubRepoUrl" -LogName $LogName
        Write-NHCLog -Message "  Driver Files: $($DriverFiles -join ', ')" -LogName $LogName
    }

    # Trin 0: Download driver filer fra GitHub hvis URL er angivet
    if ($GitHubRepoUrl -and $Success) {
        Write-NHCLog -Message "Trin 0: Downloader driver filer fra GitHub..." -LogName $LogName

        $DriverTempPath = Get-DriverFilesFromGitHub -RepoUrl $GitHubRepoUrl -INFFileName $INFFile -ExtraFiles $DriverFiles

        if ($DriverTempPath) {
            # Opdater INFFilePath til at pege på den downloadede fil
            $INFFilePath = Join-Path -Path $DriverTempPath -ChildPath $INFFile
            Write-NHCLog -Message "Bruger downloadet INF fil: $INFFilePath" -LogName $LogName
        }
        else {
            Write-NHCLog -Message "Download fra GitHub fejlede" -LogName $LogName -Level Error
            $Success = $false
        }
    }

    # Trin 1: Stage driver til Windows Driver Store
    if ($Success) {
        Write-NHCLog -Message "Trin 1: Stager driver til Windows Driver Store..." -LogName $LogName

        $INFARGS = @("/add-driver", "$INFFilePath")

        try {
            $pnpResult = Start-Process pnputil.exe -ArgumentList $INFARGS -Wait -PassThru -NoNewWindow
            if ($pnpResult.ExitCode -eq 0) {
                Write-NHCLog -Message "Driver staged succesfuldt" -LogName $LogName
            }
            else {
                Write-NHCLog -Message "pnputil returnerede exit code: $($pnpResult.ExitCode)" -LogName $LogName -Level Warning
            }
        }
        catch {
            Write-NHCLog -Message "Fejl ved staging af driver: $($_.Exception.Message)" -LogName $LogName -Level Error
            $Success = $false
        }
    }

    # Trin 2: Installer printer driver
    if ($Success) {
        Write-NHCLog -Message "Trin 2: Installerer printer driver..." -LogName $LogName

        try {
            $DriverExist = Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue
            if (-not $DriverExist) {
                Add-PrinterDriver -Name $DriverName -Confirm:$false
                Write-NHCLog -Message "Printer driver '$DriverName' installeret" -LogName $LogName
            }
            else {
                Write-NHCLog -Message "Printer driver '$DriverName' eksisterer allerede - springer over" -LogName $LogName
            }
        }
        catch {
            Write-NHCLog -Message "Fejl ved installation af printer driver: $($_.Exception.Message)" -LogName $LogName -Level Error
            $Success = $false
        }
    }

    # Trin 3: Opret printer port
    if ($Success) {
        Write-NHCLog -Message "Trin 3: Opretter printer port..." -LogName $LogName

        try {
            $PortExist = Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue
            if (-not $PortExist) {
                Add-PrinterPort -Name $PortName -PrinterHostAddress $PrinterIP -Confirm:$false
                Write-NHCLog -Message "Printer port '$PortName' oprettet med IP $PrinterIP" -LogName $LogName
            }
            else {
                Write-NHCLog -Message "Printer port '$PortName' eksisterer allerede - springer over" -LogName $LogName
            }
        }
        catch {
            Write-NHCLog -Message "Fejl ved oprettelse af printer port: $($_.Exception.Message)" -LogName $LogName -Level Error
            $Success = $false
        }
    }

    # Trin 4: Tilføj printer
    if ($Success) {
        Write-NHCLog -Message "Trin 4: Tilføjer printer..." -LogName $LogName

        try {
            $PrinterExist = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
            if ($PrinterExist) {
                Write-NHCLog -Message "Printer '$PrinterName' eksisterer - fjerner gammel printer" -LogName $LogName
                Remove-Printer -Name $PrinterName -Confirm:$false
                Start-Sleep -Seconds 2
            }

            Add-Printer -Name $PrinterName -DriverName $DriverName -PortName $PortName -Confirm:$false

            # Verificer installation
            Start-Sleep -Seconds 2
            $PrinterVerify = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
            if ($PrinterVerify) {
                Write-NHCLog -Message "Printer '$PrinterName' installeret succesfuldt" -LogName $LogName
            }
            else {
                Write-NHCLog -Message "Kunne ikke verificere printer installation" -LogName $LogName -Level Error
                $Success = $false
            }
        }
        catch {
            Write-NHCLog -Message "Fejl ved tilføjelse af printer: $($_.Exception.Message)" -LogName $LogName -Level Error
            $Success = $false
        }
    }

    # Ryd op i temp mappe hvis den blev oprettet
    if ($DriverTempPath -and (Test-Path -Path $DriverTempPath)) {
        try {
            Remove-Item -Path $DriverTempPath -Recurse -Force
            Write-NHCLog -Message "Temp mappe slettet: $DriverTempPath" -LogName $LogName
        }
        catch {
            Write-NHCLog -Message "Kunne ikke slette temp mappe: $($_.Exception.Message)" -LogName $LogName -Level Warning
        }
    }

    return $Success
}

function Remove-NetworkPrinter {
    <#
    .SYNOPSIS
        Fjerner en netværksprinter
    #>
    [CmdletBinding()]
    param()

    $Success = $true

    Write-NHCLogHeader -LogName $LogName -ScriptName "Manage-Printer.ps1" -Action "Printer Removal"

    Write-NHCLog -Message "Fjerner printer: $PrinterName" -LogName $LogName

    # Hent printer info før fjernelse (til port og driver info)
    $PrinterInfo = $null
    $PortNameToRemove = $null
    $DriverNameToRemove = $null

    try {
        $PrinterInfo = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        if ($PrinterInfo) {
            $PortNameToRemove = $PrinterInfo.PortName
            $DriverNameToRemove = $PrinterInfo.DriverName
        }
    }
    catch {
        # Ignorer fejl her
    }

    # Trin 1: Fjern printer
    Write-NHCLog -Message "Trin 1: Fjerner printer..." -LogName $LogName

    try {
        if ($PrinterInfo) {
            Remove-Printer -Name $PrinterName -Confirm:$false -ErrorAction Stop
            Write-NHCLog -Message "Printer '$PrinterName' fjernet succesfuldt" -LogName $LogName
        }
        else {
            Write-NHCLog -Message "Printer '$PrinterName' findes ikke - intet at fjerne" -LogName $LogName -Level Warning
        }
    }
    catch {
        Write-NHCLog -Message "Fejl ved fjernelse af printer: $($_.Exception.Message)" -LogName $LogName -Level Error
        $Success = $false
    }

    # Trin 2: Fjern port (valgfrit)
    if ($Success -and $RemovePort -and $PortNameToRemove) {
        Write-NHCLog -Message "Trin 2: Fjerner printer port '$PortNameToRemove'..." -LogName $LogName

        try {
            Start-Sleep -Seconds 2

            $PortExist = Get-PrinterPort -Name $PortNameToRemove -ErrorAction SilentlyContinue
            if ($PortExist) {
                Remove-PrinterPort -Name $PortNameToRemove -Confirm:$false -ErrorAction Stop
                Write-NHCLog -Message "Printer port '$PortNameToRemove' fjernet" -LogName $LogName
            }
            else {
                Write-NHCLog -Message "Printer port '$PortNameToRemove' findes ikke" -LogName $LogName -Level Warning
            }
        }
        catch {
            Write-NHCLog -Message "Fejl ved fjernelse af printer port: $($_.Exception.Message)" -LogName $LogName -Level Warning
        }
    }

    # Trin 3: Fjern driver (valgfrit)
    if ($Success -and $RemoveDriver -and $DriverNameToRemove) {
        Write-NHCLog -Message "Trin 3: Fjerner printer driver '$DriverNameToRemove'..." -LogName $LogName

        try {
            # Tjek om andre printere bruger denne driver
            $OtherPrinters = Get-Printer | Where-Object { $_.DriverName -eq $DriverNameToRemove }

            if ($OtherPrinters) {
                Write-NHCLog -Message "Driver bruges af andre printere - springer over fjernelse" -LogName $LogName -Level Warning
            }
            else {
                Start-Sleep -Seconds 2
                Remove-PrinterDriver -Name $DriverNameToRemove -Confirm:$false -ErrorAction Stop
                Write-NHCLog -Message "Printer driver '$DriverNameToRemove' fjernet" -LogName $LogName
            }
        }
        catch {
            Write-NHCLog -Message "Fejl ved fjernelse af printer driver: $($_.Exception.Message)" -LogName $LogName -Level Warning
        }
    }

    return $Success
}
#endregion

#region Main Script
switch ($Action) {
    "Install" {
        $ScriptSuccess = Install-NetworkPrinter
    }
    "Remove" {
        $ScriptSuccess = Remove-NetworkPrinter
    }
}
#endregion

#region Cleanup and Exit
Write-NHCLogFooter -LogName $LogName -Success $ScriptSuccess

if ($ScriptSuccess) {
    $ActionText = if ($Action -eq "Install") { "installeret" } else { "fjernet" }
    Write-Host "Printer '$PrinterName' $ActionText succesfuldt" -ForegroundColor Green
    exit 0
}
else {
    $ActionText = if ($Action -eq "Install") { "Installation" } else { "Fjernelse" }
    Write-Error "$ActionText af printer '$PrinterName' fejlede. Se log: C:\ProgramData\NHC-Intune\Logs\$LogName.log"
    exit 1
}
#endregion
