
<#
.NOTES
  Version:        v0.1
  Author:         https://github.com/br-ashlin
  Creation Date:  November, 2024
  Purpose/Change: Assist with tracking the proporgation and synchronization of Group Policy Objects in large enterprises. 

.Description
    This script scans all Domain Controllers (DCs) in a domain to query the modification dates of the `Machine` and `User` folders as well as the version number of a specified Group Policy Object (GPO). 
    Results include:
    1. `MachineModificationDate` - Last modified date of the `Machine` folder.
    2. `UserModificationDate` - Last modified date of the `User` folder.
    3. `GPOVersion` - Version of the GPO retrieved from `gpt.ini`.

.Example
Get-GPOStatus -GPO "Default Domain Policy"
Retrieves the modification dates for the `Machine` and `User` folders, as well as the version number of the "Default Domain Policy" across all Domain Controllers.

.Example
Get-GPOStatus -GPO "Custom GPO" -ExportCSV
Queries the specified GPO ("Custom GPO") for its modification dates and version number across all Domain Controllers and exports the results to a CSV file.

.Inputs
Requires the name of the GPO to query, which can be provided as input to the `-GPO` parameter.

.Parameter GPO
This is a Mandatory parameter to the Display name of the Group Policy Object

.Parameter ExportCSV
This is an optional parameter to indicicate whether to Export results to CSV File

.Outputs
A detailed report including:
- Domain Controller name
- Hostname
- Modification dates of the `Machine` and `User` folders
- Version number of the GPO
#>


Param(
    [Parameter(Mandatory = $True)]
    [string]$GPO,

    [Parameter(Mandatory = $false)]
    [Switch]$ExportCSV
)

# Initiative Variables
$results = @()
$OutFile = "$env:USERPROFILE\Desktop\GPOStatus_$LogDate.csv"

if (!$gpo) {
# Define the GPO Name to search for
$GPO = Read-Host "Enter GPO Display Name to query"
}

$GPOGuid = Get-GPO -Name $GPO 

# Define the GPO GUID to search for
$GPOGuid = ($GPOGuid.ID).guid  

# Import Active Directory module (if not already loaded)
Import-Module ActiveDirectory

# Get all Domain Controllers in the domain
$DomainControllers = Get-ADDomainController -Filter *
$DomainControllers = $DomainControllers | Sort-Object Hostname

# Initialize counters
$TotalCount = $DomainControllers.Count
$CurrentCount = 0

Write-Host "Total Domain Controllers Found: $TotalCount"

# Query the GPO modification date on each Domain Controller
foreach ($DC in $DomainControllers) {
    $CurrentCount++
    $Percentage = [math]::Round(($CurrentCount / $TotalCount) * 100, 2)
    
    # Display progress
    Write-Progress -Activity "Processing Domain Controllers" `
                    -Status "Processing $CurrentCount of $TotalCount ($Percentage%)" `
                    -PercentComplete $Percentage


    Write-Host ''
    Write-Host "[+] Querying Domain Controller: $($DC.Name)" -ForegroundColor Yellow

    # Construct potential paths to the GPO's files - Admin Shares
    <#
    $basePaths = @(
        "\\$($DC.HostName)\c$", 
        "\\$($DC.HostName)\d$\", 
        "\\$($DC.HostName)\e$\", 
        "\\$($DC.HostName)\f$\", 
        "\\$($DC.HostName)\z$\"
    )
 #>
    $basePaths = "\\$($DC.HostName)\"

   # Folder Relative Path Indicates the Path to SYSVOL from the BasePaths (Typical Path is 'WINDOWS\SYSVOL\sysvol\Domain\Policies') - Modify this as required 
    $FolderRelativePath = "SYSVOL\$env:USERDNSDOMAIN\Policies"

    $MachineFolderRelativePath = "$FolderRelativePath\{$GPOGuid}\Machine"
    $UserFolderRelativePath = "$FolderRelativePath\{$GPOGuid}\User"
    $GptIniRelativePath = "$FolderRelativePath\{$GPOGuid}\gpt.ini"

    # Initialize result variables
    $MachineModificationDate = "Not Found"
    $UserModificationDate = "Not Found"
    $GPOVersion = "Not Found"

    foreach ($basePath in $basePaths) {
        Write-Host "[-] Checking path: $basePath" -ForegroundColor Cyan

        # Combine base path with the relative paths
        $MachineFolderPath = Join-Path -Path $basePath -ChildPath $MachineFolderRelativePath
        $UserFolderPath = Join-Path -Path $basePath -ChildPath $UserFolderRelativePath
        $GptIniPath = Join-Path -Path $basePath -ChildPath $GptIniRelativePath

        # Check Machine Folder modification date
        if (Test-Path -Path $MachineFolderPath) {
            Write-Host "[+] Found Machine Folder at $MachineFolderPath" -ForegroundColor Green
            $MachineModificationDate = (Get-Item -Path $MachineFolderPath).LastWriteTime
        }

        # Check User Folder modification date
        if (Test-Path -Path $UserFolderPath) {
            Write-Host "[+] Found User Folder at $UserFolderPath" -ForegroundColor Green
            $UserModificationDate = (Get-Item -Path $UserFolderPath).LastWriteTime
        }

        # Check GPO Version from gpt.ini
        if (Test-Path -Path $GptIniPath) {
            Write-Host "[+] Found gpt.ini at $GptIniPath" -ForegroundColor Green
            $GPOContent = Get-Content -Path $GptIniPath | Select-String -Pattern "Version="
            if ($GPOContent) {
                $GPOVersion = $GPOContent -replace "Version=", ""
            }
        }

        # Break loop if all data has been collected
        if ($MachineModificationDate -ne "Not Found" -and $UserModificationDate -ne "Not Found" -and $GPOVersion -ne "Not Found") {
            break
        }
    }

    if ($MachineModificationDate -eq "Not Found" -or $UserModificationDate -eq "Not Found" -or $GPOVersion -eq "Not Found") {
        Write-Host "[!] Missing data for GPO:$GPO on $($DC.Name)" -ForegroundColor Red
    }

    # Add the results to the array
    $results += [PSCustomObject]@{
        DCName                = $DC.Name
        HostName              = $DC.HostName
        MachineModificationDate = $MachineModificationDate
        UserModificationDate  = $UserModificationDate
        GPOVersion            = $GPOVersion
    }
}

# Display results in a table format
$results | Format-Table -AutoSize

# Export CSV
if ($ExportCSV) {
$results | Export-CSV -path $OutFile
Write-Host "[+] Exporting Results to $outfile"
}
