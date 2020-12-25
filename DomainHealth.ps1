#Requires -Modules ActiveDirectory
#Requires -Modules SqlServer
#Requires -Modules Write-ObjectToSQL
#Requires -Version 3.0

if ($psISE) { $calculatedScriptPath = Split-Path $psISE.CurrentFile.FullPath } #ISE
elseif ($PSVersionTable.PSVersion.Major -ge 3) { $calculatedScriptPath = $PSScriptRoot } #v3+
else { $calculatedScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition } #v2



$appSettings = Get-Content $calculatedScriptPath\appsettings.json | ConvertFrom-Json

$secondsBetweenExecution = $appSettings.AppSettings.SecondsBetweenExecution
#$appSettings.DatabaseSettings

$databaseServer = $appSettings.DatabaseSettings.DatabaseServer
$databaseName = $appSettings.DatabaseSettings.DatabaseName
$useWindowsAuth = $appSettings.DatabaseSettings.UseWindowsAuth
$dbUser = $appSettings.DatabaseSettings.DBUser
$dbPassword = $appSettings.DatabaseSettings.DBPassword
$secpasswd = ConvertTo-SecureString $dbPassword -AsPlainText -Force
$DbCred = New-Object System.Management.Automation.PSCredential ($dbUser, $secpasswd)

if ($useWindowsAuth)
{
    $connString = $appSettings.DatabaseSettings.WinAuthConnectionString
}
else
{
    $connString = $appSettings.DatabaseSettings.SqlAuthConnectionString
}

$createDatabase = $appSettings.DatabaseSettings.CreateDatabaseIfNotExist
if ($createDatabase -eq "True")
{
    $databasePath = $appSettings.DatabaseSettings.DatabasePath
    $createDbSql = Get-Content $calculatedScriptPath\DatabaseScripts\CreateDatabaseSchema.txt
    $createDbSql = $CreateDbSql -f $databaseName,$databasePath
    Invoke-Sqlcmd -ServerInstance $databaseServer -query $createDbSql

    $createTablesSql = Get-Content $calculatedScriptPath\DatabaseScripts\CreateTables.sql
    $createTablesSql = $createTablesSql -f $databaseName
    Invoke-Sqlcmd -ServerInstance $databaseServer -query $createTablesSql
}

$createDatabaseLogins = $appSettings.DatabaseSettings.CreateWindowsDatabaseLogins
if ($createDatabaseLogins -eq "True")
{
    $databaseLogins = $appSettings.DatabaseSettings.WindowsDatabaseLogins
    
    $createLoginSql = Get-Content $calculatedScriptPath\DatabaseScripts\CreateDatabaseLogin.txt
    foreach ($l in $databaseLogins)
    {
        $thisLoginSql = $createLoginSql -f $l,$databaseName
        Invoke-Sqlcmd -ConnectionString $connString -Query $thisLoginSql
    }
}



$useDcDiagCreds = $appSettings.ActiveDirectorySettings.UseExplicitDcDiagCredentials
if ($useDcDiagCreds -eq "True")
{
    $dcDiagUser = "/u:" + $appSettings.ActiveDirectorySettings.User
    $dcDiagPass = "/p:" + $appSettings.ActiveDirectorySettings.Pass
    $dcDiagCredString = "/u:$dcDiagUser /p:$dcDiagPass"    
}

Import-Module ActiveDirectory

$DcDiagObj = @()
$DcDiagResults = @{}
$TestResultRegex = "(?<=\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\s)(.*)(?=)"
$TestResultAnalysisRegex = "(?<=)(.*?)(?=\s)"
$TestNameRegex = "(?<=test\s)(.*?)$"
$EnterpriseTestRegex = "Running enterprise tests on :"

#No need to keep historical dcdiag results around. maybe do some cleanup to update items instead of replacing them.
#$DomainControllerDcDiagPurge = Invoke-Sqlcmd -ConnectionString $connString -Query "Delete FROM dbo.ADDomainControllerDcDiagResults"

#$CurrentADForests = Invoke-Sqlcmd -ServerInstance $DatabaseServer -Database $DatabaseName -Credential $DbCred -Query "select * FROM dbo.ADForests"
$CurrentADForests = Invoke-Sqlcmd -ConnectionString $connString -Query "select * FROM dbo.ADForests"
$ADForest = Get-ADForest

<#
if ($CurrentADForests.Name -contains $ADForest.Name)
{
    $AdForestId = ($CurrentADForests | Where-Object {$_.Name -eq $ADForest.Name}).id
    #TODO Update db with any changes
}
#>

$ExecutionHistoryHT = @{
        CreatedBy = $env:USERNAME
        CreatedOn = (Get-Date)
        ModifiedBy = $env:USERNAME
        ModifiedOn = (Get-Date)
    }


$NewExecHistory = Write-ObjectToSQL -InputObject $ExecutionHistoryHT -Server $DatabaseServer -Database $DatabaseName -TableName ExecutionHistory -DoNotCreateTable
#$NewAdForest = Write-ObjectToSQL -InputObject $NewAdForestHT -ConnectionString $connString -TableName ADForests -PrimaryKey id  # -DoNotCreateTable
$NewExecHistoryQry = Invoke-Sqlcmd -ConnectionString $connString -Query "SELECT TOP (1) * FROM dbo.ExecutionHistory WHERE CreatedOn = '$($ExecutionHistoryHT.CreatedOn)'"
$ExecHistoryId = $NewExecHistoryQry.id


$NewAdForestHT = @{
        Name = $ADForest.Name.ToString()
        RootDomain = $ADForest.RootDomain.ToString()
        DomainNamingMaster = $ADForest.DomainNamingMaster.ToString()
        SchemaMaster = $ADForest.SchemaMaster.ToString()
        ForestMode = $ADForest.ForestMode.ToString()
        CreatedBy = $env:USERNAME
        CreatedOn = (Get-Date)
        ModifiedBy = $env:USERNAME
        ModifiedOn = (Get-Date)
    }

if (-not $CurrentADForests)
{
   
    $NewAdForest = Write-ObjectToSQL -InputObject $NewAdForestHT -Server $DatabaseServer -Database $DatabaseName -TableName ADForests -DoNotCreateTable
    #$NewAdForest = Write-ObjectToSQL -InputObject $NewAdForestHT -ConnectionString $connString -TableName ADForests -PrimaryKey id  # -DoNotCreateTable
    $NewAdForestQry = Invoke-Sqlcmd -ConnectionString $connString -Query "SELECT TOP (1) * FROM dbo.ADForests WHERE Name = '$($ADForest.Name)'"
    $AdForestId = $NewAdForestQry.id
}
else
{
    $AdForestId = ($CurrentADForests | Where-Object {$_.Name -eq $ADForest.Name}).id
    #new forest detected?
    if ($null -eq $AdForestId) 
    {
        $NewAdForest = Write-ObjectToSQL -InputObject $NewAdForestHT -Server $DatabaseServer -Database $DatabaseName -TableName ADForests -DoNotCreateTable
        
        $NewAdForestQry = Invoke-Sqlcmd -ConnectionString $connString -Query "SELECT TOP (1) * FROM dbo.ADForests WHERE Name = '$($ADForest.Name)'"
        $AdForestId = $NewAdForestQry.id
    }


}




#$CurrentADDomains = Invoke-Sqlcmd -ServerInstance $DatabaseServer -Database $DatabaseName -Credential $DbCred -Query "select * FROM dbo.ADDomains"
$CurrentADDomains = Invoke-Sqlcmd -ConnectionString $connString -Query "select * FROM dbo.ADDomains"

foreach ($d in $ADForest.Domains)
{

    if ($CurrentADDomains.Name -contains $d)
    {

        #TODO update domain values
        $AdDomainId = ($CurrentADDomains | Where-Object {$_.Name -eq $d}).id
    }
    else
    {
        $AdDomain = Get-ADDomain -Server $d
        $NewAdDomainHT = @{
          ForestId = $AdForestId
          DomainMode = $AdDomain.DomainMode.ToString()
          Name = $AdDomain.Name.ToString()
          InfrastructureMaster = $AdDomain.InfrastructureMaster.ToString()
          DomainSID = $AdDomain.DomainSID.ToString()
          ObjectGUID = $AdDomain.ObjectGUID.ToString()
          PDCEmulator = $AdDomain.PDCEmulator.ToString()
          RIDMaster = $AdDomain.RIDMaster.ToString()
          CreatedBy = $env:USERNAME
          CreatedOn = (Get-Date)
          ModifiedBy = $env:USERNAME
          ModifiedOn = (Get-Date)
        }

        $NewAdDomain = Write-ObjectToSQL -InputObject $NewAdDomainHT -Server $DatabaseServer -Database $DatabaseName -TableName ADDomains -DoNotCreateTable #-Credential $DbCred
        $NewAdDomainQry = Invoke-Sqlcmd -ConnectionString $connString -Query "SELECT TOP (1) * FROM dbo.ADDomains WHERE Name = '$($AdDomain.Name)'"
        $AdDomainId = $NewAdDomainQry.id
    }
    if ($null -eq $AdDomainId) {throw "yeet"}
    #need to handle things better if there are levels above root (ad.observicing.net)
    $DomainSplit = $d.split(".")

    $DCs = Get-ADComputer -Filter * -SearchBase "OU=Domain Controllers,DC=$($DomainSplit[0]),DC=$($DomainSplit[1])"
    $CurrentADDomainControllers = Invoke-Sqlcmd -ConnectionString $connString -Query "select * FROM dbo.ADDomainControllers"

    foreach ($dc in $DCs)
    {
        if ($CurrentADDomainControllers.SID -contains $dc.SID.value)
        {
            #TODO update properties
            $DomainControllerId = ($CurrentADDomainControllers | Where-Object {$_.SID -eq $dc.SID}).id
        }
        else
        {
            $NewDomainControllerHT = @{
                DomainId = $AdDomainId
                DnsHostName = $dc.DNSHostName.ToString()
                Name = $dc.Name.ToString()
                SID = $dc.SID.ToString()
                ObjectGUID = $dc.ObjectGUID.ToString()
                CreatedBy = $env:USERNAME
                CreatedOn = (Get-Date)
                ModifiedBy = $env:USERNAME
                ModifiedOn = (Get-Date)

            }
            $NewAdDomainController = Write-ObjectToSQL -InputObject $NewDomainControllerHT -Server $DatabaseServer -Database $DatabaseName -TableName ADDomainControllers -DoNotCreateTable
            $NewAdDomainControllerQry = Invoke-Sqlcmd -ConnectionString $connString -Query "SELECT TOP (1) * FROM dbo.ADDomainControllers WHERE SID = '$($dc.SID)'"
            $DomainControllerId = $NewAdDomainControllerQry.id
        }

        #Add other relevant things, like roles, shares, etc
        $DcHostName = $dc.DNSHostName
        $DcName = $dc.Name
        #execute dcdiag
        #$DcDiagResults.$DcName = dcdiag /s:$DcHostName $dcDiagCredString /c
        #$dcDiagArgs = "/s:$DcName" $dcDiagCredString "/c" "/fix"
        #$dcDiagArgs = "/s:$DcHostName $dcDiagCredString /test:DNS"
<#
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo 
        $ProcessInfo.FileName = "dcdiag.exe" 
        $ProcessInfo.RedirectStandardError = $true 
        $ProcessInfo.RedirectStandardOutput = $true 
        $ProcessInfo.UseShellExecute = $false 
        $ProcessInfo.Arguments = $dcdiagArgs 
        $Process = New-Object System.Diagnostics.Process 
        $Process.StartInfo = $ProcessInfo 
        $Process.Start() | Out-Null 
        $Process.WaitForExit() 
        $DcDiagResults.$DcName = $Process.StandardOutput.ReadToEnd() 
#>      if ($useDcDiagCreds)
        {  
            $currDcDiagResults = & dcdiag.exe "/s:$DcName" "$dcDiagUser" "$dcDiagPass" "/c" "/fix"
        }
        else
        {
            $currDcDiagResults = & dcdiag.exe "/s:$DcName" "/c"
        }

        $DcDiagResults.$DcName = $currDcDiagResults


        $TestResultRegex = "(?<=\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\s)(.*)(?=)"
        $TestResultAnalysisRegex = "(?<=)(.*?)(?=\s)"
        $TestNameRegex = "(?<=test\s)(.*?)$"
        $EnterpriseTestRegex = "Running enterprise tests on :"
        $individualEnterpriseTestNameRegex = "(?<= {13}TEST: )\w(.*)(?=)"
        $individualEnterpriseTestRegex = "(?<= {16})\w(.*)(?=)"
        $EnterpriseDNSTestRegex = "(?<= {21})\w(.*)(?=)"
        $DNSSummaryRegex = "(?<= {9})Summary of DNS test results:(.*)(?=)"

        foreach ($i in $DcDiagResults.$DcName)
        {
            $i

            #Test results for DNS
            if (-not $EnterPriseTestsRunning)
            {
                $EnterPriseTestsRunning = $i -match $EnterpriseTestRegex

                
            }

            #$IsTestResult = $i -match $TestResultRegex
            
            

            if ($EnterPriseTestsRunning)
            {
                Write-Host -ForegroundColor Green -BackgroundColor Black "Enterprise Tests Running"
                if (-not $DNSTestsRunning)
                {
                    $IsEntTestName = $i -match $individualEnterpriseTestNameRegex
                
                    if ($IsEntTestName)
                    {
                        $EntTestName = $Matches[0]
                        if ($EntTestName -eq "Records registration (RReg)")
                        {
                            $DNSTestsRunning = $true
                            $DNSTestCount = 0
                        }
                    }
                    else
                    {
                        $IsEntTestResult = $i -match $individualEnterpriseTestRegex
                        if ($IsEntTestResult)
                        {
                            $EntRestResult = $Matches[0]

                            $splitEntTestResult = $EntRestResult.split(" ")
                            $IsSuccessResult = ($splitEntTestResult -notcontains "Error:") -and ($splitEntTestResult -notcontains "Warning:")
                            
                            $TestResultHT = @{
                            ExecutionID = $ExecHistoryId
                            Server = $DcName
                            TestItem = $EntTestName
                            TestPassed = $IsSuccessResult
                            TestName = $EntTestName
                            DomainControllerId = $DomainControllerId
                            CreatedBy = $env:USERNAME
                            CreatedOn = (Get-Date)
                            ModifiedBy = $env:USERNAME
                            ModifiedOn = (Get-Date)
                            ExtendedDetails = $EntRestResult
                            }
                            $DcDiagObj += $TestResultHT
                            $NewAdDomainControllerDcDiagResult = Write-ObjectToSQL -InputObject $TestResultHT -Server $DatabaseServer -Database $DatabaseName -TableName ADDomainControllerDcDiagResults -DoNotCreateTable
                        }

                    }
                }
                else #DNS Tests Running
                {
                    $IsDNSSummary = $i -match $DNSSummaryRegex
                    if ($IsDNSSummary)
                    {
                        $EnterPriseTestsRunning = $false
                        $DNSTestsRunning = $false
                        continue
                    }
                    else
                    {
                        $DNSTestMatch = $i -match $EnterpriseDNSTestRegex
                        if ($DNSTestMatch)
                        {
                            switch($DNSTestCount)
                            {
                                0 { $DNSTestString = $matches[0]; $DNSTestCount++; Write-Host -ForegroundColor Green -BackgroundColor Black "Adding verbose DNS Result to string0" }
                                1 { $DNSTestString += "`r`n" + $matches[0]; $DNSTestCount++; Write-Host -ForegroundColor Green -BackgroundColor Black "Adding verbose DNS Result to string1" }
                                2 
                                { 
                                    Write-Host -ForegroundColor Green -BackgroundColor Black "Adding verbose DNS Result to DB"
                                    $DNSTestString += "`r`n" + $matches[0]
                                    $DNSTestCount = 0 
                                    $TestResultHT = @{
                                    ExecutionID = $ExecHistoryId
                                    Server = $DcName
                                    TestItem = $matches[0]
                                    TestPassed = $IsSuccessResult
                                    TestName = $EntTestName
                                    DomainControllerId = $DomainControllerId
                                    CreatedBy = $env:USERNAME
                                    CreatedOn = (Get-Date)
                                    ModifiedBy = $env:USERNAME
                                    ModifiedOn = (Get-Date)
                                    ExtendedDetails = $DNSTestString
                                    }
                                    $DcDiagObj += $TestResultHT
                                    $NewAdDomainControllerDcDiagResult = Write-ObjectToSQL -InputObject $TestResultHT -Server $DatabaseServer -Database $DatabaseName -TableName ADDomainControllerDcDiagResults -DoNotCreateTable
                                }


                                default {continue}
                                
                            }
                  
                            
                        }
                        
                    }
                }


            }



            $IsTestResult = $i -match $TestResultRegex
            if ($IsTestResult)
            {
                $TestResult = $Matches[0]
                $SplitTestResult = $TestResult.Split(" ")
                if ($SplitTestResult[3] -eq "LocatorCheck")
                {
                    $EnterPriseTestsRunning = $false
                    $DNSTestsRunning = $false
                }
                if (-not $EnterpriseTestsRunning)
                {
                    if ($SplitTestResult.count -eq 4)
                    {
                        $TestResultHT = @{
                        ExecutionID = $ExecHistoryId
                        Server = $DcName
                        TestItem = $SplitTestResult[0]
                        TestPassed = $SplitTestResult[1] -eq "passed"
                        TestName = $SplitTestResult[3]
                        DomainControllerId = $DomainControllerId
                        CreatedBy = $env:USERNAME
                        CreatedOn = (Get-Date)
                        ModifiedBy = $env:USERNAME
                        ModifiedOn = (Get-Date)
                        }
                        $DcDiagObj += $TestResultHT
                        $NewAdDomainControllerDcDiagResult = Write-ObjectToSQL -InputObject $TestResultHT -Server $DatabaseServer -Database $DatabaseName -TableName ADDomainControllerDcDiagResults -DoNotCreateTable

                    }
                    else
                    {
                        Write-Host -ForegroundColor Red -BackgroundColor Black "Although a test result was found, there weren't 4 parts"
                    }
                }

            }

        }


    }


    $CurrentADSites = Invoke-Sqlcmd -ConnectionString $connString -Query "select * FROM dbo.ADSites WHERE ForestID = $AdForestId"
    $AdFrstObj = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $ADForest.Name)
    [array]$AdSites=[System.DirectoryServices.ActiveDirectory.Forest]::GetForest($AdFrstObj).sites
    #refresh dcs
    $CurrentADDomainControllers = Invoke-Sqlcmd -ConnectionString $connString -Query "select * FROM dbo.ADDomainControllers"
    foreach ($site in $AdSites)
    {
        if ($CurrentADSites.Name -contains $site.Name)
        {
            #TODO Update
            $AdSiteId = ($CurrentAdSites | Where-Object {$_.Name -eq $site.Name}).id
            "found site $($site.name)"
        }
        else
        {
            "Adding site $($Site.name)"
            $NewAdSiteHt = @{
                ForestId = $AdForestId
                InterSiteTopologyGenerator = $Site.InterSiteTopologyGenerator
                Name = $site.Name
                Options = $site.Options
                Location = $site.Location
                CreatedBy = $env:USERNAME
                CreatedOn = (Get-Date)
                ModifiedBy = $env:USERNAME
                ModifiedOn = (Get-Date)
            }
            $NewAdSite = Write-ObjectToSQL -InputObject $NewAdSiteHT -Server $DatabaseServer -Database $DatabaseName -TableName ADSites -DoNotCreateTable
            $NewAdSiteQry = Invoke-Sqlcmd -ConnectionString $connString -Query "SELECT TOP (1) * FROM dbo.AdSites WHERE Name = '$($site.Name)'"
            $AdSiteId = $NewAdSiteQry.id
            if ($null -eq $AdSiteId) {throw "yeet"}
        }
            $CurrentAdSiteDomainControllers = Invoke-Sqlcmd -ConnectionString $connString -Query "select * FROM dbo.AdDcToSites WHERE SiteId = $AdSiteId"

            foreach ($s in $site.Servers)
            {
                $CurrentAdDomainControllerId = ($CurrentADDomainControllers | Where-Object {$_.DNSHostName -eq $s.Name}).id
                if ($CurrentAdSiteDomainControllers.DomainControllerId -contains $CurrentAdDomainControllerId)
                {
                    #TODO Update
                    "Found $($s.Name) server in $($site.name)"

                }
                else
                {
                    "not Found $($s.Name) server in $($site.name)"
                    $NewAdDcToSiteHt = @{
                        DomainControllerId = $CurrentAdDomainControllerId
                        SiteId = $AdSiteId
                        CreatedBy = $env:USERNAME
                        CreatedOn = (Get-Date)
                        ModifiedBy = $env:USERNAME
                        ModifiedOn = (Get-Date)

                        }
                    $NewAdDcToSite = Write-ObjectToSQL -InputObject $NewAdDcToSiteHt -Server $DatabaseServer -Database $DatabaseName -TableName AdDcToSites -DoNotCreateTable

                }

            }

    }

}


Start-Sleep -Seconds $secondsBetweenExecution







