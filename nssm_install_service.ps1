if ($psISE) { $calculatedScriptPath = Split-Path $psISE.CurrentFile.FullPath }
elseif ($PSVersionTable.PSVersion.Major -ge 3) { $calculatedScriptPath = $PSScriptRoot } #v3+
else { $calculatedScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition } #v2


Invoke-WebRequest https://nssm.cc/release/nssm-2.24.zip -OutFile nssm-2.24.zip
Expand-Archive .\nssm-2.24.zip

$nssm = "$calculatedScriptPath\nssm-2.24\nssm-2.24\win64\nssm.exe"

#& $nssm remove $serviceName
#$nssm = (Get-Command nssm).Source
$serviceName = 'ActiveDirectoryHealthMonitor-test'
$powershell = (Get-Command powershell).Source
$scriptPath = "$calculatedScriptPath\DomainHealth.ps1"
"installing using $scriptpath"
$arguments = '-ExecutionPolicy Bypass -File "{0}"' -f $scriptPath
& $nssm install $serviceName $powershell $arguments
& $nssm status $serviceName
Start-Service $serviceName
Get-Service $serviceName