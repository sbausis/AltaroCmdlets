<# 
    .SYNOPSIS 
        
 
    .DESCRIPTION 
		
 
    .NOTES 
        Name: AltaroCmdlets.psm1 
        Author: Baur Simon 
        Created: 4 Feb 2017 
        Version History 
            Version 1.0 -- 4 Feb 2017 
                -Initial Version 
#>
#region Private Functions

#endregion Private Functions

#region Public Functions

function ManageService($ServiceName="Altaro VM Backup API Service", $Task="start") {
	$result = $false
	Try {
		$Service = Get-Service $ServiceName -ErrorAction SilentlyContinue
		if (!($Service)) {
			throw "No Service <$ServiceName> found .!."
		} #else {
		#	Write-Host "Found Service <$ServiceName> ..."
		#}
		if (($Service.StartType -eq "Disabled") -And (($Task -eq "restart") -Or ($Task -eq "start"))) {
			Write-Host "Set Service <$ServiceName> to start manually since its disabled now .!."
			$Service | Set-Service -StartupType Manual
		}
		
		if ($Task -eq "disable") {
			if (!($Service.StartType -eq "Disabled")) {
				Write-Host "Set Service <$ServiceName> to Disabled .!."
				$Service | Set-Service -StartupType Disabled
			} else {
				Write-Host "Service <$ServiceName> is already set to Disabled ..."
			}
			$result = $true
			$Task = "stop"
		}
		
		if ($Task -eq "auto") {
			if (!($Service.StartType -eq "Automatic")) {
				Write-Host "Set Service <$ServiceName> to start automatically .!."
				$Service | Set-Service -StartupType Automatic
			} else {
				Write-Host "Service <$ServiceName> is already set to start automatically ..."
			}
			$result = $true
			$Task = "start"
		}
		
		if (($Task -eq "stop") -Or ($Task -eq "restart")) {
			if (($Service.Status -eq "Running")) {
				Write-Host "Stop Service <$ServiceName> .!."
				Stop-Service $ServiceName
				#sleep 1
			} else {
				Write-Host "Service <$ServiceName> is already stopped ..."
			}
			if ($Task -eq "restart") {
				$Service = Get-Service $ServiceName -ErrorAction SilentlyContinue
				$Task = "start"
			}
			$result = $true
		}
		
		if ($Task -eq "start") {
			if (!($Service.Status -eq "Running")) {
				Write-Host "Start Service <$ServiceName> .!."
				Start-Service $ServiceName
			} else {
				Write-Host "Service <$ServiceName> is already running ..."
			}
			$result = $true
		}
		
	} Catch {
		Write-Warning "failed .!."
		#exit 1
	}
	return $result
}

function Altaro-APIService($Task="start") {
	return ManageService -ServiceName "Altaro VM Backup API Service" -Task $Task
}

function Altaro-CheckAPIService() {
	$result = $false
	Try {
		$AltaroAPIService = Get-Service "Altaro VM Backup API Service" -ErrorAction SilentlyContinue
		if (!($AltaroAPIService)) {
			throw "No Altaro API Service found .!."
		}
		Write-Host "Found Altaro API Service ..."
		if (!($AltaroAPIService.StartType -eq "Automatic")) {
			Write-Host "Set Altaro API Service to start automatically .!."
			$AltaroAPIService | Set-Service -StartupType Automatic
		} else {
			Write-Host "Altaro API Service is already set to start automatically ..."
		}
		
		if (!($AltaroAPIService.Status -eq "Running")) {
			Write-Host "Start Altaro API Service .!."
			Start-Service "Altaro VM Backup API Service"
			$result = $true
		} else {
			Write-Host "Altaro API Service is already running ..."
			$result = $true
		}
	} Catch {
		Write-Warning "No Altaro API Service found .!."
		#exit 1
	}
	return $result
}

function Altaro-CloseUI() {
	$result = 0
	$AltaroRunning = Get-Process -Name "Altaro.ManagementConsole" -ErrorAction SilentlyContinue
	if ($AltaroRunning) {
		foreach ($AltaroProcess in $AltaroRunning) {
			Stop-Process -id $AltaroProcess.Id
			$result += 1
		}
	}
	if ($result -gt 0) {
		sleep 30
	}
	return $result
}

################################################################################

function Altaro-GetProtocolVersion() {
	$serviceAddress = "http://localhost:35113/api";
	$uri = $serviceAddress + "/protocol/version";
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" 
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-EndAllSessions failed : $error"
		} else {
			Write-Warning "Altaro-EndAllSessions failed .!."
		}
	}
	return $result.Data
}

function Altaro-StartSession($Username, $Password, $Credential, $Domain) {
	#$result = $null
	$serviceAddress = "http://localhost:35113/api"
	$ServerPort = ""
	$ServerAddress = ""
	if ([string]::IsNullOrEmpty($ServerPort)) {
		$ServerPort = "35107"
	}
	if ([string]::IsNullOrEmpty($ServerAddress)) {
		$ServerAddress = "LOCALHOST"
	}
	if ($Credential) {
		$Password = $Credential.GetNetworkCredential().Password
	}
	$body = @{
					ServerAddress = $ServerAddress; 
					ServerPort = $ServerPort; 
					Username = $Username; 
					Password = $Password; 
					Domain = $Domain
			}
	$uri = $serviceAddress + "/sessions/start"
	$result = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body (ConvertTo-Json $body)
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-StartSession failed : $error"
		} else {
			Write-Warning "Altaro-StartSession failed .!."
		}
		#return $null
	}
	return $result.Data
}

################################################################################

function Altaro-EndSession($SessionToken) {
	$serviceAddress = "http://localhost:35113/api"
	$uri = $serviceAddress + "/sessions/end/" + $SessionToken
	$result = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-EndSession failed : $error"
		} else {
			Write-Warning "Altaro-EndSession failed .!."
		}
	}
	return $true
}

function Altaro-EndAllSessions() {
	$serviceAddress = "http://localhost:35113/api"
	$uri = $serviceAddress + "/sessions/end"
	$result = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-EndAllSessions failed : $error"
		} else {
			Write-Warning "Altaro-EndAllSessions failed .!."
		}
	}
	return $result.ClosedSessions
}

################################################################################

function Altaro-GetVirtualMachines($SessionToken, $ConfiguredOnly) {
	$serviceAddress = "http://localhost:35113/api"
	$UriOptionalPart = ""
	if (![string]::IsNullOrEmpty($ConfiguredOnly)) {
		$UriOptionalPart = '/' + $ConfiguredOnly
	}
	$uri = $serviceAddress + "/vms/list/" + $SessionToken + $UriOptionalPart
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetVirtualMachines failed : $error"
		} else {
			Write-Warning "Altaro-GetVirtualMachines failed .!."
		}
	}
	return $result.VirtualMachines
}

function Altaro-GetVirtualMachine($SessionToken, $MachineRef) {
	$VirtualMachines = Altaro-GetVirtualMachines -SessionToken $SessionToken
	foreach ($VM in $VirtualMachines) {
		if ($VM.AltaroVirtualMachineRef -eq $MachineRef) {
			return $VM
		}
	}
	return $null
}

################################################################################

function Altaro-GetVirtualMachineSchedules($SessionToken, $MachineRef) {
    $serviceAddress = "http://localhost:35113/api"
	$uri = $serviceAddress + "/vms/schedules/" + $SessionToken + '/' + $MachineRef
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetVirtualMachineSchedules failed : $error"
		} else {
			Write-Warning "Altaro-GetVirtualMachineSchedules failed .!."
		}
	}
	return $result.BackupSchedules
}

################################################################################

function Altaro-GetVirtualMachineBackupLocations($SessionToken, $MachineRef) {
	$serviceAddress = "http://localhost:35113/api";
	$includeBackupLocations = ""
	$includeOffsiteLocations = ""
	$uri = $serviceAddress + "/vms/backuplocations/" + $SessionToken + '/' + $MachineRef + '/' + $includeBackupLocations + '/' + $includeOffsiteLocations
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" 
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetVirtualMachineBackupLocations failed : $error"
		} else {
			Write-Warning "Altaro-GetVirtualMachineBackupLocations failed .!."
		}
	}
	return $result.BackupLocations
}

################################################################################

function Altaro-GetBackupLocations($SessionToken) {
	$serviceAddress = "http://localhost:35113/api"
	$includeBackupLocations = ""
	$includeOffsiteLocations = ""
	$uriOptionalPart = "";
	if (![string]::IsNullOrEmpty($includeBackupLocations)) {
		$uriOptionalPart = '/' + $includeBackupLocations 
	}
	if (![string]::IsNullOrEmpty($includeOffsiteLocations)) {
		$uriOptionalPart = '/' + $includeBackupLocations +'/' + $includeOffsiteLocations
	}
	$uri = $serviceAddress + "/backuplocations/" + $SessionToken + $uriOptionalPart
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetBackupLocations failed : $error"
		} else {
			Write-Warning "Altaro-GetBackupLocations failed .!."
		}
	}
	return $result.BackupLocations
}

################################################################################

function Altaro-GetAltaroVirtualMachineRef($SessionToken, $HyperVUUID) {
	$serviceAddress = "http://localhost:35113/api"
	$uri = $serviceAddress + "/vms/altaro-ref/" + $SessionToken + '/' + $HyperVUUID
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetAltaroVirtualMachineRef failed : $error"
		} else {
			Write-Warning "Altaro-GetAltaroVirtualMachineRef failed .!."
		}
	}
	return $result.VirtualMachineIdentificationDetails
}

################################################################################

function Altaro-GetHypervisorVirtualMachineUUID($SessionToken, $MachineRef) {
	$serviceAddress = "http://localhost:35113/api"
	$uri = $serviceAddress + "/vms/hypervisor-uuid/" + $SessionToken + '/' + $MachineRef
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetHypervisorVirtualMachineUUID failed : $error"
		} else {
			Write-Warning "Altaro-GetHypervisorVirtualMachineUUID failed .!."
		}
	}
	return $result.VirtualMachineIdentificationDetails
}

################################################################################

function Altaro-GetSchedules($SessionToken) {
	$serviceAddress = "http://localhost:35113/api"
	$includeBackupSchedules = ""
	$includeSandboxRestoreSchedules = ""
	$uriOptionalPart = "";
	if (![string]::IsNullOrEmpty($includeBackupSchedules)){
		$uriOptionalPart = '/' + $includeBackupSchedules 
	}
	if (![string]::IsNullOrEmpty($includeSandboxRestoreSchedules)){
		$uriOptionalPart = '/' + $includeBackupSchedules +'/' + $includeSandboxRestoreSchedules
	}
	$uri = $serviceAddress + "/schedules/" + $SessionToken + $uriOptionalPart
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetSchedules failed : $error"
		} else {
			Write-Warning "Altaro-GetSchedules failed .!."
		}
	}
	return $result.BackupSchedules
}

################################################################################

function Altaro-GetVirtualMachineSettings($SessionToken, $MachineRef) {
	$serviceAddress = "http://localhost:35113/api";
	$uri = $serviceAddress + "/vms/settings/" + $SessionToken + '/' + $MachineRef
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetVirtualMachineSettings failed : $error"
		} else {
			Write-Warning "Altaro-GetVirtualMachineSettings failed .!."
		}
	}
	return $result.VirtualMachineSettings
}

################################################################################

function Altaro-GetAvailableVersionsForRestore($SessionToken, $MachineRef, $BackupLocationID) {
	$serviceAddress = "http://localhost:35113/api"
	$uri = $serviceAddress + "/restore-options/available-versions/" + $SessionToken + '/' + $MachineRef + '/' + $BackupLocationID;
	$result = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json"
	if ($result.Success -eq $false) {
		if (![string]::IsNullOrEmpty($result.ErrorMessage)) {
			$error = $result.ErrorMessage
			Write-Warning "Altaro-GetAvailableVersionsForRestore failed : $error"
		} else {
			Write-Warning "Altaro-GetAvailableVersionsForRestore failed .!."
		}
	}
	return $result.VirtualMachineRestoreDetails
}

#endregion Public Functions

#region Aliases

#New-Alias -Name APIService -Value Altaro-APIService
#New-Alias -Name CheckAPIService -Value Altaro-CheckAPIService
#New-Alias -Name CloseUI -Value Altaro-CloseUI
#New-Alias -Name GetProtocolVersion -Value Altaro-GetProtocolVersion
#New-Alias -Name StartSession -Value Altaro-StartSession
#New-Alias -Name EndSession -Value Altaro-EndSession
#New-Alias -Name EndAllSessions -Value Altaro-EndAllSessions
#New-Alias -Name GetVirtualMachines -Value Altaro-GetVirtualMachines
#New-Alias -Name GetVirtualMachine -Value Altaro-GetVirtualMachine
#New-Alias -Name GetVirtualMachineSchedules -Value Altaro-GetVirtualMachineSchedules
#New-Alias -Name GetVirtualMachineBackupLocations -Value Altaro-GetVirtualMachineBackupLocations
#New-Alias -Name GetBackupLocations -Value Altaro-GetBackupLocations
#New-Alias -Name GetAltaroVirtualMachineRef -Value Altaro-GetAltaroVirtualMachineRef
#New-Alias -Name GetHypervisorVirtualMachineUUID -Value Altaro-GetHypervisorVirtualMachineUUID
#New-Alias -Name GetSchedules -Value Altaro-GetSchedules
#New-Alias -Name GetVirtualMachineSettings -Value Altaro-GetVirtualMachineSettings
#New-Alias -Name GetAvailableVersionsForRestore -Value Altaro-GetAvailableVersionsForRestore

#endregion Aliases

#region Export Module Members

Export-ModuleMember -Function Altaro-APIService
Export-ModuleMember -Function Altaro-CheckAPIService
Export-ModuleMember -Function Altaro-CloseUI
Export-ModuleMember -Function Altaro-GetProtocolVersion
Export-ModuleMember -Function Altaro-StartSession
Export-ModuleMember -Function Altaro-EndSession
Export-ModuleMember -Function Altaro-EndAllSessions
Export-ModuleMember -Function Altaro-GetVirtualMachines
Export-ModuleMember -Function Altaro-GetVirtualMachine
Export-ModuleMember -Function Altaro-GetVirtualMachineSchedules
Export-ModuleMember -Function Altaro-GetVirtualMachineBackupLocations
Export-ModuleMember -Function Altaro-GetBackupLocations
Export-ModuleMember -Function Altaro-GetAltaroVirtualMachineRef
Export-ModuleMember -Function Altaro-GetHypervisorVirtualMachineUUID
Export-ModuleMember -Function Altaro-GetSchedules
Export-ModuleMember -Function Altaro-GetVirtualMachineSettings
Export-ModuleMember -Function Altaro-GetAvailableVersionsForRestore

#Export-ModuleMember -Alias APIService
#Export-ModuleMember -Alias CheckAPIService
#Export-ModuleMember -Alias CloseUI
#Export-ModuleMember -Alias GetProtocolVersion
#Export-ModuleMember -Alias StartSessionAltaro-APIService
#Export-ModuleMember -Alias EndSessionAltaro-CheckAPIService
#Export-ModuleMember -Alias EndAllSessionsAltaro-CloseUI
#Export-ModuleMember -Alias GetVirtualMachinesAltaro-GetProtocolVersion
#Export-ModuleMember -Alias GetVirtualMachineAltaro-StartSession
#Export-ModuleMember -Alias GetVirtualMachineSchedulesAltaro-EndSession
#Export-ModuleMember -Alias GetVirtualMachineBackupLocationsAltaro-EndAllSessions
#Export-ModuleMember -Alias GetBackupLocationsAltaro-GetVirtualMachines
#Export-ModuleMember -Alias GetAltaroVirtualMachineRefAltaro-GetVirtualMachine
#Export-ModuleMember -Alias GetHypervisorVirtualMachineUUIDAltaro-GetVirtualMachineSchedules
#Export-ModuleMember -Alias GetSchedulesAltaro-GetVirtualMachineBackupLocations
#Export-ModuleMember -Alias GetVirtualMachineSettingsAltaro-GetBackupLocations
#Export-ModuleMember -Alias GetAvailableVersionsForRestoreAltaro-GetAltaroVirtualMachineRef
#Export-ModuleMember -Alias GetHypervisorVirtualMachineUUID
#Export-ModuleMember -Alias GetSchedules
#Export-ModuleMember -Alias GetVirtualMachineSettings
#Export-ModuleMember -Alias GetAvailableVersionsForRestore

#endregion Export Module Members
