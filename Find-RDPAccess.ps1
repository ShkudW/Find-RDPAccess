function Find-RDPAccess {
    param(
        [string]$DC_IP,
        [string]$Username,
        [string]$Password,
        [string]$OutputFile = "C:\Users\Public\RDP_Computers.txt"
    )

    $useExplicitCreds = (-not [string]::IsNullOrEmpty($Username))

    if ($useExplicitCreds) {
        Write-Host "[*] Mode: Using Credentials ($Username)" -ForegroundColor Yellow
        net use "\\$DC_IP\SYSVOL" /delete /y 2>$null | Out-Null
        Invoke-Expression "net use \\$DC_IP\SYSVOL /user:$Username $Password" | Out-Null
    } else {
        Write-Host "[*] Mode: Using Kerberos Ticket" -ForegroundColor Green
    }

Write-Host "[+] Using ADSI" -ForegroundColor Cyan
    $allSIDs = New-Object System.Collections.Generic.List[string]
    
    try {
      
        $rootDSE = [ADSI]"LDAP://$DC_IP/RootDSE"
        
 
        $domainDN = $rootDSE.defaultNamingContext[0]
        $dnsDomain = $rootDSE.dnsHostName[0].Split('.', 2)[1] 
        
     
        if ([string]::IsNullOrEmpty($dnsDomain)) {
            $dnsDomain = $domainDN.Replace("DC=","").Replace(",",".")
        }

        Write-Host "[!] Domain DN: $domainDN" -ForegroundColor Gray
        Write-Host "[!] DNS Domain: $dnsDomain" -ForegroundColor Gray

  
        $adsiPath = "LDAP://$DC_IP/$domainDN"
        $searchRoot = [ADSI]$adsiPath

   
        $adSearcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $adSearcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
        
    
        $targetUser = if ($useExplicitCreds) { $Username.Split('\')[-1].Split('@')[0] } else { 
            $curr = ([Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('\')[-1]
            if ($curr -match "Administrator|System") { "OOkpe" } else { $curr }
        }

        $adSearcher.Filter = "(sAMAccountName=$targetUser)"
        
        $userResult = $adSearcher.FindOne()
        if ($null -eq $userResult) {
			throw "User $targetUser not found in $dnsDomain." 
		}

        
        $userBinSid = $userResult.Properties["objectsid"][0]
        $userSID = (New-Object System.Security.Principal.SecurityIdentifier($userBinSid, 0)).Value
        $allSIDs.Add($userSID)

        $userEntry = $userResult.GetDirectoryEntry()
        if ($useExplicitCreds) { $userEntry.Username = $Username; $userEntry.Password = $Password }
        $userEntry.RefreshCache(@("tokenGroups"))
        foreach ($byteSid in $userEntry.Properties["tokenGroups"]) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($byteSid, 0)
            $allSIDs.Add($sid.Value)
        }
        Write-Host "[+] Collected $($allSIDs.Count) SIDs for $targetUser." -ForegroundColor Green

    } catch {
        Write-Host "[!] Error in Phase 1: $($_.Exception.Message)" -ForegroundColor Red ; return
    }

   
    Write-Host "[+] Searching in SYSVOL SYSVOL for RDP Rights" -ForegroundColor Cyan
    $relevantGUIDs = New-Object System.Collections.Generic.List[string]
    $sysvolPoliciesPath = "\\$DC_IP\SYSVOL\$dnsDomain\Policies"

    $files = Get-ChildItem -Path $sysvolPoliciesPath -Recurse -Include "GptTmpl.inf","Groups.xml" -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        try {
            $content = Get-Content $file.FullName -Raw
            $matchFound = $false
            foreach ($sid in $allSIDs) { 
                if ($content -match [regex]::Escape($sid)) { $matchFound = $true; break } 
            }

            if ($matchFound -and ($file.FullName -match '\{[A-F0-9-]{36}\}')) {
                $guid = $matches[0]
                if ($relevantGUIDs -notcontains $guid) {
                    $relevantGUIDs.Add($guid)
                    Write-Host "[!] Found RDP Match in GPO: $guid" -ForegroundColor Yellow
                }
            }
        } catch { continue }
    }

   
    if ($relevantGUIDs.Count -eq 0) { 
		Write-Host "[-] No RDP permissions found." -ForegroundColor Red; 
		return 
	}
	Write-Host "" 
    Write-Host "[+] Mapping GPOs to OUs and Fetching Computers" -ForegroundColor Cyan
    $targetComputers = New-Object System.Collections.Generic.List[string]

    foreach ($guid in $relevantGUIDs) {
        $ouSearcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $ouSearcher.ReferralChasing = "None"
        $ouSearcher.Filter = "(gPLink=*$guid*)"
        
        foreach ($ou in $ouSearcher.FindAll()) {
            $ouDN = $ou.Properties["distinguishedname"][0]
            Write-Host "        [+] OU: $ouDN" -ForegroundColor Gray
            
            $compRoot = if ($useExplicitCreds) { [ADSI]"LDAP://$DC_IP/$ouDN" } else { [ADSI]"LDAP://$DC_IP/$ouDN" }
            $compSearcher = New-Object System.DirectoryServices.DirectorySearcher($compRoot)
            $compSearcher.ReferralChasing = "None"
            $compSearcher.Filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            
            $compSearcher.FindAll() | ForEach-Object {
                $name = $_.Properties["name"][0]
                if ($targetComputers -notcontains $name) { $targetComputers.Add($name) }
            }
        }
    }

    if ($targetComputers.Count -gt 0) {
        $targetComputers | Out-File -FilePath $OutputFile
        Write-Host "[+++] Total: $($targetComputers.Count). Saved to: $OutputFile" -ForegroundColor Green
    }
}
