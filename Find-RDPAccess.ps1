function Find-RDPAccess {


    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DC_IP,
        [string]$Username,
        [string]$Password,
        [string]$OutputFile = "C:\Users\Public\RDP_Computers.txt"
    )


    $useExplicitCreds = (-not [string]::IsNullOrEmpty($Username))

    function New-DEEntry {
        param([string]$LdapPath)
        if ($useExplicitCreds) {
            return New-Object System.DirectoryServices.DirectoryEntry($LdapPath, $Username, $Password)
        }
        return [ADSI]$LdapPath
    }

    # Returns a DirectorySearcher already attached to a DirectoryEntry
    function New-Searcher {
        param([System.DirectoryServices.DirectoryEntry]$Root, [string]$Filter)
        $s = New-Object System.DirectoryServices.DirectorySearcher($Root)
        $s.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
        $s.PageSize        = 1000
        $s.Filter          = $Filter
        return $s
    }

    # S-1-5-32-555 is the well-known SID for Builtin\Remote Desktop Users
    $RDU_SID      = "S-1-5-32-555"
    $RDU_NAMES    = @("Remote Desktop Users","Utilisateurs du Bureau à distance","Remotedesktopbenutzer")   # common localisations

 

    Write-Host "Resolving SIDs via LDAP" -ForegroundColor Cyan
    if ($useExplicitCreds) {
        Write-Host "    Mode : Explicit credentials ($Username)" -ForegroundColor Yellow
    } else {
        Write-Host "    Mode : Current Kerberos context" -ForegroundColor Green
    }

    $allSIDs = New-Object System.Collections.Generic.HashSet[string]
    $domainDN  = $null
    $dnsDomain = $null
    $searchRoot = $null
    $targetUser = $null

    try {

        $rootDSE   = New-DEEntry "LDAP://$DC_IP/RootDSE"
        $domainDN  = $rootDSE.Properties["defaultNamingContext"][0]
        $dnsHost   = $rootDSE.Properties["dnsHostName"][0]


        if ($dnsHost -match '\.') {
            $dnsDomain = $dnsHost.Split('.', 2)[1]
        }
        if ([string]::IsNullOrEmpty($dnsDomain)) {
            $dnsDomain = ($domainDN -replace 'DC=','' -replace ',','.')
        }

        Write-Host "    Domain DN  : $domainDN"  -ForegroundColor DarkGray
        Write-Host "    DNS Domain : $dnsDomain" -ForegroundColor DarkGray

        $searchRoot = New-DEEntry "LDAP://$DC_IP/$domainDN"

  
        if ($useExplicitCreds) {
            $targetUser = $Username.Split('\')[-1].Split('@')[0]
        } else {
            $curr = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            $targetUser = $curr.Split('\')[-1]
        }

        Write-Host "    Target user: $targetUser" -ForegroundColor DarkGray

        $userSearcher = New-Searcher $searchRoot "(sAMAccountName=$targetUser)"
        $userResult   = $userSearcher.FindOne()
        if ($null -eq $userResult) {
            throw "User '$targetUser' not found under $domainDN."
        }

        $userBinSid = $userResult.Properties["objectsid"][0]
        $userSID    = (New-Object System.Security.Principal.SecurityIdentifier($userBinSid, 0)).Value
        [void]$allSIDs.Add($userSID)

        $userEntry = $userResult.GetDirectoryEntry()
        if ($useExplicitCreds) {
            $userEntry.Username = $Username
            $userEntry.Password = $Password
        }
        $userEntry.RefreshCache(@("tokenGroups"))

        foreach ($byteSid in $userEntry.Properties["tokenGroups"]) {
            $sid = (New-Object System.Security.Principal.SecurityIdentifier($byteSid, 0)).Value
            [void]$allSIDs.Add($sid)
        }

        Write-Host "    [+] Collected $($allSIDs.Count) SIDs (user + transitive groups)" -ForegroundColor Green

    } catch {
        Write-Host "    [!] Fuckkk faild" -ForegroundColor Red
        return
    }


    Write-Host "Parsing SYSVOL GPO files" -ForegroundColor Cyan

    $sysvolPath    = "\\$DC_IP\SYSVOL\$dnsDomain\Policies"
    $relevantGUIDs = New-Object System.Collections.Generic.HashSet[string]

    try {
        $gpoFiles = Get-ChildItem -Path $sysvolPath -Recurse -Include "GptTmpl.inf","Groups.xml" -ErrorAction Stop
    } catch {
        Write-Host "    [!] Cannot enumerate SYSVOL: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    foreach ($file in $gpoFiles) {
        try {
            $matchFound = $false

            $guid = $null
            if ($file.FullName -match '(?i)\{([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})\}') {
                $guid = "{$($Matches[1])}"
            }
            if (-not $guid) { continue }

            if ($file.Name -eq "GptTmpl.inf") {
                $content = $null
                try   { $content = [System.IO.File]::ReadAllText($file.FullName,
                            [System.Text.Encoding]::Unicode) }
                catch { }

                # If Unicode read produced garbage (no recognisable INF sections) fall back
                if (-not $content -or $content -notmatch '\[') {
                    try   { $content = [System.IO.File]::ReadAllText($file.FullName,
                                [System.Text.Encoding]::Default) }
                    catch { continue }
                }
                if (-not $content) { continue }

                Write-Host "        Scanning: $($file.FullName)" -ForegroundColor DarkGray


                if ($content -match "(?m)^SeRemoteInteractiveLogonRight\s*=\s*(.+)$") {
                    $line = $Matches[1].Trim()
                    Write-Host "          SeRemoteInteractiveLogonRight: $line" -ForegroundColor DarkGray
                    $privSIDs = $line -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }
                    foreach ($sid in $allSIDs) {
                        if ($privSIDs -contains $sid) {
                            $matchFound = $true
                            Write-Host "    [+] SeRemoteInteractiveLogonRight match | GPO: $guid" -ForegroundColor Yellow
                            break
                        }
                    }
                }

                if (-not $matchFound -and $content -match "(?ms)\[Group Membership\](.*?)(\[|$)") {
                    $gmSection = $Matches[1]

                    foreach ($line in ($gmSection -split "`n")) {
                        $line = $line.Trim()
                        if (-not $line -or $line.StartsWith(';')) { continue }

                        if ($line -match '^(.+?)\s*=\s*(.*)$') {
                            $lhs = $Matches[1].Trim() 
                            $rhs = $Matches[2].Trim() 


                            $rhsSIDs = $rhs -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } |Where-Object { $_ }

                            $lhsSID = $lhs.TrimStart('*') -replace '__Members(of)?$','' 

                            if ($lhsSID -eq $RDU_SID -or
                                ($RDU_NAMES | Where-Object { $lhsSID -match [regex]::Escape($_) })) {
                                foreach ($sid in $allSIDs) {
                                    if ($rhsSIDs -contains $sid) {
                                        $matchFound = $true
                                        Write-Host "    [+] GroupMembership RDU->Member match | GPO: $guid" -ForegroundColor Yellow
                                        break
                                    }
                                }
                            }

                            if (-not $matchFound -and $allSIDs.Contains($lhsSID)) {
                                if ($rhsSIDs -contains $RDU_SID) {
                                    $matchFound = $true
                                    Write-Host "    [+] GroupMembership Member->RDU match | GPO: $guid" -ForegroundColor Yellow
                                }
                            }
                        }
                        if ($matchFound) { break }
                    }
                }
            }

            if ($file.Name -eq "Groups.xml") {
                $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                if (-not $content) { continue }

                try {
                    $xml = [xml]$content
                } catch { continue }

                $groupNodes = $xml.SelectNodes("//Group")
                foreach ($grpNode in $groupNodes) {
                    $grpName = $grpNode.Properties.groupName
                    $grpSid = $grpNode.Properties.groupSid

                    $isRDU = ($grpSid -eq $RDU_SID) -or ($RDU_NAMES | Where-Object { $grpName -match [regex]::Escape($_) })

                    if (-not $isRDU) { continue }

                    $members = $grpNode.SelectNodes(".//Member")
                    foreach ($m in $members) {
                        $mSid  = $m.GetAttribute("sid")
                        $mName = $m.GetAttribute("name")

                        if (($mSid  -and $allSIDs.Contains($mSid)) -or
                            ($mName -and $mName -match [regex]::Escape($targetUser))) {
                            $matchFound = $true
                            Write-Host "    [+] Groups.xml/RDU member match | GPO: $guid" -ForegroundColor Yellow
                            break
                        }
                    }
                    if ($matchFound) { break }
                }
            }

            if ($matchFound) {
                [void]$relevantGUIDs.Add($guid)
            }

        } catch {
          
            continue
        }
    }

    if ($relevantGUIDs.Count -eq 0) {
        Write-Host "`n[-] No GPO-based RDP permissions found for '$targetUser'." -ForegroundColor Red
        return
    }

    Write-Host "`n    [+] Matched GPOs: $($relevantGUIDs.Count)" -ForegroundColor Green
    $relevantGUIDs | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }



    Write-Host "`n[*] Phase 3 — Mapping GPOs to OUs and enumerating computers" -ForegroundColor Cyan

    $targetComputers = New-Object System.Collections.Generic.HashSet[string]

    foreach ($guid in $relevantGUIDs) {

        $ouSearcher = New-Searcher $searchRoot "(gPLink=*$guid*)"
        $ouSearcher.PropertiesToLoad.AddRange(@("distinguishedName","gpOptions")) | Out-Null

        $ouResults = $ouSearcher.FindAll()

        foreach ($ou in $ouResults) {
            $ouDN = $ou.Properties["distinguishedname"][0]

            $gpOptions = 0
            if ($ou.Properties["gpOptions"].Count -gt 0) {
                $gpOptions = [int]$ou.Properties["gpOptions"][0]
            }

            if ($gpOptions -eq 2) {
                Write-Host "    [~] Skipping (GPO link disabled) : $ouDN" -ForegroundColor DarkGray
                continue
            }

            Write-Host "    [OU] $ouDN" -ForegroundColor Gray

            $compRoot    = New-DEEntry "LDAP://$DC_IP/$ouDN"
            $compSearch  = New-Searcher $compRoot `
                "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            $compSearch.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $compSearch.PropertiesToLoad.Add("name") | Out-Null

            $compSearch.FindAll() | ForEach-Object {
                $name = $_.Properties["name"][0]
                if ($targetComputers.Add($name)) {
                    Write-Host "         [+] $name" -ForegroundColor DarkGreen
                }
            }
        }
    }


    Write-Host ""
    if ($targetComputers.Count -gt 0) {
        $targetComputers | Sort-Object | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "[+++] $($targetComputers.Count) computer(s) where '$targetUser' likely has RDP access." -ForegroundColor Green
        Write-Host "      Saved to: $OutputFile" -ForegroundColor Green
    } else {
        Write-Host "[-] GPOs matched but no enabled computers found in linked OUs." -ForegroundColor Red
    }
}
