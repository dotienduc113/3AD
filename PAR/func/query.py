import subprocess

query = r"""
(net accounts | findstr /i "password lockout") > .\logs\result1.txt
secedit /export /cfg secpol.txt & type secpol.txt | findstr /i "SeNetworkLogonRight SeDenyNetworkLogonRight SeDenyBatchLogonRight SeDenyServiceLogonRight SeDenyRemoteInteractiveLogonRight SeDenyInteractiveLogonRight SeInteractiveLogonRight SeRemoteInteractiveLogonRight SeShutdownPrivilege SeTcbPrivilege" > .\logs\result3.txt
(net user Administrator | findstr /c:"Account active" & reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "RequireSignOrSeal SealSecureChannel SignSecureChannel DisablePasswordChange MaximumPasswordAge RequireStrongKey" & reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i InactivityTimeoutSecs & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "CachedLogonsCount PasswordExpiryWarning" &  reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" | findstr /i "RequireSecuritySignature EnableSecuritySignature EnablePlainTextPassword"  & reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | findstr /i "autodisconnect requiresecuritysignature enablesecuritysignature enableforcedlogoff SmbServerNameHardeningLevel"  & reg query "HKLM\System\CurrentControlSet\Control\LSA" | findstr /i "UseMachineId" & reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" | findstr /i "SupportedEncryptionTypes" & reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" | findstr /i "NoLMHash LmCompatibilityLevel" & reg query "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" | findstr /i LDAPClientIntegrity & reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" | findstr /i "NtlmMinClientSec NtlmMinServerSec") > .\logs\result4.txt
(netsh advfirewall show allprofiles | findstr /i "domain private public state outbound maxfilesize LogDroppedConnections LogAllowedConnections") > .\logs\result5.txt
(auditpol /get /category:* | findstr /i /c:"Credential Validation" /c:"Kerberos Authentication Service" /c:"Kerberos Service Ticket Operations" /c:"Distribution Group Management" /c:"Other Account Management Events" /c:"Application Group Management" /c:"User account management" /c:"Process Creation" /c:"Directory Service Access" /c:"Directory Service Changes" /c:"Directory Service Replication" /c:"Detailed Directory Service Replication" /c:"Logon" /c:"Logoff" /c:"Account Lockout" /c:"IPsec Main Mode" /c:"IPsec Quick Mode" /c:"IPsec Extended Mode" /c:"Special Logon" /c:"Other Logon/Logoff Events" /c:"Network Policy Server" /c:"Audit Policy Change" /c:"Authentication Policy Change" /c:"Authorization Policy Change" /c:"MPSSVC Rule-Level Policy Change" /c:"Filtering Platform Policy Change" /c:"Other Policy Change Events" /c:"Non Sensitive Privilege Use" /c:"Other Privilege Use Events" /c:"Sensitive Privilege Use") > .\logs\result6.txt
(reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | findstr "SMB1" & reg query "HKLM\SYSTEM\CurrentControlSet\Services\MrxSmb10" | findstr Start & reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" | find "UseLogonCredential") > .\logs\result7.txt
(reg query "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" | findstr /i "netlogon sysvol") > .\logs\result8.txt
(reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" | findstr AllowEncryptionOracle) > .\logs\result9.txt
(reg query "HKLM\Software\Policies\Microsoft\Windows Defender" /s | findstr "DisableAntiSpyware DisableBehaviorMonitoring DisableRealtimeMonitoring DisableScanOnRealtimeEnable DisableOnAccessProtection DisableIOAVProtection DisableArchiveScanning DisablePackedExeScanning DisableRemovableDriveScanning") > .\logs\result10.txt
(reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | findstr "fSingleSessionPerUser fDisableClip fDisableCdm MinEncryptionLevel fPromptForPassword fEncryptRPCTraffic fEncryptRPCTraffic SecurityLayer UserAuthentication MaxDisconnectionTime MaxIdleTime PerSessionTempDir DeleteTempDirsOnExit") > .\logs\result11.txt
(reg query "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /s | findstr /i "EnableScripts ExecutionPolicy EnableScriptBlockLogging EnableTranscripting") > .\logs\result12.txt
(reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM" /s | findstr "AllowBasic AllowUnencryptedTraffic AllowDigest  DisableRunAs AllowAutoConfig WinRM\Client WinRM\Service") > .\logs\result13.txt
(reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" | findstr AllowRemoteShellAccess) > .\logs\result14.txt
(reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" | findstr Start) > .\logs\result15.txt
(reg query "HKLM\Software\Policies\Microsoft\Windows\System" | findstr DisableLGPOProcessing) > .\logs\result16.txt
secedit /export /cfg secpol.txt & type secpol.txt | findstr /i "PasswordComplexity ClearTextPassword" > .\logs\result1_56.txt
secedit /export /cfg secpol.txt & type secpol.txt | findstr /i "ForceLogoffWhenHourExpire" > .\logs\result4_22.txt & del secpol.txt
(powershell.exe "Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordNotRequired | Format-Table Name, PasswordNotRequired") > .\logs\result17_1.txt
(powershell.exe "Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp | Format-Table Name, LastLogonTimestamp") > .\logs\result17_2.txt
(powershell.exe "Get-ADUser -Filter {Enabled -eq $true} -Properties pwdLastSet | Select-Object Name, @{Name='pwdLastSetReadable';Expression={[datetime]::FromFileTime($_.pwdLastSet).ToString('dd/MM/yyyy')}}") > .\logs\result17_3.txt
(powershell.exe "Get-ADUser -Filter {Enabled -eq $true -and AdminCount -eq 1} -Properties servicePrincipalName | Format-Table Name, servicePrincipalName") > .\logs\result17_4.txt
powershell.exe "Get-ADUser krbtgt -Properties pwdLastSet | Select-Object Name, @{Name='pwdLastSetReadable';Expression={[datetime]::FromFileTime($_.pwdLastSet).ToString('dd/MM/yyyy')}}" > .\logs\result17_5.txt
(powershell.exe "(Get-ADDomain).Name; (Get-ACL ('AD:CN=AdminSDHolder,CN=System,' + (Get-ADDomain).DistinguishedName)).Access | Select-Object IdentityReference -Unique") > .\logs\result17_6.txt
"""


# chay lenh cmd va output ra cac file result.txt o thu muc logs

def run_query():
    count = 0
    for line in query.strip().splitlines():
        count = count + 1
        cmd = '{0}'.format(line.strip())
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(result.stderr)
        except Exception as e:
            print(f"Error running command: {e}")
