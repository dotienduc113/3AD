import pyfiglet
import pyfiglet.fonts
import os
import random
import subprocess
import re
from prettytable import PrettyTable
from textwrap import fill
from tabulate import tabulate
from itertools import zip_longest


# gui function
def display_banner():  # Create random font
    fonts = pyfiglet.FigletFont.getFonts()
    rd = random.randint(0, len(fonts) - 1)

    # Create an ASCII art banner
    banner = pyfiglet.figlet_format("TriAD", font=fonts[rd])

    if os.name == 'nt':  # If on Windows set the ANSICON environment variable to enable ANSI escape sequences
        os.system('color')

    # Print the banner with some formatting
    # print("\033[1;92m")  # Change text color to blue
    print(banner)
    print("Welcome to TriAD! Starting up...\n")
    print("\033[0m")  # Reset text color to default


def menu():
    # print("0. Install requirements")
    print("1. Auto Audit")
    print("2. Exit")
    new_path = ".\\logs"
    if not os.path.exists(new_path):
        os.makedirs(new_path)
    while True:
        user_input = input("\nInput: ")
        if user_input.isdigit():
            choice = int(user_input)
            if choice == 1:
                execute(choice)
            elif choice == 2:
                exit()
            else:
                print("Invalid input! Try again.")
        else:
            print("Invalid input! Try again.")


'''
# doan nay ko can
# download velociraptor function
def download_with_curl():
    try:
        curl_command = ("curl -L -o velociraptor.exe https://github.com/Velocidex/velociraptor/releases/download/v0"
                        ".72/velociraptor-v0.72.0-windows-amd64.exe")
        result = subprocess.run(curl_command, check=True)
        print("Download successful using curl!")
        return True
    except FileNotFoundError:
        print("Curl failed, trying with certutil...")
        return False


def download_with_certutil():
    try:
        certutil_cmd = (
            'certutil.exe -urlcache -split -f https://github.com/Velocidex/velociraptor/releases/download/v0.72'
            '/velociraptor-v0.72.0-windows-amd64.exe velociraptor.exe')
        result = subprocess.run(certutil_cmd, check=True)
        print("Download successful using certutil!")
        return True
    except FileNotFoundError:
        # print("Certutil failed.")
        return False


def install_requirements():
    if not download_with_curl():
        if not download_with_certutil():
            print("Both curl and certutil failed. Require manual install velociraptor.")
    return
'''

query = r"""
net accounts | findstr /i "password lockout" > .\logs\result1.txt
secedit /export /cfg secpol.txt && type secpol.txt | findstr /i "SeNetworkLogonRight SeDenyNetworkLogonRight SeDenyBatchLogonRight SeDenyServiceLogonRight SeDenyRemoteInteractiveLogonRight SeDenyInteractiveLogonRight SeInteractiveLogonRight SeRemoteInteractiveLogonRight SeShutdownPrivilege SeTcbPrivilege" > result3.txt
(net user Administrator | findstr /c:"Account active" & reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | findstr /i "RequireSignOrSeal SealSecureChannel SignSecureChannel DisablePasswordChange MaximumPasswordAge RequireStrongKey" & reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | findstr /i InactivityTimeoutSecs & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "CachedLogonsCount PasswordExpiryWarning" &  reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" | findstr /i "RequireSecuritySignature EnableSecuritySignature EnablePlainTextPassword"  & reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" | findstr /i "autodisconnect requiresecuritysignature enablesecuritysignature enableforcedlogoff SmbServerNameHardeningLevel"  & reg query "HKLM\System\CurrentControlSet\Control\LSA" | findstr /i "UseMachineId" & reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" | findstr /i "SupportedEncryptionTypes" & reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" | findstr /i "NoLMHash LmCompatibilityLevel" & reg query "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" | findstr /i LDAPClientIntegrity & reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" | findstr /i "NtlmMinClientSec NtlmMinServerSec") > .\logs\result4.txt
netsh advfirewall show allprofiles | findstr /i "domain private public state outbound maxfilesize LogDroppedConnections LogAllowedConnections" > .\logs\result5.txt
auditpol /get /category:* | findstr /i /c:"Credential Validation" /c:"Kerberos Authentication Service" /c:"Kerberos Service Ticket Operations" /c:"Distribution Group Management" /c:"Other Account Management Events" /c:"Application Group Management" /c:"User account management" /c:"Process Creation" /c:"Directory Service Access" /c:"Directory Service Changes" /c:"Directory Service Replication" /c:"Detailed Directory Service Replication" /c:"Logon" /c:"Logoff" /c:"Account Lockout" /c:"IPsec Main Mode" /c:"IPsec Quick Mode" /c:"IPsec Extended Mode" /c:"Special Logon" /c:"Other Logon/Logoff Events" /c:"Network Policy Server" /c:"Audit Policy Change" /c:"Authentication Policy Change" /c:"Authorization Policy Change" /c:"MPSSVC Rule-Level Policy Change" /c:"Filtering Platform Policy Change" /c:"Other Policy Change Events" /c:"Non Sensitive Privilege Use" /c:"Other Privilege Use Events" /c:"Sensitive Privilege Use" > .\logs\result6.txt
(powershell.exe Get-SmbServerConfiguration | findstr EnableSMB1Protocol & sc query mrxsmb10 | find "STATE" & reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" | find "UseLogonCredential") > .\logs\result7.txt
reg query "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" | findstr /i "netlogon sysvol" > .\logs\result8.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" | findstr AllowEncryptionOracle > .\logs\result9.txt
reg query "HKLM\Software\Policies\Microsoft\Windows Defender" /s | findstr "DisableAntiSpyware DisableBehaviorMonitoring DisableRealtimeMonitoring DisableScanOnRealtimeEnable DisableOnAccessProtection DisableIOAVProtection DisableArchiveScanning DisablePackedExeScanning DisableRemovableDriveScanning" > .\logs\result10.txt
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" | findstr "fSingleSessionPerUser fDisableClip fDisableCdm MinEncryptionLevel fPromptForPassword fEncryptRPCTraffic fEncryptRPCTraffic SecurityLayer UserAuthentication MaxDisconnectionTime MaxIdleTime PerSessionTempDir DeleteTempDirsOnExit" > .\logs\result11.txt
reg query "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /s | findstr /i "EnableScripts ExecutionPolicy EnableScriptBlockLogging EnableTranscripting" > .\logs\result12.txt
reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM" /s | findstr "AllowBasic AllowUnencryptedTraffic AllowDigest  DisableRunAs AllowAutoConfig WinRM\Client WinRM\Service" > .\logs\result13.txt
reg query "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" | findstr AllowRemoteShellAccess > .\logs\result14.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" | findstr Start > .\logs\result15.txt
reg query "HKLM\Software\Policies\Microsoft\Windows\System" | findstr DisableLGPOProcessing > .\logs\result16.txt
type secpol.txt | findstr /i "PasswordComplexity ClearTextPassword" > result1_56.txt
type secpol.txt | findstr /i "ForceLogoffWhenHourExpire" > result4_22.txt & del secpol.txt
"""


# chay lenh cmd bang cach doc file query.txt va output ra 1 file result.txt o thu muc logs

def run_query():
    count = 0
    for line in query.strip().splitlines():
        count = count + 1
        cmd = '{0}'.format(line.strip())
        # print(cmd)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            # print(result.stdout)  # Output the command result
            print(result.stderr)  # Print any errors
        except Exception as e:
            print(f"Error running command: {e}")


'''
def run_query1():
    f = open("query.txt", "r")
    count = 0
    for line in f:
        count = count + 1
        cmd = '{0}'.format(line.strip())
        # print(cmd)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            # print(result.stdout)  # Output the command result
            print(result.stderr)  # Print any errors
        except Exception as e:
            print(f"Error running command: {e}")
'''


# xoa khoang trang thua
def remove_extra_spaces(text):
    # Replace multiple spaces with a single space
    return re.sub(r'\s+', ' ', text).strip()

    # Iterate over the lines and extract settings


# add value to passed and failed array
def append_array(array, key, value):
    array.append(key + ": " + value)
    return


# loc du lieu trong trong query checklist 1 va 2
def filter_info_1():
    file = open(".\\logs\\result1.txt", "r")
    settings = {}
    for line in file:
        line = remove_extra_spaces(line)
        line = line.strip()
        array_line = line.split(": ")
        settings[array_line[0]] = array_line[1]
    return settings


def checklist_1(clist1):  # checklist 1 va 2 lay du lieu va so sanh
    passed = []
    failed = []
    checklist_misc(filter_info_secpol(".\\logs\\result1_56.txt"), passed, failed)
    for key in clist1:
        try:
            value = int(clist1.get(key))
        except ValueError:
            value = -1
        if key == "Minimum password age (days)":
            if value >= 1:
                append_array(passed, f"{key}", clist1.get(key))
            else:
                append_array(failed, f"{key}", clist1.get(key))
        elif key == "Maximum password age (days)":
            if 30 <= value <= 90:
                append_array(passed, f"{key}", clist1.get(key))
            else:
                append_array(failed, f"{key}", clist1.get(key))
        elif key == "Minimum password length":
            if value >= 14:
                append_array(passed, f"{key}", clist1.get(key))
            else:
                append_array(failed, f"{key}", clist1.get(key))
        elif key == "Length of password history maintained":
            if value >= 14:
                append_array(passed, f"{key}", clist1.get(key))
            else:
                append_array(failed, f"{key}", clist1.get(key))
        elif key == "Lockout threshold":
            if 0 < value <= 5:
                append_array(passed, f"{key}", clist1.get(key))
            else:
                append_array(failed, f"{key}", clist1.get(key))
        elif key == "Lockout duration (minutes)":
            if value >= 15:
                append_array(passed, f"{key}", clist1.get(key))
            else:
                append_array(failed, f"{key}", clist1.get(key))
        elif key == "Lockout observation window (minutes)":
            if value >= 15:
                append_array(passed, f"{key}", clist1.get(key))
            else:
                append_array(failed, f"{key}", clist1.get(key))
    print("\n1-2. Password Policy and Account Lockout Policy result:")
    result_table(passed, failed)


# loc du lieu trong trong query checklist 5
def filer_info_5():
    file = open(".\\logs\\result5.txt", "r")
    profiles = {}  # Dictionary to store settings for each profile
    current_profile = None
    settings = []
    for line in file:
        line = remove_extra_spaces(line)
        line = line.strip()
        if line.endswith("Profile Settings:"):
            if current_profile:
                profiles[current_profile] = settings
                settings = []
            current_profile = line
        else:
            # Split the setting and value based on multiple spaces
            parts = line.rsplit(maxsplit=1)
            if len(parts) == 2:
                setting_name = parts[0].strip()
                setting_value = parts[1].strip()
                settings.append((setting_name, setting_value))

    if current_profile:
        profiles[current_profile] = settings

    return profiles


def checklist_5(clist5):  # checklist 5 lay du lieu va so sanh
    passed = []
    failed = []
    for profile, settings in clist5.items():
        for obj, value in settings:
            if obj == "State" and value == "ON":
                append_array(passed, f"5.1 {profile[:-18]} {obj}", value)
            elif obj == "Firewall Policy" and "BlockInbound" in value:
                append_array(passed, f"5.2 {profile[:-18]} {obj}", value)
            elif obj == "LogAllowedConnections" and value == "Enable":
                append_array(passed, f"5.5 {profile[:-18]} {obj}", value)
            elif obj == "LogDroppedConnections" and value == "Enable":
                append_array(passed, f"5.4 {profile[:-18]} {obj}", value)
            elif obj == "MaxFileSize" and int(value) >= 16384:
                append_array(passed, f"5.3 {profile[:-18]} {obj}", value)
            else:
                append_array(failed, f"{profile[:-18]} {obj}", value)
    print("\n5. Windows Defender Firewall with Advanced Security result:")
    result_table(passed, failed)


def filter_info_6():
    file = open(".\\logs\\result6.txt", "r")
    lines = file.read().split('\n')
    # Initialize dictionaries to store settings
    settings = {}

    # Iterate over the lines and extract settings
    for line in lines:
        if line.strip():
            match = re.match(r'(.+?)\s{2,}(.+)', line)
            if match:
                category, setting = match.groups()
                settings[category] = setting
    return settings


def checklist_6(clist6):
    passed = []
    failed = []
    for category, setting in clist6.items():
        category = category.strip()
        setting = setting.strip()
        if (
                category == "Credential Validation" or category == "Kerberos Service Ticket Operations" or category == "Kerberos Authentication Service") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (
                category == "Distribution Group Management" or category == "Other Account Management Events") and setting == "Success":
            append_array(passed, f"{category}", setting)
        elif (
                category == "Application Group Management" or category == "User account management") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif category == "Process Creation" and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (
                category == "Directory Service Access" or category == "Directory Service Changes" or category == "Directory Service Replication" or category == "Detailed Directory Service Replication") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (
                category == "Logon" or category == "Logoff" or category == "Account Lockout" or category == "IPsec Main Mode" or category == "IPsec Quick Mode" or category == "IPsec Extended Mode" or category == "Special Logon" or category == "Other Logon/Logoff Events" or category == "Network Policy Server") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (
                category == "Audit Policy Change" or category == "MPSSVC Rule-Level Policy Change" or category == "Other Policy Change Events") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (
                category == "Authentication Policy Change" or category == "Authorization Policy Change" or category == "Filtering Platform Policy Change") and setting == "Success":
            append_array(passed, f"{category}", setting)
        elif (
                category == "Non Sensitive Privilege Use " or category == "Other Privilege Use Events" or category == "Sensitive Privilege Use") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        else:
            append_array(failed, f"{category}", setting)
    print("\n6. Audit Policy:")
    print("NOTE: Please run as administrator to get full results")
    result_table(passed, failed)


def filter_info_7():
    file = open(".\\logs\\result7.txt", "r")
    # Initialize dictionaries to store settings
    settings = {}
    for line in file:
        line = remove_extra_spaces(line.strip().replace(":", ""))
        parts = line.split()
        key = " ".join(parts[:-1])
        settings[key] = parts[-1]
    # Iterate over the lines and extract settings
    return settings


def checklist_7(clist7):
    passed = []
    failed = []
    for category, value in clist7.items():
        if category == "EnableSMB1Protocol":
            if value == "False":
                append_array(passed, f"Configure SMB v1 server", value)
            else:
                append_array(failed, f"Configure SMB v1 server", value)
        elif category == "Start REG_DWORD":
            if value == "0x0":
                append_array(passed, "Configure SMB v1 client driver", "Disable")
            else:
                append_array(failed, "Configure SMB v1 client driver", "Manual start or Automatic start")
        elif category == "UseLogonCredential REG_DWORD":
            if value == "0x0":
                append_array(passed, "WDigest Authentication", "Disable")
            else:
                append_array(failed, "WDigest Authentication", "Enable")
    print("\n7. MS Security Guide:")
    result_table(passed, failed)


def filter_info_8():
    file = open(".\\logs\\result8.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            value = ' '.join(parts[2:]).replace(" ", "")
            settings[key] = value
    except:
        pass
    return settings


def checklist_8(clist8):
    passed = []
    failed = []
    if len(clist8) == 0:
        append_array(failed, "Hardened UNC Paths - SYSVOL", "Default - Not configured")
        append_array(failed, "Hardened UNC Paths - NETLOGON", "Default - Not configured")
    for key, value in clist8.items():
        if len(clist8) == 1:
            if key == r"\\*\SYSVOL":
                if value == "RequireMutualAuthentication=1,RequireIntegrity=1":
                    append_array(passed, "Hardened UNC Paths - SYSVOL", value)
                    append_array(failed, "Hardened UNC Paths - NETLOGON", "Not configured")
                else:
                    append_array(failed, "Hardened UNC Paths - SYSVOL", value)
                    append_array(failed, "Hardened UNC Paths - NETLOGON", "Not configured")
            elif key == r"\\*\NETLOGON":
                if value == "RequireMutualAuthentication=1,RequireIntegrity=1":
                    append_array(passed, "Hardened UNC Paths - NETLOGON", value)
                    append_array(failed, "Hardened UNC Paths - SYSVOL", "Not configured")
                else:
                    append_array(failed, "Hardened UNC Paths - NETLOGON", value)
                    append_array(failed, "Hardened UNC Paths - SYSVOL", "Not configured")
        elif len(clist8) == 2:
            if key == r"\\*\SYSVOL":
                if value == "RequireMutualAuthentication=1,RequireIntegrity=1":
                    append_array(passed, "Hardened UNC Paths - SYSVOL", value)
                else:
                    append_array(failed, "Hardened UNC Paths - SYSVOL", value)
            elif key == r"\\*\NETLOGON" and len(clist8) == 2:
                if value == "RequireMutualAuthentication=1,RequireIntegrity=1":
                    append_array(passed, "Hardened UNC Paths - NETLOGON", value)
                else:
                    append_array(failed, "Hardened UNC Paths - NETLOGON", value)
    print("\n8. Network Provider:")
    result_table(passed, failed)


def filter_info_9():
    file = open(".\\logs\\result9.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def checklist_9(clist9):
    passed = []
    failed = []
    if len(clist9) == 0:
        append_array(failed, "Encryption Oracle Remediation", "Default - Not configured")
    for key, value in clist9.items():
        if key == "AllowEncryptionOracle":
            if value == "0x0":
                append_array(passed, "Encryption Oracle Remediation", "Enabled Force Updated Clients")
            elif value == "0x1":
                append_array(failed, "Encryption Oracle Remediation", "Enabled Mitigated")
            elif value == "0x2":
                append_array(failed, "Encryption Oracle Remediation", "Enabled Vulnerable")
    print("\n9. Credentials Delegation:")
    result_table(passed, failed)


def filter_info_10():
    file = open(".\\logs\\result10.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def checklist_10(clist10):
    passed = []
    failed = []
    if "DisableAntiSpyware" in clist10:
        s = "Turn off Windows Defender"
        if clist10.get("DisableAntiSpyware") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(passed, "Turn off Windows Defender", "Not configure/Disable")
    if "DisableRealtimeMonitoring" in clist10:
        s = "Turn off real-time protection"
        if clist10.get("DisableRealtimeMonitoring") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(passed, "Turn off real-time protection", "Not configure/Disable")
    if "DisableBehaviorMonitoring" in clist10:
        s = "Turn on behavior monitoring"
        if clist10.get("DisableBehaviorMonitoring") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Turn on behavior monitoring", "Not configure/Enabled")
    if "DisableIOAVProtection" in clist10:
        s = "Scan all downloaded files and attachments"
        if clist10.get("DisableIOAVProtection") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    if "DisableScanOnRealtimeEnable" in clist10:
        s = "Turn on process scanning whenever real-time protection is enabled"
        if clist10.get("DisableScanOnRealtimeEnable") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Turn on process scanning whenever real-time protection is enabled",
                     "Not configure/Enabled")
    if "DisableOnAccessProtection" in clist10:
        s = "Monitor file and program activity on your computer"
        if clist10.get("DisableOnAccessProtection") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Monitor file and program activity on your computer", "Not configure/Enabled")
    if "DisableArchiveScanning" in clist10:
        s = "Scan archive files"
        if clist10.get("DisableArchiveScanning") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Scan archive files", "Not configure/Enabled")
    if "DisablePackedExeScanning" in clist10:
        s = "Scan packed executables"
        if clist10.get("DisablePackedExeScanning") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Scan packed executables", "Not configure/Enabled")
    if "DisableRemovableDriveScanning" in clist10:
        s = "Scan removable drives"
        if clist10.get("DisableRemovableDriveScanning") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Scan removable drives", "Not configure/Disabled")
    print("\n10. Windows Defender:")
    result_table(passed, failed)


def filer_info_11():
    file = open(".\\logs\\result11.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def checklist_11(clist11):
    passed = []
    failed = []
    if "fSingleSessionPerUser" in clist11:
        s = "Restrict Remote Desktop Services users to a single Remote Desktop Services session"
        if clist11.get("fSingleSessionPerUser") == "0x1":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(passed, "Restrict Remote Desktop Services users to a single Remote Desktop Services session",
                     "Not configured/Enabled")
    if "fDisableClip" in clist11:
        s = "Do not allow Clipboard redirection"
        if clist11.get("fDisableClip") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Do not allow Clipboard redirection", "Not configured/Disabled")
    if "fDisableCdm" in clist11:
        s = "Do not allow drive redirection"
        if clist11.get("fDisableCdm") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Do not allow drive redirection", "Not configured/Disabled")
    if "MinEncryptionLevel" in clist11:
        s = "Set client connection encryption level"
        if clist11.get("MinEncryptionLevel") == "0x3":
            append_array(passed, s, "High Level")
        elif clist11.get("MinEncryptionLevel") == "0x2":
            append_array(failed, s, "Client Compatible")
        else:
            append_array(failed, s, "Low Level")
    else:
        append_array(passed, "Set client connection encryption level", "Not configured/High Level")
    if "fPromptForPassword" in clist11:
        s = "Always prompt for password upon connection"
        if clist11.get("fPromptForPassword") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Always prompt for password upon connection", "Not configured/Disabled")
    if "fEncryptRPCTraffic" in clist11:
        s = "Require secure RPC communication"
        if clist11.get("fEncryptRPCTraffic") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Require secure RPC communication", "Not configured/Disabled")
    if "SecurityLayer" in clist11:
        s = "Require use of specific security layer for remote (RDP) connections"
        if clist11.get("SecurityLayer") == "0x2":
            append_array(passed, s, "SSL")
        elif clist11.get("SecurityLayer") == "0x1":
            append_array(failed, s, "Negotiate")
        elif clist11.get("SecurityLayer") == "0x0":
            append_array(failed, s, "RDP")
    else:
        append_array(failed, "Require use of specific security layer for remote (RDP) connections",
                     "Not configured/Disabled")
    if "UserAuthentication" in clist11:
        s = "Require user authentication for remote connections by using Network Level Authentication"
        if clist11.get("UserAuthentication") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Require user authentication for remote connections by using Network Level Authentication",
                     "Not configured/")
    if "MaxDisconnectionTime" in clist11:
        s = "Set time limit for disconnected sessions"
        if clist11.get("MaxDisconnectionTime") == "0xea60":
            append_array(passed, s, "1 minutes")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Set time limit for disconnected sessions", "Not configured/Disabled")
    if "MaxIdleTime" in clist11:
        s = 0 < "Set time limit for active but idle Remote Desktop Services sessions"
        if int(clist11.get("MaxIdleTime"), 16) <= 900000:
            append_array(passed, s, "<= 15 minutes")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Set time limit for active but idle Remote Desktop Services sessions",
                     "Not configured/Disabled")
    if "exitDeleteTempDirsOnExit" in clist11:
        s = "Do not delete temp folders upon"
        if clist11.get("exitDeleteTempDirsOnExit") == "0x1":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Do not delete temp folders upon", "Not configured")
    if "PerSessionTempDir" in clist11:
        s = "Do not use temporary folders per session"
        if clist11.get("PerSessionTempDir") == "0x1":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Do not use temporary folders per session", "Not configured")
    print("\n11. Remote Desktop Services:")
    result_table(passed, failed)


def filer_info_registry(filename):
    file = open(filename, "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def checklist_12(clist12):
    passed = []
    failed = []
    for key, value in clist12.items():
        if key == "EnableScriptBlockLogging":
            s = "Turn on PowerShell Script Block Logging"
            if value == "0x1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        elif key == "EnableTranscripting":
            s = "Turn on PowerShell Transcription"
            if value == "0x0":
                append_array(passed, s, "Disabled")
            else:
                append_array(failed, s, "Enabled")
        elif key == "EnableScripts":
            s = "Turn on Script Execution"
            if value == "0x0":
                append_array(failed, s, "Disabled")
        elif key == "ExecutionPolicy":
            s = "Turn on Script Execution"
            if value == "AllSigned":
                append_array(passed, s, "Enabled Allow only signed scripts")
            elif value == "RemoteSigned":
                append_array(failed, s, "Enabled Allow local scripts and remote signed scripts")
            elif value == "Unrestricted":
                append_array(failed, s, "Enabled Allow all scripts")
            else:
                append_array(failed, s, f"Enabled {value}")
    if "EnableScriptBlockLogging" not in clist12:
        s = "Turn on PowerShell Script Block Execution Logging"
        append_array(passed, s, "Default - Not configured/Enable")
    if "EnableTranscripting" not in clist12:
        s = "Turn on PowerShell Transcription"
        append_array(failed, s, "Default - Not configured")
    if "EnableScripts" not in clist12:
        s = "Turn on Script Execution"
        append_array(failed, s, "Default - Not configured/Disable")
    print("\n12. Windows PowerShell:")
    result_table(passed, failed)


def filter_info_13():
    file = open(".\\logs\\result13.txt", "r")
    client_settings = []
    service_settings = []

    settings = {}
    try:
        parts = file.read().strip().split("HKEY_LOCAL_MACHINE")

        # Process the first part (Client)
        client_part = parts[1].strip().split("\n")
        for line in client_part[1:]:
            client_settings.append(line.strip())

        # Process the second part (Service)
        service_part = parts[2].strip().split("\n")
        for line in service_part[1:]:
            service_settings.append(line.strip())

        for line in client_settings:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = "Client " + parts[0]
            settings[key] = parts[-1]
        for line in service_settings:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = "Service " + parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def checklist_13(clist13):
    passed = []
    failed = []
    if "Client AllowBasic" in clist13:
        s = "Client Allow Basic authentication"
        if clist13.get("Client AllowBasic") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Client Allow Basic authentication", "Not configured")
    if "Client AllowUnencryptedTraffic" in clist13:
        s = "Client Allow unencrypted traffic"
        if clist13.get("Client AllowUnencryptedTraffic") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Client Allow unencrypted traffic", "Not configured")
    if "Client AllowDigest" in clist13:
        s = "Client Disallow Digest authentication"
        if clist13.get("Client AllowDigest") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Client Disallow Digest authentication", "Not configured")
    if "Service AllowBasic" in clist13:
        s = "Service Allow Basic authentication"
        if clist13.get("Service AllowBasic") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Service Allow Basic authentication", "Not configured")
    if "Service AllowUnencryptedTraffic" in clist13:
        s = "Service Allow unencrypted traffic"
        if clist13.get("Service AllowUnencryptedTraffic") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Service Allow unencrypted traffic", "Not configured")
    if "Service DisableRunAs" in clist13:
        s = "Service Disallow WinRM from storing RunAs credentials"
        if clist13.get("Service DisableRunAs") == "0x0":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Service Disallow WinRM from storing RunAs credentials", "Not configured")
    if "Service AllowAutoConfig" in clist13:
        s = "Service Allow remote server management through WinRM"
        if clist13.get("Service AllowAutoConfig") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Service Allow remote server management through WinRM", "Not configured")
    print("\n13. WinRM:")
    result_table(passed, failed)


def checklist_14(clist14):
    passed = []
    failed = []
    s = "Allow Remote Shell Access"
    if "AllowRemoteShellAccess" in clist14:
        if clist14.get("AllowRemoteShellAccess") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, s, "Not configured")
    print("\n14. Windows Remote Shell:")
    result_table(passed, failed)


def checklist_15(clist15):
    passed = []
    failed = []
    s = "Print Spooler"
    if "Start" in clist15:
        if clist15.get("Start") == "0x4":
            append_array(passed, s, "Disabled")
        elif clist15.get("Start") == "0x3":
            append_array(failed, s, "Manual")
        elif clist15.get("Start") == "0x2":
            append_array(failed, s, "Automatic")
    else:
        append_array(failed, s, "Not configured")
    print("\n15. System Services:")
    result_table(passed, failed)


def checklist_16(clist16):
    passed = []
    failed = []
    s = "Turn off Local Group Policy Objects processing"
    if "DisableLGPOProcessing" in clist16:

        if clist16.get("DisableLGPOProcessing") == "0x1":
            append_array(passed, s, "Enabled")
        elif clist16.get("DisableLGPOProcessing") == "0x2":
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, s, "Not configured")
    print("\n16. Group Policy:")
    result_table(passed, failed)


def filter_info_4():
    file = open(".\\logs\\result4.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            if parts[0].startswith("Account"):
                key = parts[0] + " " + parts[1]
            else:
                key = parts[0]
            settings[key] = parts[2]
    except:
        pass
    return settings


def checklist_4(clist4):
    passed = []
    failed = []
    checklist_misc(filter_info_secpol(".\\logs\\result4_22.txt"), passed, failed)
    if "Account active" in clist4:
        s = "Accounts Administrator: account status"
        if clist4.get("Account active") == "No":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    if "RequireSignOrSeal" in clist4:
        s = "Domain member: Digitally encrypt or sign secure channel data (always)"
        if clist4.get("RequireSignOrSeal") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Domain member: Digitally encrypt or sign secure channel data (always)",
                     "Default/Enabled")
    if "SealSecureChannel" in clist4:
        s = "Domain member: Digitally encrypt secure channel data (when possible)"
        if clist4.get("SealSecureChannel") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Domain member: Digitally encrypt secure channel data (when possible)", "Default/Enabled")
    if "SignSecureChannel" in clist4:
        s = "Domain member: Digitally sign secure channel data (when possible)"
        if clist4.get("SignSecureChannel") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Domain member: Digitally sign secure channel data (when possible)", "Default/Enabled")
    if "DisablePasswordChange" in clist4:
        s = "Domain member: Disable machine account password changes"
        if clist4.get("DisablePasswordChange") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(passed, "Domain member: Disable machine account password changes", "Default/Disabled")
    if "MaximumPasswordAge" in clist4:
        s = "Domain member: Maximum machine account password age"
        if 0 < int(clist4.get("MaximumPasswordAge"), 16) <= 30:
            append_array(passed, s, f"{int(clist4.get("MaximumPasswordAge"), 16)} days")
        else:
            append_array(failed, s, f"{int(clist4.get("MaximumPasswordAge"), 16)} days")
    else:
        append_array(passed, "Domain member: Maximum machine account password age", "Default/30 days")
    if "RequireStrongKey" in clist4:
        s = "Domain member: Require strong (Windows 2000 or later) session key"
        if clist4.get("RequireStrongKey") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Domain member: Require strong (Windows 2000 or later) session key", "Default/Enabled")
    if "InactivityTimeoutSecs" in clist4:
        s = "Interactive logon: Machine inactivity limit Inactivity"
        if 0 < int(clist4.get("InactivityTimeoutSecs"), 16) <= 900:
            append_array(passed, s, f"{int(clist4.get("InactivityTimeoutSecs"), 16)} seconds")
        else:
            append_array(failed, s, f"{int(clist4.get("InactivityTimeoutSecs"), 16)} seconds")
    else:
        append_array(failed, "Interactive logon: Machine inactivity limit", "Default/not enforced")
    if "CachedLogonsCount" in clist4:
        s = "Interactive logon: Number of previous logons to cache"
        if int(clist4.get("CachedLogonsCount")) <= 4:
            append_array(passed, s, f"{int(clist4.get("CachedLogonsCount"))} logon(s)")
        else:
            append_array(failed, s, f"{int(clist4.get("CachedLogonsCount"))} logon(s)")
    else:
        append_array(failed, "Interactive logon: Number of previous logons to cache", "Default/10 logon(s)")
    if "PasswordExpiryWarning" in clist4:
        s = "Interactive logon: Prompt user to change password before expiration"
        if 5 <= int(clist4.get("PasswordExpiryWarning"), 16) <= 14:
            append_array(passed, s, f"{int(clist4.get("PasswordExpiryWarning"), 16)} days")
        else:
            append_array(failed, s, f"{int(clist4.get("PasswordExpiryWarning"), 16)} days")
    else:
        append_array(failed, "Interactive logon: Prompt user to change password before expiration", "Default/5 days")
    if "RequireSecuritySignature" in clist4:
        s = "Microsoft network client: Digitally sign communications (always)"
        if clist4.get("RequireSecuritySignature") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Microsoft network client: Digitally sign communications (always)", "Default/Disabled")
    if "EnableSecuritySignature" in clist4:
        s = "Microsoft network client: Digitally sign communications (if server agrees)"
        if clist4.get("EnableSecuritySignature") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Microsoft network client: Digitally sign communications (if server agrees)",
                     "Default/Enabled")
    if "EnablePlainTextPassword" in clist4:
        s = "Microsoft network client: Send unencrypted password to third-party SMB servers"
        if clist4.get("EnablePlainTextPassword") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(passed, "Microsoft network client: Send unencrypted password to third-party SMB servers",
                     "Default/Disabled")
    if "autodisconnect" in clist4:
        s = "Microsoft network server: Amount of idle time required before suspending session"
        if 0 < int(clist4.get("autodisconnect"), 16) <= 15:
            append_array(passed, s, f"{int(clist4.get('autodisconnect'), 16)} minute(s)")
        else:
            append_array(failed, s, f"{int(clist4.get('autodisconnect'), 16)} minute(s)")
    else:
        append_array(passed, "Microsoft network server: Amount of idle time required before suspending session",
                     "Default/Not defined")
    if "requiresecuritysignature" in clist4:
        s = "Microsoft network server: Digitally sign communications (always)"
        if clist4.get("requiresecuritysignature") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Microsoft network server: Digitally sign communications (always)", "Default")
    if "enablesecuritysignature" in clist4:
        s = "Microsoft network server: Digitally sign communications (if client agrees)"
        if clist4.get("enablesecuritysignature") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, "Microsoft network server: Digitally sign communications (if client agrees)",
                     "Default/Enabled on domain controllers only.")
    if "enableforcedlogoff" in clist4:
        s = "Microsoft network server: Disconnect clients when logon hours expire"
        if clist4.get("enableforcedlogoff") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Microsoft network server: Disconnect clients when logon hours expire", "Default/Enabled")
    if "SmbServerNameHardeningLevel" in clist4:
        s = "Microsoft network server: Server SPN target name validation level"
        if clist4.get("SmbServerNameHardeningLevel") == "0x1":
            append_array(passed, s, "Accept if provided by client or higher")
        elif clist4.get("SmbServerNameHardeningLevel") == "0x2":
            append_array(passed, s, "Required from client")
        else:
            append_array(failed, s, "Off")
    else:
        append_array(failed, "Microsoft network server: Server SPN target name validation level", "Default/Off")
    if "UseMachineId" in clist4:
        s = "Network security: Allow Local System to use computer identity for NTLM"
        if clist4.get("UseMachineId") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Network security: Allow Local System to use computer identity for NTLM",
                     "Default/Enabled")
    if "SupportedEncryptionTypes" in clist4:
        s = "Network security: Configure encryption types allowed for Kerberos"
        if clist4.get("SupportedEncryptionTypes") == "0x7ffffff8":
            append_array(passed, s, "AES128_HMAC_SHA/ES256_HMAC_SHA1/Future encryption types")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Network security: Configure encryption types allowed for Kerberos", "Default/Not defined")
    if "NoLmHash" in clist4:
        s = "Network security: Do not store LAN Manager hash value on next password change"
        if clist4.get("NoLmHash") == "0x1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Network security: Do not store LAN Manager hash value on next password change",
                     "Default/Enabled")
    if "LmCompatibilityLevel" in clist4:
        s = "Network security: LAN Manager authentication level"
        if clist4.get("LmCompatibilityLevel") == "0x5":
            append_array(passed, s, "Send NTLMv2 response only. Refuse LM & NTLM")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Network security: LAN Manager authentication level", "Default/Depends on OS")
    if "ldapclientintegrity" in clist4:
        s = "Network security: LDAP client signing requirements"
        if clist4.get("ldapclientintegrity") == "0x1":
            append_array(passed, s, "Negotiate signing")
        elif clist4.get("ldapclientintegrity") == "0x2":
            append_array(passed, s, "Require signing")
        else:
            append_array(failed, s, "None")
    else:
        append_array(passed, "Network security: LDAP client signing requirements", "Default/Negotiate signing")
    if "NtlmMinClientSec" in clist4:
        s = "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients"
        if clist4.get("NtlmMinClientSec") == "0x20080000":
            append_array(passed, s, "Require NTLMv2 session security/Require 128-bit encryption")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed,
                     "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients",
                     "Default/Depends on OS")
    if "NtlmMinServerSec" in clist4:
        s = "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers"
        if clist4.get("NtlmMinServerSec") == "0x20080000":
            append_array(passed, s, "Require NTLMv2 session security/Require 128-bit encryption")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed,
                     "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers",
                     "Default/Depends on OS")

    print("\n4. Security Options:")
    result_table(passed, failed)


def filter_info_secpol(path):
    file = open(path, "r")
    settings = {}
    for line in file:
        line = remove_extra_spaces(line)
        line = line.strip()
        array_line = line.split("=")
        settings[array_line[0].strip()] = array_line[1].strip()
    return settings


def checklist_3(clist3):
    passed = []
    failed = []
    if "SeNetworkLogonRight" in clist3:
        s = "Access this computer from the network"
        if clist3.get("SeNetworkLogonRight") == "*S-1-5-11,*S-1-5-32-544,*S-1-5-9":
            append_array(passed, s, "Administrators,Authenticated Users")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Access this computer from the network", "Default")
    if "SeRemoteInteractiveLogonRight" in clist3:
        s = "Deny access to this computer from the network"
        if clist3.get("SeRemoteInteractiveLogonRight") == "*S-1-5-113,Administrator,Guest":
            append_array(passed, s, "Guest,Administrators,Local Account")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Deny access to this computer from the network", "Default")
    if "SeDenyBatchLogonRight" in clist3:
        s = "Deny log on as a batch job"
        if clist3.get("SeDenyBatchLogonRight") == "Guest,Domain Admins,Enterprise Admins":
            append_array(passed, s, "Guest,Domain Admins,Enterprise Admins")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Deny log on as a batch job", "Default")
    if "SeDenyServiceLogonRight" in clist3:
        s = "Deny log on as a service"
        if clist3.get("SeDenyServiceLogonRight") == "Guest,Domain Admins,Enterprise Admins":
            append_array(passed, s, "Guest,Domain Admins,Enterprise Admins")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Deny log on as a service", "Default")
    if "SeDenyRemoteInteractiveLogonRight" in clist3:
        s = "Deny log on through Remote Desktop Services"
        if clist3.get(
                "SeDenyRemoteInteractiveLogonRight") == "*S-1-5-113,Administrator,Guest,Domain Admins,Enterprise Admins":
            append_array(passed, s, "Guest,Domain Admins,Enterprise Admins")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Deny log on through Remote Desktop Services", "Default")
    if "SeDenyInteractiveLogonRight" in clist3:
        s = "Deny log on locally"
        if clist3.get("SeDenyInteractiveLogonRight") == "Guest,Domain Admins,Enterprise Admins":
            append_array(passed, s, "Guest,Domain Admins,Enterprise Admins")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Deny log on locally", "Default")
    if "SeInteractiveLogonRight" in clist3:
        s = "Allow log on locally"
        if clist3.get("SeInteractiveLogonRight") == "*S-1-5-32-544":
            append_array(passed, s, "Administrator")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Allow log on locally", "Default")
    if "SeRemoteInteractiveLogonRight" in clist3:
        s = "Allow log on through Remote Desktop Services"
        if clist3.get("SeRemoteInteractiveLogonRight") == "*S-1-5-32-544":
            append_array(passed, s, "Administrator")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(passed, "Allow log on through Remote Desktop Services", "Default")
    if "SeShutdownPrivilege" in clist3:
        s = "Shutdown the system"
        if clist3.get("SeShutdownPrivilege") == "*S-1-5-32-544":
            append_array(passed, s, "Guest,Domain Admins,Enterprise Admins")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Shutdown the system", "Default")
    if "SeAssignPrimaryTokenPrivilege" in clist3:
        s = "Act as part of the operating system"
        if clist3.get("SeAssignPrimaryTokenPrivilege") == "*S-1-5-19,*S-1-5-20":
            append_array(passed, s, "None")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(passed, "Act as part of the operating system", "Default")

    print("\n3. User Rights Assignment:")
    result_table(passed, failed)


def checklist_misc(clistmisc, passed, failed):
    if "PasswordComplexity" in clistmisc:
        s = "Password must meet complexity requirements "
        if clistmisc.get("PasswordComplexity") == "1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Password must meet complexity requirements ", "Default/Enabled")
    if "ClearTextPassword" in clistmisc:
        s = "Store passwords using reversible encryption"
        if clistmisc.get("ClearTextPassword") == "1":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(passed, "Store passwords using reversible encryption", "Default/Disabled")
    if "ForceLogoffWhenHourExpire" in clistmisc:
        s = "Network security: Force logoff when logon hours expire"
        if clistmisc.get("ForceLogoffWhenHourExpire") == "1":
            append_array(passed, s, "Enabled")
        else:
            append_array(failed, s, "Disabled")
    else:
        append_array(passed, "Network security: Force logoff when logon hours expire", "Default/Enabled")



def compare_checklist():
    clist1 = filter_info_1()
    clist3 = filter_info_secpol(".\\logs\\result3.txt")
    clist4 = filter_info_4()
    clist5 = filer_info_5()
    clist6 = filter_info_6()
    clist7 = filter_info_7()
    clist8 = filter_info_8()
    clist9 = filter_info_9()
    clist10 = filer_info_registry(".\\logs\\result10.txt")
    clist11 = filer_info_registry(".\\logs\\result11.txt")
    clist12 = filer_info_registry(".\\logs\\result12.txt")
    clist13 = filter_info_13()
    clist14 = filer_info_registry(".\\logs\\result14.txt")
    clist15 = filer_info_registry(".\\logs\\result15.txt")
    clist16 = filer_info_registry(".\\logs\\result16.txt")


    checklist_1(clist1)
    checklist_3(clist3)
    checklist_4(clist4)
    checklist_5(clist5)
    checklist_6(clist6)
    checklist_7(clist7)
    checklist_8(clist8)
    checklist_9(clist9)
    checklist_10(clist10)
    checklist_11(clist11)
    checklist_12(clist12)
    checklist_13(clist13)
    checklist_14(clist14)
    checklist_15(clist15)
    checklist_16(clist16)



# dung de cho vao bang passed va failed
'''
def result_table1(passed, failed):
    # Create the table with two columns
    table = PrettyTable(max_table_width=100)
    table.field_names = ["Passed", "Failed"]

    # Determine the max length of passed/failed lists to balance the table rows
    max_len = max(len(passed), len(failed))

    # Add rows to the table, pairing passed and failed items
    for i in range(max_len):
        passed_item = passed[i] if i < len(passed) else ""
        failed_item = failed[i] if i < len(failed) else ""
        table.add_row([passed_item, failed_item])

    # Print the table
    print(table)
    return
'''


def result_table(passed, failed, width=100):
    # Wrap text in each column to the specified width
    passed_wrapped = [fill(item, width=width) if item else '' for item in passed]
    failed_wrapped = [fill(item, width=width) if item else '' for item in failed]

    # Create the table with two columns
    table = [[p, f] for p, f in zip_longest(passed_wrapped, failed_wrapped, fillvalue='')]

    # Print the table
    print(tabulate(table, headers=["Passed", "Failed"], tablefmt="grid"))


def execute(choice):
    #if choice == 0:
    #    install_requirements()
    if choice == 1:
        run_query()
        compare_checklist()
        return


if __name__ == "__main__":
    display_banner()
    # install_requirements()
    # checklist = filter_info()
    # compare_checklist()
    menu()
