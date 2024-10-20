import pyfiglet
import sys
import os
import random
import subprocess
import re
from prettytable import PrettyTable


# gui function
def display_banner():
    # Create random font
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
    print("0. Install requirements")
    ''''
    print("1. Password Policy and Account Lockout Policy")
    print("2. User Rights Assignment")
    print("3. Security Options")
    print("4. Windows Defender Firewall with Advanced Security")
    print("5. Audit Policy")
    print("6. MS Security Guide")
    print("7. Network Provider")
    print("8. Credentials Delegation")
    '''
    print("1. Auto Audit")
    print("2. Exit")
    new_path = ".\\logs"
    if not os.path.exists(new_path):
        os.makedirs(new_path)
    while True:
        user_input = input("\nInput (0-2): ")
        if user_input.isdigit():
            choice = int(user_input)
            if 1 >= choice >= 0:
                execute(choice)
            elif choice == 2:
                exit()
            else:
                print("Invalid input! Try again.")
        else:
            print("Invalid input! Try again.")


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


#########################################################################################################################


# chay lenh cmd bang cach doc file query.txt va output ra 1 file result.txt o thu muc logs
def run_query():
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
    for key in clist1:
        try:
            value = int(clist1.get(key))
        except ValueError:
            value = -1
        if key == "Minimum password age (days)":
            if value >= 1:
                append_array(passed, f"1.3 {key}", clist1.get(key))
            else:
                append_array(failed, f"1.3 {key}", clist1.get(key))
        elif key == "Maximum password age (days)":
            if 30 <= value <= 90:
                append_array(passed, f"1.2 {key}", clist1.get(key))
            else:
                append_array(failed, f"1.2 {key}", clist1.get(key))
        elif key == "Minimum password length":
            if value >= 14:
                append_array(passed, f"1.4 {key}", clist1.get(key))
            else:
                append_array(failed, f"1.4 {key}", clist1.get(key))
        elif key == "Length of password history maintained":
            if value >= 14:
                append_array(passed, f"1.1 {key}", clist1.get(key))
            else:
                append_array(failed, f"1.1 {key}", clist1.get(key))
        elif key == "Lockout threshold":
            if 0 < value <= 5:
                append_array(passed, f"2.2 {key}", clist1.get(key))
            else:
                append_array(failed, f"2.2 {key}", clist1.get(key))
        elif key == "Lockout duration (minutes)":
            if value >= 15:
                append_array(passed, f"2.1 {key}", clist1.get(key))
            else:
                append_array(failed, f"2.1 {key}", clist1.get(key))
        elif key == "Lockout observation window (minutes)":
            if value >= 15:
                append_array(passed, f"2.2 {key}", clist1.get(key))
            else:
                append_array(failed, f"2.2 {key}", clist1.get(key))
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
    if len(clist10) == 0:
        append_array(passed, "Windows Defender Policy 10.1 -> 10.8", "Default - Not configured")
    for key, value in clist10.items():
        if key == "DisableAntiSpyware":
            if value == "0x0":
                append_array(passed, "Turn off Windows Defender", "Disabled")
            else:
                append_array(failed, "Turn off Windows Defender", "Enabled")
        elif key == "DisableRealtimeMonitoring":
            if value == "0x0":
                append_array(passed, "Turn off real-time protection", "Disabled")
            else:
                append_array(failed, "Turn off real-time protection", "Enabled")
        elif key == "DisableBehaviorMonitoring":
            if value == "0x0":
                append_array(passed, "Turn on behavior monitoring", "Enabled")
            else:
                append_array(failed, "Turn on behavior monitoring", "Disable")
        elif key == "DisableIOAVProtection":
            if value == "0x0":
                append_array(passed, "Scan all downloaded files and attachments", "Enabled")
            else:
                append_array(failed, "Scan all downloaded files and attachments", "Disable")
        elif key == "DisableScanOnRealtimeEnable":
            if value == "0x0":
                append_array(passed, "Turn on process scanning whenever real-time protection is enabled", "Enabled")
            else:
                append_array(failed, "Turn on process scanning whenever real-time protection is enabled", "Disable")
        elif key == "DisableOnAccessProtection":
            if value == "0x0":
                append_array(passed, "Monitor file and program activity on your computer", "Enabled")
            else:
                append_array(failed, "Monitor file and program activity on your computer", "Disable")
        elif key == "DisableArchiveScanning":
            if value == "0x0":
                append_array(passed, "Scan archive files", "Enabled")
            else:
                append_array(failed, "Scan archive files", "Disable")
        elif key == "DisablePackedExeScanning":
            if value == "0x0":
                append_array(passed, "Scan packed executables", "Enabled")
            else:
                append_array(failed, "Scan packed executables", "Disable")
    if "DisableRemovableDriveScanning" in clist10:
        if clist10["DisableRemovableDriveScanning"] == "0x0":
            append_array(passed, "Scan removable drives", "Enabled")
        else:
            append_array(failed, "Scan removable drives", "Disable")
    else:
        append_array(failed, "Scan removable drives", "Default - Not configured")
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
    if len(clist11) == 0:
        append_array(failed, "Remote Desktop Services", "Default - Not configured")
    for key, value in clist11.items():
        if key == "fSingleSessionPerUser":
            s = "Restrict Remote Desktop Services users to a single Remote Desktop Services session"
            if value == "0x1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        elif key == "fDisableClip":
            s = "Do not allow Clipboard redirection"
            if value == "0x1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        elif key == "fDisableCdm":
            s = "Do not allow drive redirection"
            if value == "0x1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        elif key == "MinEncryptionLevel":
            s = "Set client connection encryption level"
            if value == "0x3":
                append_array(passed, s, "High Level")
            elif value == "0x2":
                append_array(failed, s, "Client Compatible")
            elif value == "0x1":
                append_array(failed, s, "Low Level")
            else:
                append_array(failed, s, "Disabled")
        elif key == "fPromptForPassword":
            s = "Always prompt for password upon connection"
            if value == "0x1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        elif key == "fEncryptRPCTraffic":
            s = "Require secure RPC communication"
            if value == "0x1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        elif key == "SecurityLayer":
            s = "Require use of specific security layer for remote (RDP) connections"
            if value == "0x2":
                append_array(passed, s, "SSL")
            elif value == "0x1":
                append_array(failed, s, "Negotiate")
            elif value == "0x0":
                append_array(failed, s, "RDP")
            else:
                append_array(failed, s, "Disabled")
        elif key == "UserAuthentication":
            s = "Require user authentication for remote connections by using Network Level Authentication"
            if value == "0x1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        elif key == "MaxDisconnectionTime":
            s = "Require secure RPC communication"
            if value == "0xea60":
                append_array(passed, s, "'Enabled 1 minute")
            else:
                append_array(failed, s, "Disabled or wrong configuration")
        elif key == "MaxIdleTime":
            s = "Set time limit for active but idle Remote Desktop Services sessions"
            if value == "0xdbba0":
                append_array(passed, s, "Enabled <= 15 minute(s) (>0)")
            else:
                append_array(failed, s, "Disabled or wrong configuration")
        elif key == "exitDeleteTempDirsOnExit":
            s = "Do not delete temp folders upon"
            if value == "0x1":
                append_array(passed, s, "Disabled")
            else:
                append_array(failed, s, "Enabled")
    if "fSingleSessionPerUser" not in clist11:
        s = "Restrict Remote Desktop Services users to a single Remote Desktop Services session"
        append_array(passed, s, "Default - Not configured/Enable")
    if "MinEncryptionLevel" not in clist11:
        s = "Set client connection encryption level"
        append_array(passed, s, "Default - Not configured/High Level")
    print("\n11. Remote Desktop Services:")
    if len(clist11) < 12:
        print("WARNING: Query results are missing REQUIRE MANUAL CHECK")
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
    if "Account active" in clist4:
        s = "Accounts: Administrator account status"
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
        append_array(passed, "Domain member: Digitally encrypt or sign secure channel data (always)", "Default/Enabled")
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
        append_array(failed, "Interactive logon: Machine inactivity limit Inactivity", "Default/not enforced")
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
        append_array(passed, "Microsoft network client: Digitally sign communications (if server agrees)", "Default/Enabled")
    if "EnablePlainTextPassword" in clist4:
        s = "Microsoft network client: Send unencrypted password to third-party SMB servers"
        if clist4.get("EnablePlainTextPassword") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(passed, "Microsoft network client: Send unencrypted password to third-party SMB servers", "Default/Disabled")
    if "autodisconnect" in clist4:
        s = "Microsoft network server: Amount of idle time required before suspending session"
        if 0 < int(clist4.get("autodisconnect"), 16) <= 15:
            append_array(passed, s, f"{int(clist4.get('autodisconnect'), 16)} minute(s)")
        else:
            append_array(failed, s, f"{int(clist4.get('autodisconnect'), 16)} minute(s)")
    else:
        append_array(passed, "Microsoft network server: Amount of idle time required before suspending session", "Default/Not defined")
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
        append_array(failed, "Microsoft network server: Digitally sign communications (if client agrees)", "Default/Enabled on domain controllers only.")
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
        append_array(passed, "Network security: Allow Local System to use computer identity for NTLM", "Default/Enabled")
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
        append_array(passed, "Network security: Do not store LAN Manager hash value on next password change", "Default/Enabled")
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
        append_array(failed, "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients", "Default/Depends on OS")
    if "NtlmMinServerSec" in clist4:
        s = "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers"
        if clist4.get("NtlmMinServerSec") == "0x20080000":
            append_array(passed, s, "Require NTLMv2 session security/Require 128-bit encryption")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers", "Default/Depends on OS")
    print("\n4. Security Options:")
    result_table(passed, failed)


def compare_checklist():
    clist1 = filter_info_1()
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
    clist4 = filter_info_4()

    checklist_1(clist1)
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
def result_table(passed, failed):
    # Create the table with two columns
    table = PrettyTable()
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


def execute(choice):
    if choice == 0:
        install_requirements()
    elif choice == 1:
        run_query()
        compare_checklist()
        return


if __name__ == "__main__":
    display_banner()
    # install_requirements()
    # checklist = filter_info()
    # compare_checklist()
    menu()
