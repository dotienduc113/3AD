from textwrap import fill
from tabulate import tabulate
from itertools import zip_longest
from func.filter import *
from func.export import *

count_passed = 0
count_failed = 0
count = 0

def compare_checklist():

    clist1_2 = filter_Password_Account_lockout()
    clist3 = filter_info_secpol(".\\logs\\result3.txt")
    clist4 = filter_Security_Options()
    clist5 = filer_Windows_Defender_Firewall()
    clist6 = filter_Audit_Policy()
    clist7 = filter_MS_Security_Guide()
    clist8 = filter_Network_Provider()
    clist9 = filter_Credentials_Delegation()
    clist10 = filer_info_registry(".\\logs\\result10.txt")
    clist11 = filer_info_registry(".\\logs\\result11.txt")
    clist12 = filer_info_registry(".\\logs\\result12.txt")
    clist13 = filter_WinRM()
    clist14 = filer_info_registry(".\\logs\\result14.txt")
    clist15 = filer_info_registry(".\\logs\\result15.txt")
    clist16 = filer_info_registry(".\\logs\\result16.txt")

    Password_Account_lockout(clist1_2)
    User_Rights_Assignment(clist3)
    Security_Options(clist4)
    Windows_Defender_Firewall(clist5)
    Audit_Policy(clist6)
    MS_Security_Guide(clist7)
    Network_Provider(clist8)
    Credentials_Delegation(clist9)
    Windows_Defender(clist10)
    Remote_Desktop_Services(clist11)
    Windows_PowerShell(clist12)
    WinRM(clist13)
    Windows_Remote_Shell(clist14)
    System_Services(clist15)
    Group_Policy(clist16)
    AD_User_Account()

    # print("\n")
    # print("Final result: ")
    # print("Passed: " + str(count_passed) + "\nFailed: " + str(count_failed) + "\nTotal: " + str(113))


def result_table(passed, failed, width=100):
    # Wrap text in each column to the specified width
    passed_wrapped = [fill(item, width=width) if item else '' for item in passed]
    failed_wrapped = [fill(item, width=width) if item else '' for item in failed]

    # Create the table with two columns
    table = [[p, f] for p, f in zip_longest(passed_wrapped, failed_wrapped, fillvalue='')]

    print(tabulate(table, headers=["Passed", "Failed"], tablefmt="grid"))

    global count
    global count_passed
    global count_failed
    count = count + len(passed) + len(failed)
    count_passed = len(passed)
    count_failed = len(failed)

    return tabulate(table, headers=["Passed", "Failed"], tablefmt="grid")


def export_result(str, table, current_time):
    f_name = f"3AD_{current_time}.txt"
    with open(f".\\results\\{f_name}", "a+") as f:
        f.write(str)
        f.write(table)


def append_array(array, key, value):
    array.append(key + ": " + value)
    return


def Password_Account_lockout(clist1):  # checklist 1 va 2 lay du lieu va so sanh
    passed = []
    failed = []
    checklist_misc(filter_info_secpol(".\\logs\\result1_56.txt"), passed, failed, 1)
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
            str = "Enforce password history"
            if value >= 14:
                append_array(passed, f"{str}", clist1.get(key))
            else:
                append_array(failed, f"{str}", clist1.get(key))
        elif key == "Lockout threshold":
            str = "Account lockout threshold"
            if 0 < value <= 5:
                append_array(passed, f"{str}", clist1.get(key))
            else:
                append_array(failed, f"{str}", clist1.get(key))
        elif key == "Lockout duration (minutes)":
            str = "Account lockout duration (minutes)"
            if value >= 15:
                append_array(passed, f"{str}", clist1.get(key))
            else:
                append_array(failed, f"{str}", clist1.get(key))
        elif key == "Lockout observation window (minutes)":
            str = "Reset account lockout counter after (minutes)"
            if value >= 15:
                append_array(passed, f"{str}", clist1.get(key))
            else:
                append_array(failed, f"{str}", clist1.get(key))
    str = "\nPassword Policy and Account Lockout Policy"
    print(str)
    t = result_table(passed, failed)
    export_json(passed, Password_Account_lockout_miti, str.strip(), "passed")
    export_json(failed, Password_Account_lockout_miti, str.strip(), "failed")
    #export_result(str.strip() + "\n", t, current_time)





def User_Rights_Assignment(clist3):
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
        s = "Shut down the system"
        if clist3.get("SeShutdownPrivilege") == "*S-1-5-32-544":
            append_array(passed, s, "Guest,Domain Admins,Enterprise Admins")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Shut down the system", "Default")
    if "SeAssignPrimaryTokenPrivilege" in clist3:
        s = "Act as part of the operating system"
        if clist3.get("SeAssignPrimaryTokenPrivilege") == "*S-1-5-19,*S-1-5-20":
            append_array(passed, s, "None")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(passed, "Act as part of the operating system", "Default")

    str = "\nUser Rights Assignment"
    print(str)
    t = result_table(passed, failed)
    export_json(passed, User_Rights_Assignment_miti, str.strip(), "passed")
    export_json(failed, User_Rights_Assignment_miti, str.strip(), "failed")
    #export_result("\n" + str + "\n", t, current_time)


def Security_Options(clist4):
    passed = []
    failed = []
    checklist_misc(filter_info_secpol(".\\logs\\result4_22.txt"), passed, failed, 4)
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
        s = "Interactive logon: Number of previous logons to cache (in case domain controller is not available)"
        if int(clist4.get("CachedLogonsCount")) <= 4:
            append_array(passed, s, f"{int(clist4.get("CachedLogonsCount"))} logon(s)")
        else:
            append_array(failed, s, f"{int(clist4.get("CachedLogonsCount"))} logon(s)")
    else:
        append_array(failed, "Interactive logon: Number of previous logons to cache (in case domain controller is not available)", "Default/10 logon(s)")
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
    str = "\nSecurity Options"
    print(str)
    t = result_table(passed, failed)
    export_json(passed, Security_Options_miti, str.strip(), "passed")
    export_json(failed, Security_Options_miti, str.strip(), "failed")
    #export_result("\n" + str + "\n", t, current_time)


def Windows_Defender_Firewall(clist5):
    passed = []
    failed = []
    for profile, settings in clist5.items():
        for obj, value in settings:
            if obj == "State":
                if value == "ON":
                    append_array(passed, f"{profile[:-18]} Firewall state", value)
                else:
                    append_array(failed, f"{profile[:-18]} Firewall state", value)
            if obj == "Firewall Policy":
                if "BlockInbound" in value:
                    append_array(passed, f"{profile[:-18]} Inbound connections", value)
                else:
                    append_array(failed, f"{profile[:-18]} Inbound connections", value)
            if obj == "LogAllowedConnections":
                if value == "Enable":
                    append_array(passed, f"{profile[:-18]} Log successful connections", value)
                else:
                    append_array(failed, f"{profile[:-18]} Log successful connections", value)
            if obj == "LogDroppedConnections":
                if value == "Enable":
                    append_array(passed, f"{profile[:-18]} Log dropped packets", value)
                else:
                    append_array(failed, f"{profile[:-18]} Log dropped packets", value)
            if obj == "MaxFileSize":
                if int(value) >= 16384:
                    append_array(passed, f"{profile[:-18]} Log file maximum size (KB)", value)
                else:
                    append_array(failed, f"{profile[:-18]} Log file maximum size (KB)", value)
    str = "\nWindows Defender Firewall with Advanced Security"
    print(str)
    t = result_table(passed, failed)
    export_json(passed, Windows_Defender_Firewall_miti, str.strip(), "passed")
    export_json(failed, Windows_Defender_Firewall_miti, str.strip(), "failed")
    # export_result("\n" + str + "\n", t, current_time)


def Audit_Policy(clist6):
    passed = []
    failed = []
    if "Credential Validation" in clist6 and "Kerberos Service Ticket Operations" in clist6 and "Kerberos Authentication Service" in clist6:
        if clist6.get("Credential Validation") == "Success and Failure" and clist6.get(
                "Kerberos Service Ticket Operations") == "Success and Failure" and clist6.get(
            "Kerberos Authentication Service") == "Success and Failure":
            append_array(passed, "Audit account logon event", "Success and Failure")
        else:
            append_array(failed, "Audit account logon event", "Misconfigure")
    else:
        append_array(failed, "Audit account logon event", "Default")
    if "Distribution Group Management" in clist6 and "Other Account Management Events" in clist6 and "Application Group Management" in clist6 and "User account management" in clist6:
        if clist6.get("Distribution Group Management") == "Success" and clist6.get(
                "Other Account Management Events") == "Success" and clist6.get(
            "Application Group Management") == "Success and Failure" and clist6.get(
            "User account management") == "Success and Failure":
            append_array(passed, "Audit account management", "Success")
        else:
            append_array(failed, "Audit account management", "Misconfigure")
    else:
        append_array(failed, "Audit account management", "Default")
    if "Process Creation" in clist6:
        if clist6.get("Process Creation") == "Success":
            append_array(passed, "Audit process tracking", "Success")
        else:
            append_array(failed, "Audit process tracking", "Misconfigure")
    else:
        append_array(failed, "Audit process tracking", "Default")
    if "Directory Service Access" in clist6 and "Directory Service Changes" in clist6 and "Directory Service Replication" in clist6 and "Detailed Directory Service Replication" in clist6:
        if clist6.get("Directory Service Access") == "Success and Failure" and clist6.get(
                "Directory Service Changes") == "Success and Failure" and clist6.get(
            "Directory Service Replication") == "Success and Failure" and clist6.get(
            "Detailed Directory Service Replication") == "Success and Failure":
            append_array(passed, "Audit Directory Service Access", "Success and Failure")
        else:
            append_array(failed, "Audit Directory Service Access", "Default/Misconfigure")
    else:
        append_array(failed, "Audit Directory Service Access", "Default")
    if "Logon" in clist6 and "Logoff" in clist6 and "Account Lockout" in clist6 and "IPsec Main Mode" in clist6 and "IPsec Quick Mode" in clist6 and "IPsec Extended Mode" in clist6 and "Special Logon" in clist6 and "Other Logon/Logoff Events" in clist6 and "Network Policy Server" in clist6:
        if clist6.get("Logon") == "Success and Failure" and clist6.get(
                "Logoff") == "Success and Failure" and clist6.get(
            "Account Lockout") == "Success and Failure" and clist6.get(
            "IPsec Main Mode") == "Success and Failure" and clist6.get(
            "IPsec Quick Mode") == "Success and Failure" and clist6.get(
            "IPsec Extended Mode") == "Success and Failure" and clist6.get(
            "Special Logon") == "Success and Failure" and clist6.get(
            "Other Logon/Logoff Events") == "Success and Failure" and clist6.get(
            "Network Policy Server") == "Success and Failure":
            append_array(passed, "Audit logon events", "Success and Failure")
        else:
            append_array(failed, "Audit logon events", "Misconfigure")
    else:
        append_array(failed, "Audit logon events", "Default")
    if "Audit Policy Change" in clist6 and "MPSSVC Rule-Level Policy Change" in clist6 and "Other Policy Change Events" in clist6 and "Authentication Policy Change" in clist6 and "Authorization Policy Change" in clist6 and "Filtering Platform Policy Change" in clist6:
        if clist6.get("Audit Policy Change") == "Success and Failure" and clist6.get(
                "MPSSVC Rule-Level Policy Change") == "Success and Failure" and clist6.get(
            "Other Policy Change Events") == "Success and Failure" and clist6.get(
            "Authentication Policy Change") == "Success" and clist6.get(
            "Authorization Policy Change") == "Success" and clist6.get(
            "Filtering Platform Policy Change") == "Success":
            append_array(passed, "Audit Policy Change", "Success and Failure")
        else:
            append_array(failed, "Audit Policy Change", "Misconfigure")
    else:
        append_array(failed, "Audit Policy Change", "Default")
    if "Non Sensitive Privilege Use" in clist6 and "Other Privilege Use Events" in clist6 and "Sensitive Privilege Use" in clist6:
        if clist6.get("Non Sensitive Privilege Use") == "Success and Failure" and clist6.get(
                "Other Privilege Use Events") == "Success and Failure" and clist6.get(
            "Sensitive Privilege Use") == "Success and Failure":
            append_array(passed, "Audit Privilege Use", "Success and Failure")
        else:
            append_array(failed, "Audit Privilege Use", "Misconfigure")
    else:
        append_array(failed, "Audit Privilege Use", "Default")

    str = "\nAudit Policy"
    print(str)
    t = result_table(passed, failed)
    export_json(passed, Audit_Policy_miti, str.strip(), "passed")
    export_json(failed, Audit_Policy_miti, str.strip(), "failed")
    if len(clist6) == 0:
        print("NOTE: Please run as administrator to get full results")
        #export_result("\n" + str + "\n" + "NOTE: Please run as administrator to get full results\n", t, current_time)
    #else:
    #export_result("\n" + str + "\n", t, current_time)


def MS_Security_Guide(clist7):
    passed = []
    failed = []
    print(clist7)
    if "SMB1" in clist7:
        s = "Configure SMB v1 server"
        if clist7.get("SMB1") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Configure SMB v1 server", "Not configured/Default Enabled")
    if "Start" in clist7:
        s = "Configure SMB v1 client driver"
        if clist7.get("Start") == "0x4":
            append_array(passed, s, "Disabled")
        elif clist7.get("Start") == "0x3":
            append_array(failed, s, "Manual start")
        elif clist7.get("Start") == "0x2":
            append_array(failed, s, "Automatic start")
    else:
        append_array(failed, "Configure SMB v1 client driver", "Not configured/Default Enabled")
    if "UseLogonCredential" in clist7:
        s = "WDigest Authentication"
        if clist7.get("UseLogonCredential") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "WDigest Authentication", "Not configured/Enabled")
    str = "\nMS Security Guide"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, MS_Security_Guide_miti, str.strip(), "passed")
    export_json(failed, MS_Security_Guide_miti, str.strip(), "failed")


def Network_Provider(clist8):
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
    str = "\nNetwork Provider"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, Network_Provider_miti, str.strip(), "passed")
    export_json(failed, Network_Provider_miti, str.strip(), "failed")

# clist9 = filter_Credentials_Delegation()
def Credentials_Delegation(clist9):
    # tao mang passed va failed
    passed = []
    failed = []
    # kiem tra neu khong cau hinh policy -> failed
    if len(clist9) == 0:
        append_array(failed, "Encryption Oracle Remediation", "Default - Not configured")
    # vong lap k-v cua dictionary clist
    for key, value in clist9.items():
        # kiem tra key = gia tri registry
        if key == "AllowEncryptionOracle":
            # so sanh gia tri value doi voi yeu cau cua checklist
            if value == "0x0":
                append_array(passed, "Encryption Oracle Remediation", "Enabled Force Updated Clients")
            elif value == "0x1":
                append_array(failed, "Encryption Oracle Remediation", "Enabled Mitigated")
            elif value == "0x2":
                append_array(failed, "Encryption Oracle Remediation", "Enabled Vulnerable")
    str = "\nCredentials Delegation"
    print(str)
    t = result_table(passed, failed)
    # export_result("\n" + str + "\n", t, current_time)
    # xuat ra json passed va failed array
    export_json(passed, Credentials_Delegation_miti, str.strip(), "passed")
    export_json(failed, Credentials_Delegation_miti, str.strip(), "failed")


def Windows_Defender(clist10):
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
    else:
        append_array(passed, "Scan all downloaded files and attachments", "Not configure/Enabled")
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
    str = "\nWindows Defender"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, Windows_Defender_miti, str.strip(), "passed")
    export_json(failed, Windows_Defender_miti, str.strip(), "failed")


def Remote_Desktop_Services(clist11):
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
        s = "Set time limit for active but idle Remote Desktop Services sessions"
        if int(clist11.get("MaxIdleTime"), 16) <= 900000:
            append_array(passed, s, "<= 15 minutes")
        else:
            append_array(failed, s, "Misconfigured")
    else:
        append_array(failed, "Set time limit for active but idle Remote Desktop Services sessions",
                     "Not configured/Disabled")
    if "exitDeleteTempDirsOnExit" in clist11:
        s = "Do not delete temp folders upon exit"
        if clist11.get("exitDeleteTempDirsOnExit") == "0x1":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Do not delete temp folders upon exit", "Not configured")
    if "PerSessionTempDir" in clist11:
        s = "Do not use temporary folders per session"
        if clist11.get("PerSessionTempDir") == "0x1":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Do not use temporary folders per session", "Not configured")
    str = "\nRemote Desktop Services"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, Remote_Desktop_Services_miti, str.strip(), "passed")
    export_json(failed, Remote_Desktop_Services_miti, str.strip(), "failed")


def Windows_PowerShell(clist12):
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
        s = "Turn on PowerShell Script Block Logging"
        append_array(passed, s, "Default - Not configured/Enable")
    if "EnableTranscripting" not in clist12:
        s = "Turn on PowerShell Transcription"
        append_array(failed, s, "Default - Not configured")
    if "EnableScripts" not in clist12:
        s = "Turn on Script Execution"
        append_array(failed, s, "Default - Not configured/Disable")
    str = "\nWindows PowerShell"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, Windows_PowerShell_miti, str.strip(), "passed")
    export_json(failed, Windows_PowerShell_miti, str.strip(), "failed")


def WinRM(clist13):
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
        if clist13.get("Service DisableRunAs") == "0x1":
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
    str = "\nWinRM"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, WinRM_miti, str.strip(), "passed")
    export_json(failed, WinRM_miti, str.strip(), "failed")


def Windows_Remote_Shell(clist14):
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
    str = "\nWindows Remote Shell"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, Windows_Remote_Shell_miti, str.strip(), "passed")
    export_json(failed, Windows_Remote_Shell_miti, str.strip(), "failed")


def System_Services(clist15):
    passed = []
    failed = []
    s = "Print Spooler (Spooler)"
    if "Start" in clist15:
        if clist15.get("Start") == "0x4":
            append_array(passed, s, "Disabled")
        elif clist15.get("Start") == "0x3":
            append_array(failed, s, "Manual")
        elif clist15.get("Start") == "0x2":
            append_array(failed, s, "Automatic")
    else:
        append_array(failed, s, "Not configured")
    str = "\nSystem Services"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, System_Services_miti, str.strip(), "passed")
    export_json(failed, System_Services_miti, str.strip(), "failed")


def Group_Policy(clist16):
    passed = []
    failed = []
    s = "Turn off local group policy processing"
    if "DisableLGPOProcessing" in clist16:

        if clist16.get("DisableLGPOProcessing") == "0x1":
            append_array(passed, s, "Enabled")
        elif clist16.get("DisableLGPOProcessing") == "0x2":
            append_array(failed, s, "Disabled")
    else:
        append_array(failed, s, "Not configured")
    str = "\nGroup Policy"
    print(str)
    t = result_table(passed, failed)
    #export_result("\n" + str + "\n", t, current_time)
    export_json(passed, Group_Policy_miti, str.strip(), "passed")
    export_json(failed, Group_Policy_miti, str.strip(), "failed")


def checklist_misc(clistmisc, passed, failed, i):
    if i == 1:
        if "PasswordComplexity" in clistmisc:
            s = "Password must meet complexity requirements"
            if clistmisc.get("PasswordComplexity") == "1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        else:
            append_array(passed, "Password must meet complexity requirements", "Default/Enabled")
        if "ClearTextPassword" in clistmisc:
            s = "Store passwords using reversible encryption"
            if clistmisc.get("ClearTextPassword") == "1":
                append_array(passed, s, "Disabled")
            else:
                append_array(failed, s, "Enabled")
        else:
            append_array(passed, "Store passwords using reversible encryption", "Default/Disabled")
    elif i == 4:
        if "ForceLogoffWhenHourExpire" in clistmisc:
            s = "Network security: Force logoff when logon hours expire"
            if clistmisc.get("ForceLogoffWhenHourExpire") == "1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        else:
            append_array(passed, "Network security: Force logoff when logon hours expire", "Default/Enabled")


def checklist_17_1(passed, failed):
    data = filter_info_17(".\\logs\\result17_1.txt")
    s = "Password Configuration"
    if "True" in data.values():
        name = [k for k, v in data.items() if v == "True"]
        append_array(failed, s, "Account (" + ", ".join(name) + ")")
    else:
        append_array(passed, s, "None")


def checklist_17_2(passed, failed):
    data = filter_info_17_2(".\\logs\\result17_2.txt")
    s = "Check Unused Accounts"
    if "none" in data.values():
        name = [k for k, v in data.items() if v == "none"]
        append_array(failed, s, "Account (" + ", ".join(name) + ")")
    else:
        append_array(passed, s, "None")


def checklist_17_3(passed, failed):
    data = filter_info_17(".\\logs\\result17_3.txt")
    failed_user = {}
    s = "Check Accounts Not Changing Passwords Periodically"
    for date in data.values():
        date_object = datetime.datetime.strptime(date, "%d/%m/%Y").date()
        today = datetime.datetime.today().date()
        date_diff = today - date_object
        if date_diff.days >= 365:
            name = [k for k, v in data.items() if v == date]
            failed_user = ", ".join(name)
    if len(failed_user) != 0:
        append_array(failed, s, "Account (" + failed_user + ")")
    else:
        append_array(passed, s, "None")


def checklist_17_4(passed, failed):
    data = filter_info_17(".\\logs\\result17_4.txt")
    failed_user = {}
    s = "Check Privileged Accounts Used for Services"
    for value in data.values():
        if value != "{}":
            name = [k for k, v in data.items() if v != "{}"]
            failed_user = ", ".join(name)
    if len(failed_user) != 0:
        append_array(failed, s, "Account (" + failed_user + ")")
    else:
        append_array(passed, s, "None")


def checklist_17_5(passed, failed):
    data = filter_info_17(".\\logs\\result17_5.txt")
    s = "Change krbtgt Account Password"
    for date in data.values():
        date_object = datetime.datetime.strptime(date, "%d/%m/%Y").date()
        today = datetime.datetime.today().date()
        date_diff = today - date_object
        if date_diff.days >= 180:
            append_array(failed, s, "(" + date + ")")
        else:
            append_array(passed, s, "(" + date + ")")
    if len(data) == 0:
        append_array(failed, s, "None")


def checklist_17_6(passed, failed):
    data = filter_info_17_6(".\\logs\\result17_6.txt")
    s = "Configure NTFS Permissions for AdminSDHolder Folder"
    failed_arr = []
    try:
        domain_name = data[1].upper()
        approved_account = [r'NT AUTHORITY\Authenticated Users', r'NT AUTHORITY\SYSTEM', r'BUILTIN\Administrators',
                            rf'{domain_name}\Domain Admins', rf'{domain_name}\Enterprise Admins', 'Everyone',
                            r'NT AUTHORITY\SELF', r'BUILTIN\Pre-Windows 2000 Compatible Access',
                            r'BUILTIN\Windows Authorization Access Group', r'BUILTIN\Terminal Server License Servers',
                            rf'{domain_name}\Cert Publishers']
        for name in data[0]:
            name = name.strip()
            if name not in approved_account:
                failed_arr.append(name)
        failed_user = ", ".join(failed_arr)
        if len(failed_arr) != 0:
            append_array(failed, s, "Account (" + failed_user + ")")
        else:
            append_array(passed, s, "None")
    except:
        pass
        append_array(failed, s, "")


def AD_User_Account():
    passed = []
    failed = []
    checklist_17_1(passed, failed)
    checklist_17_2(passed, failed)
    checklist_17_3(passed, failed)
    checklist_17_4(passed, failed)
    checklist_17_5(passed, failed)
    checklist_17_6(passed, failed)
    str = "\nAD user account"
    print(str)
    t = result_table(passed, failed)
    export_json(passed, AD_user_account_miti, str.strip(), "passed")
    export_json(failed, AD_user_account_miti, str.strip(), "failed")