from func.filter import filter_info_secpol
from textwrap import fill
from tabulate import tabulate
from itertools import zip_longest
import datetime
from func.filter import filter_info_1, filter_info_secpol, filter_info_4, filer_info_5, filter_info_6, filter_info_7, \
    filter_info_8, filter_info_9, filer_info_registry, filter_info_13
import json
from func.export import ck1_miti, ck3_miti, ck4_miti, export_json,  export_csv_table, export_csv_line, export_zip_files


def compare_checklist():
    current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
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

    checklist_1(clist1, current_time)
    checklist_3(clist3, current_time)
    checklist_4(clist4, current_time)
    #checklist_5(clist5, current_time)
    #checklist_6(clist6, current_time)
    #checklist_7(clist7, current_time)
    #checklist_8(clist8, current_time)
    #checklist_9(clist9, current_time)
    #checklist_10(clist10, current_time)
    #checklist_11(clist11, current_time)
    #checklist_12(clist12, current_time)
    #checklist_13(clist13, current_time)
    #checklist_14(clist14, current_time)
    #checklist_15(clist15, current_time)
    #checklist_16(clist16, current_time)

    export_csv_table()
    export_csv_line()
    #export_zip_files()


def result_table(passed, failed, width=100):
    # Wrap text in each column to the specified width
    passed_wrapped = [fill(item, width=width) if item else '' for item in passed]
    failed_wrapped = [fill(item, width=width) if item else '' for item in failed]

    # Create the table with two columns
    table = [[p, f] for p, f in zip_longest(passed_wrapped, failed_wrapped, fillvalue='')]

    # Print the table
    print(tabulate(table, headers=["Passed", "Failed"], tablefmt="grid"))

    return tabulate(table, headers=["Passed", "Failed"], tablefmt="grid")


def export_result(str, table, current_time):
    f_name = f"3AD_{current_time}.txt"
    with open(f".\\results\\{f_name}", "a+") as f:
        f.write(str)
        f.write(table)


def append_array(array, key, value):
    array.append(key + ": " + value)
    return


'''
def export_json(passed, timestamp, checklist_name):
    result = []
    for i in passed:
        result.append({"name": i, "timestamp": timestamp, "checklist_name": checklist_name, "detail": "detail"})
    with open('result.json', 'w') as f:
        json.dump(result, f, indent=4)
'''


def checklist_1(clist1, current_time):  # checklist 1 va 2 lay du lieu va so sanh
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
    str = "\n1-2. Password Policy and Account Lockout Policy result"
    print(str)
    t = result_table(passed, failed)
    export_json(passed, ck1_miti, str.strip(), "passed")
    export_json(failed, ck1_miti, str.strip(), "failed")
    #export_result(str.strip() + "\n", t, current_time)


def checklist_3(clist3, current_time):
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

    str = "\n3. User Rights Assignment"
    print(str)
    t = result_table(passed, failed)
    #export_json(passed, ck3_miti, str.strip(), "passed")
    #export_json(failed, ck3_miti, str.strip(), "failed")
    #export_result("\n" + str + "\n", t, current_time)


def checklist_4(clist4, current_time):
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
    str = "\n4. Security Options"
    print(str)
    t = result_table(passed, failed)
    #export_json(passed, ck4_miti, str.strip(), "passed")
    #export_json(failed, ck4_miti, str.strip(), "failed")
    #export_result("\n" + str + "\n", t, current_time)


def checklist_5(clist5, current_time):  # checklist 5 lay du lieu va so sanh
    passed = []
    failed = []
    for profile, settings in clist5.items():
        for obj, value in settings:
            if obj == "State" and value == "ON":
                append_array(passed, f"{profile[:-18]} {obj}", value)
            elif obj == "Firewall Policy" and "BlockInbound" in value:
                append_array(passed, f"{profile[:-18]} {obj}", value)
            elif obj == "LogAllowedConnections" and value == "Enable":
                append_array(passed, f"{profile[:-18]} {obj}", value)
            elif obj == "LogDroppedConnections" and value == "Enable":
                append_array(passed, f"{profile[:-18]} {obj}", value)
            elif obj == "MaxFileSize" and int(value) >= 16384:
                append_array(passed, f"{profile[:-18]} {obj}", value)
            else:
                append_array(failed, f"{profile[:-18]} {obj}", value)
    str = "\n5. Windows Defender Firewall with Advanced Security result:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_6(clist6, current_time):
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

    str = "\n6. Audit Policy:"
    print(str)
    t = result_table(passed, failed)
    if len(clist6) == 0:
        print("NOTE: Please run as administrator to get full results")
        export_result("\n" + str + "\n" + "NOTE: Please run as administrator to get full results\n", t, current_time)
    else:
        export_result("\n" + str + "\n", t, current_time)


def checklist_7(clist7, current_time):
    passed = []
    failed = []
    if "EnableSMB1Protocol" in clist7:
        s = "Configure SMB v1 server"
        if clist7.get("EnableSMB1Protocol") == "False":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Configure SMB v1 server", "Not configure/Enable")
    if "Start REG_DWORD" in clist7:
        s = "Configure SMB v1 server"
        if clist7.get("Start REG_DWORD") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "Configure SMB v1 server", "Not configure/Enable")
    if "UseLogonCredential REG_DWORD" in clist7:
        s = "WDigest Authentication"
        if clist7.get("UseLogonCredential REG_DWORD") == "0x0":
            append_array(passed, s, "Disabled")
        else:
            append_array(failed, s, "Enabled")
    else:
        append_array(failed, "WDigest Authentication", "Not configure/Enable")
    str = "\n7. MS Security Guide:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_8(clist8, current_time):
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
    str = "\n8. Network Provider:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_9(clist9, current_time):
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
    str = "\n9. Credentials Delegation:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_10(clist10, current_time):
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
    str = "\n10. Windows Defender:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_11(clist11, current_time):
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
    str = "\n11. Remote Desktop Services:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_12(clist12, current_time):
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
    str = "\n12. Windows PowerShell:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_13(clist13, current_time):
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
    str = "\n13. WinRM:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_14(clist14, current_time):
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
    str = "\n14. Windows Remote Shell:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_15(clist15, current_time):
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
    str = "\n15. System Services:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_16(clist16, current_time):
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
    str = "\n16. Group Policy:"
    print(str)
    t = result_table(passed, failed)
    export_result("\n" + str + "\n", t, current_time)


def checklist_misc(clistmisc, passed, failed, i):
    if i == 1:
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
    elif i == 4:
        if "ForceLogoffWhenHourExpire" in clistmisc:
            s = "Network security: Force logoff when logon hours expire"
            if clistmisc.get("ForceLogoffWhenHourExpire") == "1":
                append_array(passed, s, "Enabled")
            else:
                append_array(failed, s, "Disabled")
        else:
            append_array(passed, "Network security: Force logoff when logon hours expire", "Default/Enabled")
