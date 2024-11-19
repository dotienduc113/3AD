import json
import datetime
import csv
import socket
import zipfile
import os

ck1_miti = {
    "Enforce password history": [
        "The Enforce password history policy setting determines the number of unique new passwords that must be associated with a user account before. If not defined, users can use the same password for unlimited duration, which enhances the risk of being brute-forced.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Password Policy and set Enforce password history to 24.",
        "Medium"
    ],

    "Maximum password age": [
        "The Maximum password age policy setting determines the period that a password can be used before the system requires the user to change it. Setting the age to 0 will never require a password change, posing a security risk.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Password Policy and set Maximum password age to between 30 and 90 days to ensure a balance between security and usability.",
        "Medium"
    ],

    "Minimum password age": [
        "The Minimum password age policy setting determines the period a user must wait before changing their password. A minimum age of 0 allows users to bypass password history requirements.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Password Policy and set Minimum password age to at least 1 day.",
        "Medium"
    ],

    "Minimum password length": [
        "The Minimum password length policy setting specifies the fewest number of characters a password can have. Short passwords are easier to crack.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Password Policy and set Minimum password length to at least 14 characters.",
        "Medium"
    ],

    "Password must meet complexity requirements": [
        "The Password must meet complexity requirements policy ensures that passwords contain a combination of uppercase, lowercase, digits, and symbols to increase security.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Password Policy and set this policy to Enabled.",
        "Medium"
    ],

    "Store passwords using reversible encryption": [
        "Storing passwords using reversible encryption is essentially the same as storing plain-text passwords. This is highly discouraged.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Password Policy and set Store passwords using reversible encryption to Disabled.",
        "Medium"
    ],
    "Account lockout duration": [
        "The Account lockout duration policy setting determines the number of minutes a locked-out account will remain locked out before it is automatically unlocked. A sufficiently long duration helps prevent brute force attacks by delaying repeated login attempts.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy and set Account lockout duration to at least 15 minutes.",
        "Medium"
    ],

    "Account lockout threshold": [
        "The Account lockout threshold policy setting specifies the number of failed sign-in attempts that will trigger a user account to be locked out. A lower threshold increases protection against brute force attacks.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy and set Account lockout threshold to a maximum of 5 attempts, ensuring it's greater than 0.",
        "Medium"
    ],

    "Reset account lockout counter after": [
        "The Reset account lockout counter after policy setting determines the time (in minutes) that must elapse after a failed login attempt before the counter resets to zero. A longer reset period discourages automated attacks.",
        "Navigate to Computer Configuration\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy and set Reset account lockout counter after to at least 15 minutes.",
        "Medium"
    ]

}

ck3_miti = {
    "Access this computer from the network": [
        "This policy setting determines which users or groups can connect to the computer over the network. Granting access to only authenticated users and administrators helps prevent unauthorized access.",
        "Ensure that only 'Administrators' and 'Authenticated Users' have access.",
        "Medium"
    ],

    "Deny access to this computer from the network": [
        "This policy setting prevents users or groups from connecting to the computer over the network, overriding the ability granted by 'Access this computer from the network'.",
        "Deny access to 'Guest', 'Administrators', and 'Local Account' to enhance security.",
        "Medium"
    ],

    "Deny log on as a batch job": [
        "This policy setting specifies users or groups that are denied log on as a batch job, which includes tasks such as scheduled tasks.",
        "Deny this privilege to 'Guest', 'Domain Admins', and 'Enterprise Admins' to limit unauthorized task executions.",
        "Medium"
    ],

    "Deny log on as a service": [
        "This policy setting specifies the users or groups who are not allowed to log on as a service.",
        "Deny this privilege to 'Guest', 'Domain Admins', and 'Enterprise Admins' to prevent unauthorized service configurations.",
        "Medium"
    ],

    "Deny log on through Remote Desktop Services": [
        "This policy setting prevents specific users or groups from logging on to the computer through Remote Desktop Services.",
        "Deny access to 'Guest', 'Administrators', 'Domain Admins', 'Enterprise Admins', and 'Local Account' for increased security.",
        "Medium"
    ],

    "Deny log on locally": [
        "This policy setting determines which users are prevented from logging on at the computer's console.",
        "Deny local logon to 'Guest', 'Domain Admins', and 'Enterprise Admins' to restrict physical access.",
        "Medium"
    ],

    "Allow log on locally": [
        "This policy setting specifies which users can log on at the computer's console.",
        "Allow only 'Administrators' to log on locally to limit physical access.",
        "Medium"
    ],

    "Allow log on through Remote Desktop Services": [
        "This policy setting specifies which users can log on to the computer via Remote Desktop Services.",
        "Allow only 'Administrators' for secure remote access management.",
        "Medium"
    ],

    "Shut down the system": [
        "This policy setting specifies which users can shut down the system.",
        "Restrict this privilege to 'Administrators' to prevent unauthorized system shutdowns.",
        "Medium"
    ],

    "Act as part of the operating system": [
        "This policy setting allows a process to assume the identity of any user and gain access to resources as that user. Very few, if any, services require this right.",
        "Do not assign this privilege to any users or groups (None) to prevent potential security risks.",
        "High"
    ]
}

ck4_miti = {
    "Accounts: Administrator account status": [
        "This policy setting determines whether the built-in Administrator account is enabled or disabled. Disabling this account reduces the attack surface.",
        "Set the Administrator account status to 'Disabled' to enhance security.",
        "Low"
    ],

    "Domain member: Digitally encrypt or sign secure channel data (always)": [
        "This policy setting ensures that all secure channel data is both signed and encrypted, protecting the integrity and confidentiality of communications.",
        "Set this policy to 'Enabled' to ensure secure channel data is always protected.",
        "Medium"
    ],

    "Domain member: Digitally encrypt secure channel data (when possible)": [
        "This policy setting attempts to encrypt secure channel data whenever possible, which guards against eavesdropping attacks.",
        "Enable this setting to provide additional security for secure channel data.",
        "Medium"
    ],

    "Domain member: Digitally sign secure channel data (when possible)": [
        "This setting applies a digital signature to secure channel data when possible, ensuring authenticity and integrity.",
        "Enable this setting to protect secure channel data from tampering.",
        "Medium"
    ],

    "Domain member: Disable machine account password changes": [
        "This policy setting determines whether machine account passwords are automatically changed. Frequent changes can reduce security risks.",
        "Set to 'Disabled' to allow automatic machine account password changes.",
        "Medium"
    ],

    "Domain member: Maximum machine account password age": [
        "This setting specifies the maximum age for machine account passwords, which are less secure if unchanged for long periods.",
        "Set to 30 days or fewer to ensure passwords are regularly updated.",
        "Medium"
    ],

    "Domain member: Require strong (Windows 2000 or later) session key": [
        "This policy setting ensures that a strong session key is used, enhancing the security of communications.",
        "Set to 'Enabled' to require strong session keys.",
        "Medium"
    ],

    "Interactive logon: Machine inactivity limit": [
        "This determines how many seconds of inactivity are allowed before the machine locks the screen.",
        "Set to 900 seconds or fewer to quickly lock the session after inactivity.",
        "Medium"
    ],

    "Interactive logon: Number of previous logons to cache (in case domain controller is not available)": [
        "This setting specifies how many logon attempts are cached. Excessive caching can be a security risk.",
        "Set to 4 or fewer to limit cached credentials.",
        "Low"
    ],

    "Interactive logon: Prompt user to change password before expiration": [
        "This setting determines how soon users are reminded to change their password before it expires.",
        "Configure to prompt users 5 to 14 days before password expiration.",
        "Low"
    ],

    "Microsoft network client: Digitally sign communications (always)": [
        "This setting ensures that digital signing is always used for SMB communications, enhancing security.",
        "Set to 'Enabled' to ensure messages are signed.",
        "Medium"
    ],

    "Microsoft network client: Digitally sign communications (if server agrees)": [
        "This setting negotiates SMB signing when possible, protecting against tampering.",
        "Enable this setting to sign communications if the server agrees.",
        "Medium"
    ],

    "Microsoft network client: Send unencrypted password to third-party SMB servers": [
        "Sending unencrypted passwords is a security risk. This setting should be restricted.",
        "Set to 'Disabled' to prevent unencrypted passwords from being sent.",
        "High"
    ],

    "Microsoft network server: Amount of idle time required before suspending session": [
        "This setting defines how long a session will remain idle before being suspended.",
        "Set to 15 minutes or fewer to ensure sessions are suspended during inactivity.",
        "Medium"
    ],

    "Microsoft network server: Digitally sign communications (always)": [
        "This setting requires all SMB communications to be digitally signed, protecting against forgery.",
        "Set to 'Enabled' for maximum communication security.",
        "Medium"
    ],

    "Microsoft network server: Digitally sign communications (if client agrees)": [
        "This setting allows SMB signing if the client agrees, enhancing message security when supported.",
        "Enable this for increased protection if the client supports signing.",
        "Medium"
    ],

    "Microsoft network server: Disconnect clients when logon hours expire": [
        "This setting determines whether clients are forcibly disconnected when logon hours expire.",
        "Set to 'Enabled' to disconnect clients when their logon hours expire.",
        "Low"
    ],

    "Microsoft network server: Server SPN target name validation level": [
        "This setting determines how strictly the server validates target SPN names.",
        "Set to 'Accept if provided by client or higher' to ensure proper validation.",
        "Medium"
    ],

    "Network security: Allow Local System to use computer identity for NTLM": [
        "This setting allows the Local System to authenticate as a computer account using NTLM.",
        "Set to 'Enabled' to allow this behaviour, enhancing compatibility.",
        "Medium"
    ],

    "Network security: Configure encryption types allowed for Kerberos": [
        "This policy determines the encryption types that Kerberos can use, impacting security and compatibility.",
        "Configure to support 'AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', and 'Future encryption types' for strong encryption.",
        "High"
    ],

    "Network security: Do not store LAN Manager hash value on next password change": [
        "Storing LM hash values poses a security risk and should be avoided.",
        "Set to 'Enabled' to prevent storing LAN Manager hash values.",
        "High"
    ],

    "Network security: Force logoff when logon hours expire": [
        "This setting enforces logoff when logon hours expire, preventing unauthorized access.",
        "Set to 'Enabled' to force logoff upon logon hour expiration.",
        "Medium"
    ],

    "Network security: LAN Manager authentication level": [
        "This setting determines the challenges and responses to use for network authentication, impacting security.",
        "Set to 'Send NTLMv2 response only. Refuse LM & NTLM' to enhance authentication security.",
        "High"
    ],

    "Network security: LDAP client signing requirements": [
        "This setting specifies whether LDAP client signing is negotiated or required, affecting data integrity.",
        "Set to 'Negotiate signing or higher' to ensure data integrity with LDAP communications.",
        "Medium"
    ],

    "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients": [
        "This setting determines the minimum security level for NTLM SSP sessions on clients.",
        "Configure to 'Require NTLMv2 session security and Require 128-bit encryption' for strong security.",
        "Medium"
    ],

    "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers": [
        "This setting determines the minimum session security level for NTLM SSP sessions on servers.",
        "Configure to 'Require NTLMv2 session security and Require 128-bit encryption' for strong security.",
        "Medium"
    ]
}

ck5_miti = {
    "Domain Firewall state": [
        "The firewall state setting determines whether the Windows firewall is enabled or disabled. A properly configured firewall is essential for protecting the system from unauthorized access.",
        "Set the firewall state to 'On' to ensure the system is protected by the firewall.",
        "Medium"
    ],
    "Private Firewall state": [
        "The firewall state setting determines whether the Windows firewall is enabled or disabled. A properly configured firewall is essential for protecting the system from unauthorized access.",
        "Set the firewall state to 'On' to ensure the system is protected by the firewall.",
        "Medium"
    ],
    "Public Firewall state": [
        "The firewall state setting determines whether the Windows firewall is enabled or disabled. A properly configured firewall is essential for protecting the system from unauthorized access.",
        "Set the firewall state to 'On' to ensure the system is protected by the firewall.",
        "Medium"
    ],
    "Domain Inbound connections": [
        "This setting determines what happens to inbound connections that do not match an allowed rule. Blocking inbound connections by default protects the system from unsolicited and potentially harmful incoming traffic.",
        "Set inbound connections to 'Block (Default)' to prevent unauthorized access.",
        "Medium"
    ],
    "Private Inbound connections": [
        "This setting determines what happens to inbound connections that do not match an allowed rule. Blocking inbound connections by default protects the system from unsolicited and potentially harmful incoming traffic.",
        "Set inbound connections to 'Block (Default)' to prevent unauthorized access.",
        "Medium"
    ],
    "Public Inbound connections": [
        "This setting determines what happens to inbound connections that do not match an allowed rule. Blocking inbound connections by default protects the system from unsolicited and potentially harmful incoming traffic.",
        "Set inbound connections to 'Block (Default)' to prevent unauthorized access.",
        "Medium"
    ],
    "Domain Log file maximum size (KB)": [
        "This setting specifies the maximum size of the firewall log file. A larger log file can capture more data, which is helpful for monitoring and auditing purposes.",
        "Set the log file maximum size to 16,384 KB or greater to ensure sufficient logging capacity.",
        "Medium"
    ],
    "Private Log file maximum size (KB)": [
        "This setting specifies the maximum size of the firewall log file. A larger log file can capture more data, which is helpful for monitoring and auditing purposes.",
        "Set the log file maximum size to 16,384 KB or greater to ensure sufficient logging capacity.",
        "Medium"
    ],
    "Public Log file maximum size (KB)": [
        "This setting specifies the maximum size of the firewall log file. A larger log file can capture more data, which is helpful for monitoring and auditing purposes.",
        "Set the log file maximum size to 16,384 KB or greater to ensure sufficient logging capacity.",
        "Medium"
    ],
    "Domain Log dropped packets": [
        "Logging dropped packets allows administrators to monitor and analyze unsuccessful connection attempts, which can provide insights into potential security threats.",
        "Set to 'Yes' to enable logging of all dropped packets.",
        "Medium"
    ],
    "Private Log dropped packets": [
        "Logging dropped packets allows administrators to monitor and analyze unsuccessful connection attempts, which can provide insights into potential security threats.",
        "Set to 'Yes' to enable logging of all dropped packets.",
        "Medium"
    ],
    "Public Log dropped packets": [
        "Logging dropped packets allows administrators to monitor and analyze unsuccessful connection attempts, which can provide insights into potential security threats.",
        "Set to 'Yes' to enable logging of all dropped packets.",
        "Medium"
    ],
    "Domain Log successful connections": [
        "Logging successful connections helps in tracking allowed traffic, providing an audit trail for security monitoring.",
        "Set to 'Yes' to enable logging of all successful connections.",
        "Medium"
    ],
    "Private Log successful connections": [
        "Logging successful connections helps in tracking allowed traffic, providing an audit trail for security monitoring.",
        "Set to 'Yes' to enable logging of all successful connections.",
        "Medium"
    ],
    "Public Log successful connections": [
        "Logging successful connections helps in tracking allowed traffic, providing an audit trail for security monitoring.",
        "Set to 'Yes' to enable logging of all successful connections.",
        "Medium"
    ]
}


ck6_miti = {
    "Audit account logon event": [
        "This setting audits each instance of a user's account logon or logoff event on a domain controller. This helps in tracking account usage.",
        "Enable both 'Success' and 'Failure' auditing to ensure comprehensive monitoring of account logon events.",
        "Medium"
    ],

    "Audit account management": [
        "This audits changes to user accounts and groups, including the creation, modification, or deletion. Monitoring these events is crucial for security and compliance.",
        "Enable 'Success and Failure' auditing to track all account management activities.",
        "Medium"
    ],

    "Audit process tracking": [
        "This setting audits detailed tracking information for events such as a program activation, process exit, handle duplication, and indirect object access.",
        "Enable 'Success' auditing to monitor and analyze process-related activities.",
        "Medium"
    ],

    "Audit Directory Service Access": [
        "This audits user access to an Active Directory object that has its own system access control list (SACL) specified. It's important for monitoring attempts to access directory services.",
        "Enable both 'Success' and 'Failure' auditing to keep track of access to directory services.",
        "Medium"
    ],

    "Audit logon events": [
        "This setting audits each instance of user logon or logoff, which helps in tracking who logged on to the system.",
        "Enable both 'Success' and 'Failure' auditing to capture a full spectrum of logon activity.",
        "Medium"
    ],

    "Audit Policy Change": [
        "This setting audits changes to user rights, audit policies, and trust policies, which are critical for maintaining security configurations.",
        "Enable 'Success' auditing to track modifications to important security policies.",
        "Medium"
    ],

    "Audit Privilege Use": [
        "This audits each instance of a user exercising a user right. Monitoring privileged use is crucial for preventing unauthorized actions.",
        "Enable both 'Success' and 'Failure' auditing to monitor the usage of privileges.",
        "Medium"
    ]
}

ck7_miti = {
    "Configure SMB v1 client driver": [
        "SMB v1 is outdated and susceptible to critical vulnerabilities, such as WannaCry attacks. Disable SMB v1 to mitigate these risks.",
        "High"
    ],
    "Configure SMB v1 server": [
        "Enabling SMB v1 on servers increases the risk of significant security breaches. Disable to prevent exploitation vulnerabilities.",
        "High"
    ],
    "WDigest Authentication": [
        "WDigest stores credentials insecurely, making them vulnerable to theft. Disable to enhance security and prevent plain-text credential storage.",
        "Medium"
    ]
}

ck8_miti = {
    "Hardened UNC Paths - SYSVOL": [
        "Without hardened UNC paths, unauthorized access to critical network shares can occur. Apply restrictions to trusted paths only.",
        "Medium"

    ],
    "Hardened UNC Paths - NETLOGON": [
        "Without hardened UNC paths, unauthorized access to critical network shares can occur. Apply restrictions to trusted paths only.",
        "Medium"
    ]
}

ck9_miti = {
    "Encryption Oracle Remediation": [
        "Without proper remediation, encryption handling vulnerabilities can be exploited. Enforce updated security configurations to avoid such attacks.",
        "High"
    ]
}

ck10_miti = {
    "Turn off Windows Defender": [
        "Disabling Defender without an alternative leaves systems vulnerable. Keep Defender enabled unless there is a credible antivirus substitute.",
        "Medium"
    ],
    "Turn off real-time protection": [
        "Real-time protection is essential for immediate threat mitigation. Ensure it is always enabled to prevent delayed detection.",
        "Medium"
    ],
    "Turn on behavior monitoring": [
        "Behavior monitoring identifies and responds to suspicious activities. Enable to effectively track potential threats.",
        "Medium"
    ],
    "Scan all downloaded files and attachments": [
        "Unchecked downloads and files can introduce malware. Ensure scans are performed to filter threats.",
        "Medium"
    ],
    "Turn on process scanning whenever real-time protection is enabled": [
        "Process scanning alongside real-time protection detects malicious processes. Enable this for comprehensive security.",
        "Medium"
    ],
    "Monitor file and program activity on your computer": [
        "Without monitoring, harmful activities may go unnoticed. Enable for enhanced security visibility.",
        "Medium"
    ],
    "Scan archive files": [
        "Archives can conceal malicious files. Ensure that these are included in scanning routines.",
        "Medium"
    ],
    "Scan packed executables": [
        "Packed executables can hide malware. Enable scanning to detect disguised threats.",
        "Medium"
    ],
    "Scan removable drives": [
        "Unscanned drives can spread malware. Ensure all removable media is scanned upon access.",
        "Medium"
    ]
}

ck11_miti = {
    "Restrict Remote Desktop Services users to a single Remote Desktop Services session": [
        "Allowing multiple sessions can strain resources and pose security risks. Limit users to one session to minimize exposure.",
        "Medium"
    ],
    "Do not allow Clipboard redirection": [
        "Clipboard redirection may result in data leakage. Disable to prevent unauthorized data transfer during remote sessions.",
        "Medium"
    ],
    "Do not allow drive redirection": [
        "Drive redirection can lead to unintended data exposure. Disable to secure RDP session data.",
        "Medium"
    ],
    "Set client connection encryption level": [
        "Weak encryption can be intercepted. Use strong encryption levels to secure client communications.",
        "Medium"
    ],
    "Always prompt for password upon connection": [
        "Skipping prompts might lead to unauthorized access. Require passwords for authentication on each connection.",
        "Medium"
    ],
    "Require secure RPC communication": [
        "Unsecured RPC can be vulnerable to interception or alteration. Require secure RPC to maintain data integrity.",
        "Medium"
    ],
    "Require use of specific security layer for remote (RDP) connections": [
        "Undefined security layers can expose vulnerabilities. Enforce specific layers like SSL/TLS.",
        "Medium"
    ],
    "Require user authentication for remote connections by using Network Level Authentication": [
        "Connections without NLA weaken security. Implement NLA for authentication before session establishment.",
        "Medium"
    ],
    "Set time limit for disconnected sessions": [
        "Unlimited disconnected sessions consume resources and can expose security risks. Set reasonable time limits (e.g., 15 minutes).",
        "Medium"
    ],
    "Set time limit for active but idle Remote Desktop Services sessions": [
        "Idle sessions hold resources and may expose risks. Set reasonable limits for session idle time (e.g., 15 minutes).",
        "Medium"
    ],
    "Do not delete temp folders upon exit": [
        "Retained temp data can lead to unauthorized data access. Ensure temp data is deleted unless necessary.",
        "Medium"
    ],
    "Do not use temporary folders per session": [
        "Using shared temp folders can risk data leaks. Utilize separate folders per session to isolate data.",
        "Medium"
    ]
}

ck12_miti = {
    "Turn on PowerShell Script Block Logging": [
        "Without script block logging, potential threats may not be identified. Enable for security auditing and threat analysis.",
        "Medium"
    ],
    "Turn on PowerShell Transcription": [
        "Without transcription, command activities remain unchecked. Enable to capture command outputs for detailed analysis.",
        "High"
    ],
    "Turn on Script Execution": [
        "Unrestricted execution can lead to security vulnerabilities. Restrict to signed scripts to ensure credibility.",
        "Medium"
    ]
}

ck13_miti = {
    "Allow Basic authentication": [
        "Basic authentication is insecure as it exposes credentials. Disable or ensure secure practices are used.",
        "High"
    ],
    "Allow unencrypted traffic": [
        "Unencrypted traffic is vulnerable to interception. Disable to protect data integrity and confidentiality.",
        "High"
    ],
    "Disallow Digest authentication": [
        "Digest authentication may not sufficiently secure credentials. Disable to prevent potential vulnerabilities.",
        "High"
    ],
    "Disallow WinRM from storing RunAs credentials": [
        "Storing credentials can result in unauthorized access. Prevent storage to enhance security.",
        "Medium"
    ],
    "Allow remote server management through WinRM": [
        "Improper configurations may lead to unauthorized access. Enable securely with authentication controls.",
        "Medium"
    ]
}

ck14_miti = {
    "Allow Remote Shell Access": [
        "Unrestricted remote shell access can lead to unauthorized control and exploitation. Restrict access with strict controls.",
        "Medium"
    ]
}

ck15_miti = {
    "Print Spooler (Spooler)": [
        "An enabled spooler is at risk for exploits, such as remote code execution. Monitor and restrict spooler usage.",
        "Medium"
    ]
}

ck16_miti = {
    "Turn off local group policy processing": [
        "Local policy processing can lead to inconsistent security settings. Keep central domain policy control to maintain uniform security standards.",
        "Medium"
    ]
}


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


result = []
current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
timestamp = datetime.datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')
json_name = f"3AD_result.json"
# csv_table_name = f"3AD_result_{current_time}.csv"
# csv_line_name = f"3AD_line_{current_time}.csv"
# zip_file_name = f"3AD_{current_time}.zip"
ip_address = get_ip()


def file_name(csv_table_name=None):
    if csv_table_name is not None and csv_table_name != "":
        return f"{csv_table_name}.csv"
    else:
        return f"3AD_result.csv"


def export_json(arr, ck_mitigation, checklist_name, status):
    for i in arr:
        for v in ck_mitigation.keys():
            if v in i:
                mitigation = ck_mitigation.get(v)
                result.append(
                    {"timestamp": timestamp,
                     "ip_address": ip_address,
                     "name": i,
                     "checklist_name": checklist_name,
                     "status": status,
                     "Reference": mitigation[0],
                     "Best practices": mitigation[1],
                     "Severity": mitigation[2]})
    with open(f".\\results\\{json_name}", 'w') as f:
        json.dump(result, f, indent=4)


def export_csv_table(csv_table_name=None):
    if csv_table_name is not None and csv_table_name != "":
        csv_table_name = f"{csv_table_name}.csv"
    else:
        csv_table_name = f"3AD_result.csv"
    with open(f'.\\results\\{json_name}', 'r') as f:
        data = json.load(f)
    fieldnames = ['timestamp', 'ip_address', 'name', 'checklist_name', 'status', 'Reference', 'Best practices', 'Severity']
    file_exists = os.path.isfile(f".\\results\\{csv_table_name}")
    with open(f".\\results\\{csv_table_name}", 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists or os.path.getsize(f".\\results\\{csv_table_name}") == 0:
            writer.writeheader()
        for row in data:
            writer.writerow(row)


def delete_json():
    file_path = f".\\results\\{json_name}"
    if os.path.exists(file_path):
        os.remove(file_path)


'''
def export_csv_line():
    with open(f'.\\results\\{json_name}', 'r') as f:
        data = json.load(f)
    fieldnames = ['timestamp', 'severity', 'count']
    low = 0
    medium = 0
    high = 0
    with open(f".\\results\\{csv_line_name}", 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            if row['status'] == "failed":
                if row['severity'] == "High":
                    high += 1
                elif row['severity'] == "Medium":
                    medium += 1
                elif row['severity'] == "Low":
                    low += 1
        writer.writerow({'timestamp': data[0]['timestamp'], 'severity': "high", 'count': high})
        writer.writerow({'timestamp': data[0]['timestamp'], 'severity': "medium", 'count': medium})
        writer.writerow({'timestamp': data[0]['timestamp'], 'severity': "low", 'count': low})


def export_zip_files():
    # Create a zip file
    with zipfile.ZipFile(f".\\results\\{zip_file_name}", 'w') as zip_file:
        # Add files to the zip file
        for file_name in [f".\\results\\{json_name}", f".\\results\\{csv_table_name}",
                          f".\\results\\{csv_line_name}"]:
            zip_file.write(file_name, arcname=os.path.basename(file_name))

    # Remove the original files
    for file_name in [f".\\results\\{json_name}", f".\\results\\{csv_table_name}",
                      f".\\results\\{csv_line_name}"]:
        os.remove(file_name)
'''
