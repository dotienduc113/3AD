import json
import datetime
import csv
import socket
import zipfile
import os

ck1_miti = {
    "Enforce password history": [
        "Previously compromised passwords might be used to gain access. Password reuse must be different than the last 24 passwords",
        "Medium"
    ],
    "Maximum password age": [
        "Without regular password changes, passwords can be exposed for a longer period. Maximum password age from 30 - 90 days",
        "Medium"
    ],
    "Minimum password age": [
        "Too short password age might let users bypass password history requirements. Minimum password age is 1 day",
        "Medium"
    ],
    "Minimum password length": [
        "Short passwords are vulnerable to password attacks. Minimum password length is 14 characters",
        "Medium"
    ],
    "Password must meet complexity requirements": [
        "Simple passwords are vulnerable to brute-force attacks. Password must include a mix of upper and lower case letters, numbers, and special characters.",
        "Medium"
    ],
    "Store passwords using reversible encryption": [
        "Reversible encryption is not recommended since passwords will be easily decrypted. Set to Disabled",
        "Medium"
    ],
    "Account lockout duration": [
        "Short durations can allow repeated brute-force attempts. Set to at least 15 minutes",
        "Medium"
    ],
    "Account lockout threshold": [
        "High thresholds can enable multiple guessing attempts before lockout. Set to 5 failed attempts",
        "Medium"
    ],
    "Reset account lockout counter after": [
        "Long reset time can delay detection of brute-force attacks. Set to at least 15 minutes",
        "Medium"
    ]
}

ck3_miti = {
    "Access this computer from the network": [
        "Allow only Administrators and Authenticated Users to secure network access while maintaining necessary connectivity.",
        "Medium"
    ],
    "Deny access to this computer from the network": [
        "Deny Guest, Administrators, and Local Account to prevent unauthorized access and ensure security protocols are upheld.",
        "Medium"
    ],
    "Deny log on as a batch job": [
        "Deny Guest, Domain Admins, and Enterprise Admins to prevent unauthorized task execution and protect critical processes.",
        "Medium"
    ],
    "Deny log on as a service": [
        "Deny Guest, Domain Admins, and Enterprise Admins to restrict service use and prevent misuse by unauthorized accounts.",
        "Medium"
    ],
    "Deny log on through Remote Desktop Services": [
        "Deny Guest, Administrators, Domain Admins, Enterprise Admins, and Local Account to secure Remote Desktop Services and prevent unauthorized access.",
        "Medium"
    ],
    "Deny log on locally": [
        "Deny Guest, Domain Admins, and Enterprise Admins to secure local access, ensuring only legitimate users have access.",
        "Medium"
    ],
    "Allow log on locally": [
        "Allow only Administrators to provide controlled local access and ensure administrative oversight.",
        "Medium"
    ],
    "Allow log on through Remote Desktop Services": [
        "Allow only Administrator to maintain secure remote administration capabilities while minimizing risks.",
        "Medium"
    ],
    "Shut down the system": [
        "Allow only Administrators to prevent unauthorized system shutdowns and ensure operational integrity.",
        "Medium"
    ],
    "Act as part of the operating system": [
        "Allow none to prevent unauthorized privilege escalation, ensuring system security and integrity.",
        "High"
    ]
}

ck4_miti = {
    "Accounts: Administrator account status": [
        "Ensure the default admin account is renamed and disabled to prevent unauthorized access. The recommended state for this setting is: Disabled.",
        "Low"
    ],
    "Domain member: Digitally encrypt or sign secure channel data (always)": [
        "Require encryption or signing of all secure channel data to ensure integrity and confidentiality. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Domain member: Digitally encrypt secure channel data (when possible)": [
        "Encrypt secure channel data whenever possible to prevent interception. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Domain member: Digitally sign secure channel data (when possible)": [
        "Sign channel data for authenticity where possible. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Domain member: Disable machine account password changes": [
        "Do not disable; regular password changes should be enabled for security. The recommended state for this setting is: Disabled.",
        "Medium"
    ],
    "Domain member: Maximum machine account password age": [
        "Set to a maximum of 30 days to facilitate timely password updates. The recommended state for this setting is: 30 days.",
        "Medium"
    ],
    "Domain member: Require strong (Windows 2000 or later) session key": [
        "Ensure use of strong session keys to protect data transmission. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Interactive logon: Machine inactivity limit": [
        "Set a time limit for inactive machines to automatically lock. The recommended state for this setting is: 15 minutes.",
        "Medium"
    ],
    "Interactive logon: Number of previous logons to cache": [
        "Limit cached logons to the required minimum to reduce risk. The recommended state for this setting is: 2 logons.",
        "Low"
    ],
    "Interactive logon: Prompt user to change password before expiration": [
        "Prompt 14 days before expiration to ensure uninterrupted access. The recommended state for this setting is: 5-14 days.",
        "Low"
    ],
    "Microsoft network client: Digitally sign communications (always)": [
        "Require digital signing of all client communications for security. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Microsoft network client: Digitally sign communications (if server agrees)": [
        "Sign communications if mutually agreed to enhance security. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Microsoft network client: Send unencrypted password to third-party SMB servers": [
        "Disable to avoid exposure of passwords. The recommended state for this setting is: Disabled.",
        "High"
    ],
    "Microsoft network server: Amount of idle time required before suspending session": [
        "Suspend sessions after a reasonable idle period (e.g., 15 minutes). The recommended state for this setting is: 15 minutes.",
        "Medium"
    ],
    "Microsoft network server: Digitally sign communications (always)": [
        "Always sign server communications to prevent tampering. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Microsoft network server: Digitally sign communications (if client agrees)": [
        "Sign communications if mutually agreed to protect integrity. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Microsoft network server: Disconnect clients when logon hours expire": [
        "Automatically disconnect clients past their logon hours to enforce policy. The recommended state for this setting is: Enabled.",
        "Low"
    ],
    "Microsoft network server: Server SPN target name validation level": [
        "Require strict SPN validation to prevent spoofing. The recommended state for this setting is: Accept if provided by client.",
        "Medium"
    ],
    "Network security: Allow Local System to use computer identity for NTLM": [
        "Restrict use of computer identity to prevent improper authorization. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Network security: Configure encryption types allowed for Kerberos": [
        "Allow only strong encryption types like AES for Kerberos. The recommended state for this setting is: AES128_HMAC_SHA1 AES256_HMAC_SHA1 Future encryption types.",
        "High"
    ],
    "Network security: Do not store LAN Manager hash value on next password change": [
        "Disable LM hash storage to protect against easy cracking. The recommended state for this setting is: Enabled.",
        "High"
    ],
    "Network security: Force logoff when logon hours expire": [
        "Enable force logoff to maintain access restrictions. The recommended state for this setting is: Enabled.",
        "Medium"
    ],
    "Network security: LAN Manager authentication level": [
        "Set to NTLMv2 only to avoid weak authentication methods. The recommended state for this setting is: Send NTLMv2 response only. Refuse LM & NTLM.",
        "High"
    ],
    "Network security: LDAP client signing requirements": [
        "Require signing to ensure LDAP transaction integrity and security. The recommended state for this setting is: Negotiating.",
        "Medium"
    ],
    "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients": [
        "Set robust security policies for client sessions to safeguard data. The recommended state for this setting is: Require NTLMv2 session security and Require 128-bit encryption.",
        "Medium"
    ],
    "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers": [
        "Implement strict security measures for server sessions to protect data. The recommended state for this setting is: Require NTLMv2 session security and Require 128-bit encryption.",
        "Medium"
    ]
}

ck5_miti = {
    "Domain Firewall State": [
        "An inactive firewall exposes the system to malicious attacks and unauthorized access. Always enable the firewall to block inbound threats and monitor network traffic. ",
        "Medium"
    ],
    "Private Firewall State": [
        "An inactive firewall exposes the system to malicious attacks and unauthorized access. Always enable the firewall to block inbound threats and monitor network traffic. ",
        "Medium"
    ],
    "Public Firewall State": [
        "An inactive firewall exposes the system to malicious attacks and unauthorized access. Always enable the firewall to block inbound threats and monitor network traffic. ",
        "Medium"
    ],
    "Domain Inbound connections": [
        "Allowing all inbound connections can lead to network breaches and exploitation. Default to blocking inbound connections and create specific rules for necessary exceptions.",
        "Medium"
    ],
    "Private Inbound connections": [
        "Allowing all inbound connections can lead to network breaches and exploitation. Default to blocking inbound connections and create specific rules for necessary exceptions.",
        "Medium"
    ],
    "Public Inbound connections": [
        "Allowing all inbound connections can lead to network breaches and exploitation. Default to blocking inbound connections and create specific rules for necessary exceptions.",
        "Medium"
    ],
    "Domain Log file maximum size (KB)": [
        "Insufficient log size may lead to loss of critical logging data during peak activities. Configure a reasonable log size and implement log rotation to store all necessary data.",
        "Medium"
    ],
    "Private Log file maximum size (KB)": [
        "Insufficient log size may lead to loss of critical logging data during peak activities. Configure a reasonable log size and implement log rotation to store all necessary data.",
        "Medium"
    ],
    "Public Log file maximum size (KB)": [
        "Insufficient log size may lead to loss of critical logging data during peak activities. Configure a reasonable log size and implement log rotation to store all necessary data.",
        "Medium"
    ],
    "Domain Log dropped packets": [
        "Without logging dropped packets, suspicious activities may go unnoticed. Enable dropped packet logging to review and analyze potential threats regularly.",
        "Medium"
    ],
    "Private Log dropped packets": [
        "Without logging dropped packets, suspicious activities may go unnoticed. Enable dropped packet logging to review and analyze potential threats regularly.",
        "Medium"
    ],
    "Public Log dropped packets": [
        "Without logging dropped packets, suspicious activities may go unnoticed. Enable dropped packet logging to review and analyze potential threats regularly.",
        "Medium"
    ],
    "Domain Log successful connections": [
        "Failing to log successful connections may prevent detecting unauthorized access. Enable logging for successful connections to monitor and audit network access.",
        "Medium"
    ],
    "Private Log successful connections": [
        "Failing to log successful connections may prevent detecting unauthorized access. Enable logging for successful connections to monitor and audit network access.",
        "Medium"
    ],
    "Public Log successful connections": [
        "Failing to log successful connections may prevent detecting unauthorized access. Enable logging for successful connections to monitor and audit network access.",
        "Medium"
    ]
}

ck6_miti = {
    "Audit account logon event": [
        "Audit for both Success and Failure to ensure detection of all account logon attempts, whether successful or failed.",
        "Medium"
    ],
    "Audit account management": [
        "Audit for Success and Failure to capture all account management activities, enhancing visibility into changes made to user accounts.",
        "Medium"
    ],
    "Audit process tracking": [
        "Audit for Success Only to track all process creation and termination, providing insights into application usage and potential issues.",
        "Medium"
    ],
    "Audit Directory Service Access": [
        "Audit for both Success and Failure to monitor access attempts to directory services, detecting potential unauthorized access.",
        "Medium"
    ],
    "Audit logon events": [
        "Audit for both Success and Failure to capture all logon attempts, aiding in the identification of unauthorized access attempts.",
        "Medium"
    ],
    "Audit Policy Change": [
        "Audit for Success Only to track successful changes to security policies, ensuring accountability for policy modifications.",
        "Medium"
    ],
    "Audit Privilege Use": [
        "Audit for both Success and Failure to monitor all attempts to use privileges, identifying potential misuse of elevated permissions.",
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
                     "mitigation": mitigation[0], "severity": mitigation[1]})
    with open(f".\\results\\{json_name}", 'w') as f:
        json.dump(result, f, indent=4)


def export_csv_table(csv_table_name=None):
    if csv_table_name is not None and csv_table_name != "":
        csv_table_name = f"{csv_table_name}.csv"
    else:
        csv_table_name = f"3AD_result.csv"
    with open(f'.\\results\\{json_name}', 'r') as f:
        data = json.load(f)
    fieldnames = ['timestamp', 'ip_address', 'name', 'checklist_name', 'status', 'mitigation', 'severity']
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
