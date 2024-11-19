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
        "The configuration of the SMB v1 client driver is important for mitigating vulnerabilities associated with the outdated SMB v1 protocol. Disabling the SMB v1 client driver reduces the attack surface posed by less secure protocols.",
        "Set to 'Enabled: Disable driver' to prevent the use of SMB v1.",
        "High"
    ],

    "Configure SMB v1 server": [
        "The configuration of the SMB v1 server is critical for ensuring the security of file sharing services. Disabling the SMB v1 server prevents the system from acting as an SMB v1 server, which safeguards it against known vulnerabilities.",
        "Set to 'Disabled' to ensure the SMB v1 server is not operational.",
        "Medium"
    ],

    "WDigest Authentication": [
        "WDigest Authentication, when enabled, stores user credentials in memory in a less secure manner. Disabling WDigest prevents this and enhances credential protection.",
        "Set to 'Disabled' to protect credentials from being stored in memory insecurely.",
        "Medium"
    ]
}


ck8_miti = {
    "Hardened UNC Paths - SYSVOL": [
        "This security setting configures the hardening of UNC paths, specifically for NETLOGON and SYSVOL, to strengthen security through additional authentication and integrity checks.",
        "Require Mutual Authentication and Require Integrity for UNC paths to ensure secure communication and prevent unauthorized access. Configure two parameters: RequireMutualAuthentication=1, RequireIntegrity=1 for the UNC paths '\\\\*\\SYSVOL' and '\\\\*\\NETLOGON'.",
        "Medium"
    ]
}


ck8_miti = {
    "Hardened UNC Paths - SYSVOL": [
        "This security setting configures the hardening of UNC paths, specifically for NETLOGON and SYSVOL, to strengthen security through additional authentication and integrity checks.",
        "Require Mutual Authentication and Require Integrity for UNC paths to ensure secure communication and prevent unauthorized access. Configure two parameters: RequireMutualAuthentication=1, RequireIntegrity=1 for the UNC paths '\\\\*\\SYSVOL' and '\\\\*\\NETLOGON'.",
        "Medium"
    ],
    "Hardened UNC Paths - NETLOGON": [
        "This security setting configures the hardening of UNC paths, specifically for NETLOGON and SYSVOL, to strengthen security through additional authentication and integrity checks.",
        "Require Mutual Authentication and Require Integrity for UNC paths to ensure secure communication and prevent unauthorized access. Configure two parameters: RequireMutualAuthentication=1, RequireIntegrity=1 for the UNC paths '\\\\*\\SYSVOL' and '\\\\*\\NETLOGON'.",
        "Medium"
    ],
}

ck9_miti = {
	"Encryption Oracle Remediation": [
    	"The Encryption Oracle Remediation policy setting rectifies potential vulnerabilities within the Credential Security Support Provider (CredSSP) protocol, which could be exploited in man-in-the-middle attacks. This setting is crucial for ensuring secure communications between client and server.",
    	"Navigate to Computer Configuration\\Administrative Templates\\System\\Credentials Delegation and set Encryption Oracle Remediation to 'Enabled: Force Updated Clients'. This configuration mandates that only clients with up-to-date security updates are able to establish connections, thus reducing the risk of exploitation through outdated encryption methods.",
    	"High"
	]
}

ck10_miti = {
    "Turn off Windows Defender": [
        "Windows Defender provides essential protection against malware and other security threats. Disabling this feature can leave the system vulnerable to attacks.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender and set 'Turn off Windows Defender' to 'Disabled' to ensure that Windows Defender remains active.",
        "Medium"
    ],

    "Turn off real-time protection": [
        "Real-time protection is a feature of Windows Defender that immediately scans files as they are accessed to detect malware. Disabling real-time protection increases the risk of undetected malware execution.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender Antivirus\\Real-time Protection and set 'Turn off real-time protection' to 'Disabled' to maintain continuous monitoring of threats.",
        "Medium"
    ],

    "Turn on behavior monitoring": [
        "Behaviour monitoring helps detect new, emerging, and unknown threats by observing the behaviour of programs. Enabling this feature provides an additional layer of security.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender Antivirus\\Real-time Protection and set 'Turn on behaviour monitoring' to 'Enabled'.",
        "Medium"
    ],

    "Scan all downloaded files and attachments": [
        "Scanning all downloaded files and email attachments helps prevent malicious files from executing by providing an essential safeguard against many types of cyber threats.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender Antivirus\\Scan and set 'Scan all downloaded files and attachments' to 'Enabled'.",
        "Medium"
    ],

    "Turn on process scanning whenever real-time protection is enabled": [
        "Process scanning analyses running processes to detect potentially harmful behavior or known malware patterns, enhancing overall protection.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender Antivirus\\Real-time Protection and set 'Turn on process scanning whenever real-time protection is enabled' to 'Enabled'.",
        "Medium"
    ],

    "Monitor file and program activity on your computer": [
        "Monitoring file and program activities helps detect and respond to suspicious behaviors, providing proactive protection against malware.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender Antivirus\\Real-time Protection and set 'Monitor file and program activity on your computer' to 'Enabled'.",
        "Medium"
    ],

    "Scan archive files": [
        "Scanning archive files allows Windows Defender to detect hidden threats within compressed files, preventing malware from bypassing security checks.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender Antivirus\\Scan and set 'Scan archive files' to 'Enabled'.",
        "Medium"
    ],

    "Scan packed executables": [
        "Packed executables can contain obfuscated malicious code. Scanning them helps protect against threats that attempt to evade traditional anti-malware detection.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender Antivirus\\Scan and set 'Scan packed executables' to 'Enabled'.",
        "Medium"
    ],

    "Scan removable drives": [
        "Removable drives can be a vector for malware transfer. Ensuring they are scanned helps mitigate the risk of infection from external sources.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Defender Antivirus\\Scan and set 'Scan removable drives' to 'Enabled'.",
        "Medium"
    ]
}

ck11_miti = {
    "Restrict Remote Desktop Services users to a single Remote Desktop Services session": [
        "This setting restricts users to a single session on a Remote Desktop Server, which helps contain user activity and reduces server load.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Connections and set 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' to 'Enabled'.",
        "Medium"
    ],

    "Do not allow Clipboard redirection": [
        "Clipboard redirection can pose a security risk by allowing data transfer between local and remote desktops. Disabling it enhances data security.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Device and Resource Redirection and set 'Do not allow Clipboard redirection' to 'Enabled'.",
        "Medium"
    ],

    "Do not allow drive redirection": [
        "Drive redirection allows users to access local drives from the remote session. Disabling this increases security by preventing potential unauthorized data transfer.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Device and Resource Redirection and set 'Do not allow drive redirection' to 'Enabled'.",
        "Medium"
    ],

    "Set client connection encryption level": [
        "The encryption level setting determines the strength of the encryption used for RDP connections. 'High Level' ensures data confidentiality.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Security and set 'Set client connection encryption level' to 'High Level'.",
        "Medium"
    ],

    "Always prompt for password upon connection": [
        "Requiring users to enter their password upon each connection adds a layer of security by ensuring user authentication at each access attempt.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Security and set 'Always prompt for password upon connection' to 'Enabled'.",
        "Medium"
    ],

    "Require secure RPC communication": [
        "Secure Remote Procedure Call (RPC) communication helps protect communication between client and server from interception and attacks.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Security and set 'Require secure RPC communication' to 'Enabled'.",
        "Medium"
    ],

    "Require use of specific security layer for remote (RDP) connections": [
        "Selecting a specific security layer (e.g., SSL) for RDP connections helps ensure credible and more secure remote connections.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Security and set 'Require use of specific security layer for remote (RDP) connections' to 'SSL'.",
        "Medium"
    ],

    "Require user authentication for remote connections by using Network Level Authentication": [
        "Network Level Authentication (NLA) verifies user credentials before establishing a remote connection, offering improved security.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Security and set 'Require user authentication for remote connections by using Network Level Authentication' to 'Enabled'.",
        "Medium"
    ],

    "Set time limit for disconnected sessions": [
        "Setting a time limit for disconnected sessions helps to free up system resources and decreases the risk of session hijacking.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Session Time Limits and set 'Set time limit for disconnected sessions' to 'Enabled: 1 minute'.",
        "Medium"
    ],

    "Set time limit for active but idle Remote Desktop Services sessions": [
        "Setting a time limit for idle sessions helps ensure resources are available and enhances security by terminating unattended sessions.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Session Time Limits and set 'Set time limit for active but idle Remote Desktop Services sessions' to '<= 15 minute(s) (>0)'.",
        "Medium"
    ],

    "Do not delete temp folders upon exit": [
        "When enabled, temporary folders are not deleted upon user session exit, which could lead to information being retained unintentionally.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Temporary Folders and set 'Do not delete temp folders upon exit' to 'Disabled' to ensure cleanup and security.",
        "Medium"
    ],

    "Do not use temporary folders per session": [
        "Enabling this setting means that each user session will not create separate temporary folders, potentially causing file conflicts.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Temporary Folders and set 'Do not use temporary folders per session' to 'Disabled'.",
        "Medium"
    ]
}

ck12_miti = {
    "Turn on PowerShell Script Block Logging": [
        "PowerShell Script Block Logging records detailed information about commands executed, assisting in identifying potentially malicious activity through comprehensive auditing.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows PowerShell and set 'Turn on PowerShell Script Block Logging' to 'Enabled' to enhance auditing and monitoring capabilities.",
        "Medium"
    ],

    "Turn on PowerShell Transcription": [
        "PowerShell Transcription creates records of all PowerShell command input and output, which can be essential for auditing and detecting suspicious activities.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows PowerShell and set 'Turn on PowerShell Transcription' to 'Enabled' to facilitate detailed session auditing.",
        "High"
    ],

    "Turn on Script Execution": [
        "This setting determines which PowerShell scripts are allowed to run. Allowing only signed scripts ensures that execution is limited to scripts from trusted sources, mitigating the risk of executing malicious code.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows PowerShell and set 'Turn on Script Execution' to 'Enabled: Allow only signed scripts or higher' to enforce script security policies.",
        "Medium"
    ]
}

ck13_miti = {
    "Allow Basic authentication": [
        "Basic authentication sends credentials in an unencrypted manner and is considered insecure unless used over a secure channel such as HTTPS. Disabling it helps prevent credential compromise.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Client or Service, depending on the context, and set 'Allow Basic authentication' to 'Disabled' to avoid insecure authentication methods.",
        "High"
    ],

    "Allow unencrypted traffic": [
        "Allowing unencrypted traffic can expose sensitive data to interception. It's crucial to ensure all traffic is encrypted to maintain data confidentiality and integrity.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Client or Service, depending on the context, and set 'Allow unencrypted traffic' to 'Disabled'.",
        "High"
    ],

    "Disallow Digest authentication": [
        "Digest authentication, though more secure than Basic, still poses risks if the transmission or storage of user credentials is intercepted. Disabling it can enhance credential security.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Client and set 'Disallow Digest authentication' to 'Enabled' to prevent use of weaker authentication methods.",
        "High"
    ],

    "Disallow WinRM from storing RunAs credentials": [
        "Storing RunAs credentials can increase the risk of credential misuse or exposure. Ensuring credentials are not stored enhances security.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Service and set 'Disallow WinRM from storing RunAs credentials' to 'Enabled'.",
        "Medium"
    ],

    "Allow remote server management through WinRM": [
        "Restricting remote server management through WinRM can limit remote administrative access, minimizing potential attack vectors. This setting should be carefully configured based on organizational requirements.",
        "Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Windows Remote Management (WinRM)\\WinRM Service and set 'Allow remote server management through WinRM' to 'Disabled' unless absolutely necessary for administrative purposes.",
        "Medium"
    ]
}

ck14_miti = {
	"Allow Remote Shell Access": [
    	"Allowing remote shell access can pose security risks by enabling remote execution and potentially exposing systems to unauthorized access and malicious activities.",
    	"Navigate to Computer Configuration\\Administrative Templates\\Windows Components\\Remote Shell and set 'Allow Remote Shell Access' to 'Disabled' to prevent remote users from accessing shell environments.",
    	"Medium"
	]
}


ck15_miti = {
	"Print Spooler (Spooler)": [
    	"The Print Spooler service manages print jobs and is a known security target for various vulnerabilities. Disabling it on servers where printing is unnecessary can mitigate potential security risks.",
    	"If printing is not required on the server, navigate to Services (services.msc), locate 'Print Spooler', and set the service to 'Disabled' to reduce the attack surface.",
    	"Medium"
	]
}


ck16_miti = {
	"Turn off local group policy processing": [
    	"Enabling the option to turn off local Group Policy processing ensures that local policies on the machine do not override or conflict with domain-level policies. This helps maintain consistent policy enforcement across the network.",
    	"Navigate to Computer Configuration\\Administrative Templates\\System\\Group Policy and set 'Turn off local group policy objects processing' to 'Enabled' to enforce domain-based policies uniformly without local policy interference.",
    	"Medium"
	]
}

ck17_miti = {
    "Password Configuration": [
        "Ensuring all active accounts have a configured password is crucial for security, preventing unauthorized access and potential exploitation.",
        "\n1. Access Active Directory Users and Computers, navigate to the Users folder, right-click on the specific account (e.g., USER$), select Reset Password, set a new password, and click OK.\n2. Alternatively, configure the requirement using PowerShell: \n> Set-ADUser -Identity ‘USER$’ -PasswordNotRequired $false",
        "High"
    ],

    "Check Unused Accounts": [
        "Accounts that have not been used for an extended period may present security risks. Disabling inactive accounts helps reduce the attack surface.",
        "\n1. For accounts without LastLogonTimestamp, exclude non-interactive logon types such as Service Accounts or accounts running scheduled tasks. \n2. For accounts not used in the past 45 days, consider disabling or removing unnecessary accounts.",
        "Medium"
    ],

    "Check Accounts Not Changing Passwords Periodically": [
        "Periodic password changes are essential to mitigate the risk of password compromise. Ensuring that active accounts change passwords regularly helps maintain security integrity.",
        "\n1. For accounts with no PasswordLastSet information, require immediate password change or disable if unused. \n2. For accounts not changed in the past 365 days, require a password change. \nTo enforce: Access Active Directory Users and Computers, select the user account, go to Account options, and check 'User must change password at next logon'.",
        "Medium"
    ],

    "Check Accounts Used for Services": [
        "Using privileged accounts for services can expose critical credentials to unnecessary risk. Service accounts should have the least privilege necessary.",
        "Create dedicated service accounts with appropriate limited privileges. Avoid using domain admin accounts for services, as exploitation could grant attackers access to the entire domain.",
        "High"
    ],

    "Change krbtgt Account Password": [
        "The krbtgt account is critical for Kerberos authentication. Regular password changes help protect against replay attacks and ticket reuse.",
        "Change the krbtgt account password twice with a 10-hour interval between changes to ensure expiration of old tickets, effectively nullifying any potential reuse.",
        "Medium"
    ],

    "Configure NTFS Permissions for AdminSDHolder Folder": [
        "The AdminSDHolder container helps protect administrative accounts and groups by enforcing secure permissions. Ensure permissions are strictly controlled.",
        "Ensure that NTFS permissions of the AdminSDHolder folder are restricted to default users only, with no additional user configurations.",
        "Medium"
    ],

    "Configure 'Protected Users' Group for High-Privilege Domain Accounts": [
        "Adding high-privilege domain accounts to the 'Protected Users' group enhances security by applying stringent account protection policies.",
        "Ensure that all high-privilege domain accounts, such as Administrators, Domain Admins, and Enterprise Admins, are added to the 'Protected Users' group for elevated security protection.",
        "High"
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
timestamp = datetime.datetime.now().strftime('%d/%m/%Y %I:%M:%S %p')
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
