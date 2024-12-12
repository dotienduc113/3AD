import argparse
from ldap3 import Server, Connection as LDAPConnection, ALL, NTLM
from impacket.smbconnection import SMBConnection, smb
import click
from ftplib import FTP, error_perm
import socket
import os
import csv
import win32serviceutil
import datetime

timestamp = datetime.datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')


def export_csv_service(service, status, description, mitigation, csv_name):
    fieldnames = ['Timestamp', 'Service', 'Status', 'Description', 'Mitigation']
    results_dir = ".\\results"
    file_path = os.path.join(results_dir, csv_name)

    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    file_exists = os.path.isfile(file_path)

    with open(file_path, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists or os.path.getsize(file_path) == 0:
            writer.writeheader()
        writer.writerow({'Timestamp': timestamp, 'Service': service, 'Status': status, 'Description': description, 'Mitigation': mitigation})


def check_smbv1(host, csv_name):
    description = "Outdated protocol vulnerable to exploits like EternalBlue, MITM attacks and lacks encryption."
    mitigation = "Disable SMBv1 and use SMBv3 with encryption and integrity."
    try:
        # connect den smb server
        s = SMBConnection('*SMBSERVER', host, preferredDialect=smb.SMB_DIALECT)
        # kiem tra xem object smbconnection s co duoc tao khong
        if isinstance(s, SMBConnection):
            print(f"SMBv1 is ENABLED on {host}")
            export_csv_service("SMBv1", "Enabled", description, mitigation, csv_name)
        else:
            print(f"SMBv1 is DISABLED on {host}")
            export_csv_service("SMBv1", "Disabled", description, mitigation, csv_name)
    except Exception as e:
        print(f"Error checking SMBv1 on {host}: {e}")
        export_csv_service("SMBv1", "Disabled", description, mitigation, csv_name)
        return


def check_adcs(host, csv_name, port=135):
    description = "Misconfigured templates can lead to privilege escaation and certificate abuse."
    mitigation = "Audit templates, restrict access, and use strong cryptographic algorithms."
    try:
        # Tao TCP socket su dung de ket noi AF_INET = IPv4, SOCK_STREAM = TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        # ket noi den thong qua host va port mac dinh 135
        sock.connect((host, port))
        print(f"ADCS (MS-RPC) is accessible on {host}:{port}")
        export_csv_service("Active Directory Certificate Services", "Enabled", description, mitigation, csv_name)
    except Exception as e:
        print(f"ADCS (MS-RPC) is NOT accessible on {host}:{port}")
        export_csv_service("Active Directory Certificate Services", "Disabled", description, mitigation, csv_name)
    finally:
        sock.close()


def check_ldap(domain, user, password, server_ip, csv_name):
    description = "Default plaintext transmission and anonymous binds expose sensitive data."
    mitigation = "Use LDAPS, disable anonymous binds, and enforce strict access controls."
    try:
        # Tao 1 object LDAP Server:
        server = Server(f'ldap://{server_ip}', get_info=ALL)
        username = f"{domain}\\{user}"
        # kiem tra ket noi den ldap server
        conn = LDAPConnection(server, user=f"{username}", password=password, authentication=NTLM, auto_bind=True)
        if conn.bind():
            print("LDAP bind successful.")
            export_csv_service("LDAP", "Enabled", description, mitigation, csv_name)
        else:
            print("LDAP bind failed:", conn.result)
            export_csv_service("LDAP", "Disabled", description, mitigation, csv_name)
        conn.unbind()
    except Exception as e:
        print(f"LDAP query failed: {e}")
        print("Ensure you are using the correct domain, username, and password.")
        export_csv_service("LDAP", "Failed - need manual check", description, mitigation, csv_name)


def check_anonymous_ftp(server_ip, csv_name, port=21, timeout=10):
    description = " Unauthenticated access can expose or allow manipulation of sensitive files."
    mitigation = "Disable anonymous FTP or use secure alternatives like SFTP/FTPS."
    try:
        # Ket noi den FTP server
        print(f"Connecting to FTP server {server_ip}:{port}...")
        ftp = FTP()
        ftp.connect(host=server_ip, port=port, timeout=timeout)

        # Dang nhap voi tai khoan anonymous
        print("Attempting anonymous login...")
        response = ftp.login(user="anonymous", passwd="anonymous@domain.com")
        print("Anonymous login successful!")
        print("Server Response:", response)

        export_csv_service("Anonymous FTP", "Enabled", description, mitigation, csv_name)
        # Close the connection
        ftp.quit()

    except Exception as e:
        print(f"Connection failed: {e}")
        export_csv_service("Anonymous FTP", "Disabled", description, mitigation, csv_name)


def check_adds(csv_name):
    description = "Poor configuration leads to attacks like DCSync, Kerberoasting, and lateral movement."
    mitigation = "Enforce strong password policies, monitor privileges, and restrict replication permissions."
    service_name = "NTDS"
    try:
        # su dung win32serviceutil de kiem tra status cua NTDS service (Active Directory Domain Services).
        service_status = win32serviceutil.QueryServiceStatus(service_name)
        status_code = service_status[1]
        # gan status codes toi state tuong ung
        status_mapping = {
            1: "Stopped",
            2: "Start Pending",
            3: "Stop Pending",
            4: "Running",
            5: "Continue Pending",
            6: "Pause Pending",
            7: "Paused"
        }
        # mac dinh la unknown neu khong tim thay
        status = status_mapping.get(status_code, "Unknown")
        print(f"AD DS Service Status: {status}")

        if status == "Running":
            export_csv_service("Active Directory Domain Services", "Running", description, mitigation, csv_name)
            return True
        else:
            export_csv_service("Active Directory Domain Services", f"{status}", description, mitigation, csv_name)
            return False
    except Exception as e:
        print(f"Error checking AD DS service: {e}")
        export_csv_service("Active Directory Domain Services", f"Not Connected", description, mitigation, csv_name)
        return False


