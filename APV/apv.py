import subprocess
import json
from textwrap import fill
from tabulate import tabulate
from itertools import zip_longest
import glob
import zipfile
from func.export import export_json, export_csv_table
import pyfiglet
import random
from func.service import *


def display_banner():
    fonts = pyfiglet.FigletFont.getFonts()
    rd = random.randint(0, len(fonts) - 1)

    banner = pyfiglet.figlet_format("TriAD APV", font=fonts[rd])

    if os.name == 'nt':
        os.system('color')

    print(banner)
    print("Welcome to APV! Starting up...\n")


def run_bloodhound(domain, username, password):
    try:
        result = subprocess.run(f'cd logs && bloodhound-python -d {domain} -u {username} -p {password} -c ACL --zip',
                                shell=True)
        print(result.stderr)  # Print any errors
    except Exception as e:
        print(f"Error running command: {e}")


def get_zip_file():
    zip_files = glob.glob('.\\logs\\*_BloodHound.zip')
    if not zip_files:
        return None
    zip_files.sort(key=os.path.getmtime)
    return zip_files[-1]


def wmic_query():
    query1 = "wmic useraccount get name,sid"
    query2 = "wmic group get name,sid"
    try:
        # Run both commands
        result1 = subprocess.run(query1, shell=True, capture_output=True, text=True)
        result2 = subprocess.run(query2, shell=True, capture_output=True, text=True)

        result1_lines = result1.stdout.strip().splitlines()[1:]  # Skip the first line
        result2_lines = result2.stdout.strip().splitlines()[1:]  # Skip the first line

        combined_result = "\n".join(result1_lines + result2_lines)

        return combined_result
    except Exception as e:
        print(f"Error running command: {e}")


def wmic_query_sep(i):
    if i == 0:
        query = "wmic useraccount get name,sid"
        try:
            result = subprocess.run(query, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            print(f"Error running command: {e}")
    elif i == 1:
        query = "wmic group get name,sid"
        try:
            result = subprocess.run(query, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            print(f"Error running command: {e}")
    elif i == 2:
        query = """powershell.exe -Command "(Get-ADForest).Domains| %{Get-ADDomain -Server $_}|select name, domainsid" """
        try:
            result = subprocess.run(query, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            print(f"Error running command: {e}")


def compare_sid(v, sids):
    for user, sid in sids.items():
        if sid == v:
            return user


def compare_sid_group(v, sids):
    for user, sid in sids.items():
        if sid in v:
            return user


def get_sid(result):
    # doc ket qua result tu ham wmic_query_sep
    lines = result.split("\n")
    dic = {}
    # black list = ["Print Operators", "Backup Operators", "Replicator", "Remote Desktop Users"] "Network Configuration Operators", "Performance Monitor Users", "Performance Log Users", "Distributed COM Users", "IIS_IUSRS", "Cryptographic Operators", "Event Log Readers", "Certificate Service DCOM Access", "RDS Remote Access Servers", "RDS Endpoint Servers", "RDS Management Servers", "Hyper-V Administrators", "Access Control Assistance Operators", "Remote Management Users", "Server Operators", "Account Operators", "Pre-Windows 2000 Compatible Access", "Incoming Forest Trust Builders", "Windows Authorization Access Group", "Terminal Server License Servers", "Cert Publishers", "RAS and IAS Servers", "Allowed RODC Password Replication Group", "Denied RODC Password Replication Group"]
    list = []
    for line in lines[1:]:
        if line.strip():
            parts = line.split()
            sid = parts[-1]
            user = " ".join(parts[0:-1])
            # tao ra 1 dictionary k-v tuong ung user va sid
            if user not in list:
                dic[user] = sid
    return dic


def get_sid_domain(result):
    lines = result.split("\n")
    dic = {}
    list = []
    for line in lines[2:]:
        if line.strip():
            parts = line.split()
            sid = parts[-1]
            user = " ".join(parts[0:-1])
            if user not in list:
                dic[user] = sid
    return dic


sid_user = get_sid(str(wmic_query_sep(0)))
sid_group = get_sid(str(wmic_query_sep(1)))
sid_domain = get_sid_domain(str(wmic_query_sep(2)))


def extract_ace_data(user, data, permission):  # str user, dictionary data, str permission
    arr0 = [], arr1 = [], arr2 = []
    dic = {}
    for key, value in data.items():
        for item in value:
            if 'Aces' in item and 'Properties' in item:
                # gan gia tri s voi name trong json: s = administrator@easybank.com
                s = item["Properties"]["name"]
                s1 = s.split("@")
                # so sanh gia tri user dau vao voi user trong du lieu bloodhound
                if user == s1[0]:
                    # kiem tra ACE va permission dau vao
                    for ace in item['Aces']:
                        if ace['RightName'] == permission:
                            value = ace["PrincipalSID"]
                            # map gia tri value (sid) voi user tuong ung
                            user0 = compare_sid(value, sid_user)
                            user1 = compare_sid_group(value, sid_group)
                            user2 = compare_sid(value, sid_domain)
                            if user0 not in arr0 and user0 is not None:
                                arr0.append(user0)
                                dic["user"] = arr0
                            if user1 not in arr1 and user1 is not None:
                                arr1.append(user1)
                                dic["group"] = arr1
                            if user2 not in arr2 and user2 is not None:
                                arr2.append(user2)
                                dic["domain"] = arr2
    return dic


def extract_ace_data_domain(user, data, permission):
    arr0 = []
    arr1 = []
    arr2 = []
    dic = {}
    for key, value in data.items():
        for item in value:
            if 'Aces' in item and 'Properties' in item:
                s = item["Properties"]["name"]
                s1 = s.split("@")
                if user in s1[0]:
                    for ace in item['Aces']:
                        if ace['RightName'] == permission:
                            value = ace["PrincipalSID"]
                            user0 = compare_sid(value, sid_user)
                            user1 = compare_sid_group(value, sid_group)
                            user2 = compare_sid(value, sid_domain)
                            if user0 not in arr0 and user0 is not None:
                                arr0.append(user0)
                                dic["user"] = arr0
                            if user1 not in arr1 and user1 is not None:
                                arr1.append(user1)
                                dic["group"] = arr1
                            if user2 not in arr2 and user2 is not None:
                                arr2.append(user2)
                                dic["domain"] = arr2
    return dic


def read_json(part):
    zip_file = get_zip_file()
    filename = os.path.basename(zip_file)
    date = filename.split('_')[0]
    try:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            with zip_ref.open(f'{date}{part}', 'r') as f:
                content = f.read()
                if not content.strip():
                    print("File is empty or contains only whitespace")
                    return
                data = json.loads(content)
                return data

    except FileNotFoundError:
        print("File not found")
    except json.JSONDecodeError as e:
        print("Error parsing JSON:", e)
    except Exception as e:
        print("An error occurred:", e)


def result_table(passed, header, width=100):
    # Wrap text in each column to the specified width
    passed_wrapped = [fill(item, width=width) if item else '' for item in passed]

    # Create the table with two columns
    table = [p for p in zip_longest(passed_wrapped, fillvalue='')]

    # Print the table
    if len(passed) > 0:
        print(tabulate(table, headers=[header], tablefmt="grid"))
        return tabulate(table, headers=[header], tablefmt="grid")
    return ""


def export_result(current_time, str, table):
    f_name = f"APV_{current_time}.txt"
    with open(f".\\results\\{f_name}", "a+") as f:
        if str != "":
            f.write(str)
        if len(table) > 1:
            f.write(table)


def execute(dic, permission, name, secured_object_type):
    if len(dic) != 0:
        try:
            arr0 = dic.get('user') # lay mang tu value dic['user']
            result_table(arr0, permission) # xuat ra terminal
            export_json(arr0, permission, name, secured_object_type, 'user') # xuat ra json
        except:
            pass
        try:
            arr1 = dic.get('group')
            result_table(arr1, permission)
            export_json(arr1, permission, name, secured_object_type, 'group')
        except:
            pass
        try:
            arr2 = dic.get('domain')
            result_table(arr2, permission)
            export_json(arr2, permission, name, secured_object_type, 'domain')
        except:
            pass


def apv_permission(domain, username, password, csv_name):
    run_bloodhound(domain, username, password)

    # users
    data = read_json("_users.json")
    count = 0
    print("\n")
    secured_object_type = "user"
    for name, sid in sid_user.items():
        count = count + 1
        print(str(count) + "." + name)

        dic = extract_ace_data(name.upper(), data, "ForceChangePassword")
        execute(dic, "ForceChangePassword", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "GenericAll")
        execute(dic, "GenericAll", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "GenericWrite")
        execute(dic, "GenericWrite", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "WriteDacl")
        execute(dic, "WriteDacl", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "WriteOwner")
        execute(dic, "WriteOwner", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "AllExtendedRights")
        execute(dic, "AllExtendedRights", name, secured_object_type)

    export_csv_table(csv_name)

    # groups

    data = read_json("_groups.json")
    count = 0
    print("\n")
    secured_object_type = "group"

    for name, sid in sid_group.items():
        count = count + 1
        print(str(count) + "." + name)

        dic = extract_ace_data(name.upper(), data, "GenericAll")
        execute(dic, "GenericAll", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "GenericWrite")
        execute(dic, "GenericWrite", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "WriteDacl")
        execute(dic, "WriteDacl", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "WriteOwner")
        execute(dic, "WriteOwner", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "AllExtendedRights")
        execute(dic, "AllExtendedRights", name, secured_object_type)

        dic = extract_ace_data(name.upper(), data, "AddMember")
        execute(dic, "AddMember", name, secured_object_type)

    export_csv_table(csv_name)

    # domains
    data = read_json("_domains.json")
    count = 0
    print("\n")
    secured_object_type = "domains"
    for name, sid in sid_domain.items():
        count = count + 1
        print(str(count) + "." + name)

        dic = extract_ace_data_domain(name.upper(), data, "GetChanges")
        execute(dic, "GetChanges", name, secured_object_type)

        dic = extract_ace_data_domain(name.upper(), data, "GetChangesAll")
        execute(dic, "GetChangesAll", name, secured_object_type)

        dic = extract_ace_data_domain(name.upper(), data, "GetChangesInFilteredSet")
        execute(dic, "GetChangesInFilteredSet", name, secured_object_type)

        dic = extract_ace_data_domain(name.upper(), data, "AllExtendedRights")
        execute(dic, "AllExtendedRights", name, secured_object_type)

        dic = extract_ace_data_domain(name.upper(), data, "GenericAll")
        execute(dic, "GenericAll", name, secured_object_type)

        dic = extract_ace_data_domain(name.upper(), data, "WriteDacl")
        execute(dic, "WriteDacl", name, secured_object_type)

        dic = extract_ace_data_domain(name.upper(), data, "WriteOwner")
        execute(dic, "WriteOwner", name, secured_object_type)

    export_csv_table(csv_name)


def apv_service(domain, user, password, target_host, filename):
    if filename is not None:
        csv_name = f"{filename}.csv"
    else:
        csv_name = "Service_result.csv"

    print("\n--- Checking SMBv1 ---")
    check_smbv1(target_host, csv_name)

    print("\n--- Checking Active Directory Certificate Services ---")
    check_adcs(target_host, csv_name)

    print("\n--- Checking LDAP ---")
    check_ldap(domain, user, password, target_host, csv_name)

    print("\n--- Checking anonymous FTP ---")
    check_anonymous_ftp(target_host, csv_name)

    print("\n--- Checking Active Directory Domain Services ---")
    check_adds(csv_name)


if __name__ == '__main__':
    display_banner()

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', required=True, help='Domain to target')
    parser.add_argument('-u', '--username', required=True, help='Username to use')
    parser.add_argument('-p', '--password', required=True, help='Password to use')
    parser.add_argument('-i', '--ipaddress', required=True, help='IP address to use')
    parser.add_argument('-per', '--permission', action='store_true', help='Running APV-Permission')
    parser.add_argument('-ser', '--service', action='store_true', help='Running APV-Service')
    parser.add_argument('-op', '--output_permission', nargs='?', default=None,
                        help='Specify the output APV_Permission file')
    parser.add_argument('-os', '--output_service', nargs='?', default=None,
                        help='Specify the output APV_Permission file')
    args = parser.parse_args()

    new_path = ".\\logs"
    if not os.path.exists(new_path):
        os.makedirs(new_path)
    new_path2 = ".\\results"
    if not os.path.exists(new_path2):
        os.makedirs(new_path2)

    if args.permission and args.service:
        apv_permission(args.domain, args.username, args.password, args.output_permission)
        apv_service(args.domain, args.username, args.password, args.ipaddress, args.output_service)
    elif args.permission:
        apv_permission(args.domain, args.username, args.password, args.output_permission)
    elif args.service:
        apv_service(args.domain, args.username, args.password, args.ipaddress, args.output_service)
    else:
        apv_permission(args.domain, args.username, args.password, args.output_permission)
        apv_service(args.domain, args.username, args.password, args.ipaddress, args.output_service)
