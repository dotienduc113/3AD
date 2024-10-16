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
        cmd = '{0} > .\\logs\\result"{1}".txt'.format(line.strip(), format(count))
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


# loc du lieu trong trong query checklist 1 va 2
def filter_info_1():
    file = open(".\\logs\\result1.txt", "r")
    checklist = {}
    for line in file:
        line = remove_extra_spaces(line)
        line = line.strip()
        array_line = line.split(": ")
        checklist[array_line[0]] = array_line[1]
    return checklist


# loc du lieu trong trong query checklist 5
def filer_info_5():
    file = open(".\\logs\\result2.txt", "r")
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


def filter_info_6():
    file = open(".\\logs\\result3.txt", "r")
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


# add value to passed and failed array
def append_array(array, key, value):
    array.append(key + ": " + value)
    return


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
    print("\n1+2. Password Policy and Account Lockout Policy result: \n")
    result_table(passed,failed)


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
    print("\n5. Windows Defender Firewall with Advanced Security result: \n")
    result_table(passed, failed)


def checklist_6(clist6):
    passed = []
    failed = []
    for category, setting in clist6.items():
        category = category.strip()
        setting = setting.strip()
        if (category == "Credential Validation" or category == "Kerberos Service Ticket Operations" or category == "Kerberos Authentication Service") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (category == "Distribution Group Management" or category == "Other Account Management Events") and setting == "Success":
            append_array(passed, f"{category}", setting)
        elif (category == "Application Group Management" or category == "User account management") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif category == "Process Creation" and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (category == "Directory Service Access" or category == "Directory Service Changes" or category == "Directory Service Replication" or category == "Detailed Directory Service Replication") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (category == "Logon" or category == "Logoff" or category == "Account Lockout" or category == "IPsec Main Mode"  or category == "IPsec Quick Mode" or category == "IPsec Extended Mode" or category == "Special Logon" or category == "Other Logon/Logoff Events" or category == "Network Policy Server") and setting == "Success and Failure" :
            append_array(passed, f"{category}", setting)
        elif (category == "Audit Policy Change" or category == "MPSSVC Rule-Level Policy Change" or category == "Other Policy Change Events") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        elif (category == "Authentication Policy Change" or category == "Authorization Policy Change" or category == "Filtering Platform Policy Change") and setting == "Success":
            append_array(passed, f"{category}", setting)
        elif (category == "Non Sensitive Privilege Use " or category == "Other Privilege Use Events" or category == "Sensitive Privilege Use") and setting == "Success and Failure":
            append_array(passed, f"{category}", setting)
        else:
            append_array(failed, f"{category}", setting)
    print("\n6. Audit Policy: \n")
    result_table(passed, failed)


def compare_checklist():
    clist1 = filter_info_1()
    clist5 = filer_info_5()
    clist6 = filter_info_6()

    '''
    for profile, settings in checklist2.items():
        print(f"\n{profile}")
        for setting, value in settings:
            print(f"{profile[:-18]} {setting}, Value: {value}")
    '''

    checklist_1(clist1)
    checklist_5(clist5)
    checklist_6(clist6)


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
        # run_query()
        compare_checklist()
        return


if __name__ == "__main__":
    display_banner()
    # install_requirements()
    # checklist = filter_info()
    # compare_checklist()
    menu()
