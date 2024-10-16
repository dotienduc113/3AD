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


# add value to passed and failed array
def append_array(array, key, value):
    array.append(key + ": " + value)
    return


def checklist_1(passed, failed, checklist):  # checklist 1 va 2 lay du lieu va so sanh
    for key in checklist:
        try:
            value = int(checklist.get(key))
        except ValueError:
            value = -1
        if key == "Minimum password age (days)":
            if value >= 1:
                append_array(passed, key, checklist.get(key))
                # passed.append(key + ": " + checklist.get(key))
            else:
                append_array(failed, key, checklist.get(key))
                # failed.append(key + ": " + checklist.get(key))
        elif key == "Maximum password age (days)":
            if 30 <= value <= 90:
                append_array(passed, key, checklist.get(key))
            else:
                append_array(failed, key, checklist.get(key))
        elif key == "Minimum password length":
            if value >= 14:
                append_array(passed, key, checklist.get(key))
            else:
                append_array(failed, key, checklist.get(key))
        elif key == "Length of password history maintained":
            if value >= 14:
                append_array(passed, key, checklist.get(key))
            else:
                append_array(failed, key, checklist.get(key))
        elif key == "Lockout threshold":
            if 0 < value <= 5:
                append_array(passed, key, checklist.get(key))
            else:
                append_array(failed, key, checklist.get(key))
        elif key == "Lockout duration (minutes)":
            if value >= 15:
                append_array(passed, key, checklist.get(key))
            else:
                append_array(failed, key, checklist.get(key))
        elif key == "Lockout observation window (minutes)":
            if value >= 15:
                append_array(passed, key, checklist.get(key))
            else:
                append_array(failed, key, checklist.get(key))


def checklist_5(passed, failed, checklist5):  # checklist 5 lay du lieu va so sanh
    for profile, settings in checklist5.items():
        for obj, value in settings:
            if obj == "State" and value == "ON":
                append_array(passed, f"{profile[:-18]} {obj}", value)
            elif obj == "Firewall Policy" and "BlockInbound" in value:
                append_array(passed, f"{profile[:-18]} {obj}", value)
            #elif obj == "InboundUserNotification" and value == "Enable":
            #append_array(passed, f"{profile[:-18]} {obj}", value)
            elif obj == "LogAllowedConnections" and value == "Enable":
                append_array(passed, f"{profile[:-18]} {obj}", value)
            elif obj == "LogDroppedConnections" and value == "Enable":
                append_array(passed, f"{profile[:-18]} {obj}", value)
            elif obj == "MaxFileSize" and int(value) >= 16384:
                append_array(passed, f"{profile[:-18]} {obj}", value)
            else:
                append_array(failed, f"{profile[:-18]} {obj}", value)


def compare_checklist():
    clist = filter_info_1()
    clist5 = filer_info_5()
    '''
    for profile, settings in checklist2.items():
        print(f"\n{profile}")
        for setting, value in settings:
            print(f"{profile[:-18]} {setting}, Value: {value}")
    '''
    passed = []
    failed = []
    checklist_1(passed, failed, clist)
    checklist_5(passed, failed, clist5)
    return passed, failed


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
        result = compare_checklist()
        result_table(result[0], result[1])
        return


if __name__ == "__main__":
    display_banner()
    # install_requirements()
    # run_velo()
    # checklist = filter_info()
    # compare_checklist()
    menu()
