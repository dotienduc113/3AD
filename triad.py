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
    print("1. Auto Audit")
    print("2. Exit")
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


def run_velo():
    f = open("velo_query.txt", "r")
    for line in f:
        cmd = ('velociraptor query "{0}" >> result.txt'.format(line.strip()))
        # print(cmd)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(result.stdout)  # Output the command result
            print(result.stderr)  # Print any errors
        except Exception as e:
            print(f"Error running command: {e}")


def remove_extra_spaces(text):
    # Replace multiple spaces with a single space
    return re.sub(r'\s+', ' ', text).strip()


def filter_info():
    file = open("result.txt", "r")
    checklist = {}
    for line in file:
        if line.strip().startswith("\"Checklist \":"):
            line = remove_extra_spaces(line)
            array_line = line[15:-1].split(": ")
            checklist[array_line[0]] = array_line[1]
    return checklist


# add value to passed and failed array
def append_array(array, key, value):
    array.append(key + ": " + value)
    return


def compare_checklist():
    checklist = filter_info()  # Assuming this returns a dictionary
    passed = []
    failed = []
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
    return passed, failed


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
        run_velo()  # - nho xoa cai nay
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
