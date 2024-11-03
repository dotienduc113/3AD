import pyfiglet
import pyfiglet.fonts
import os
import random
import subprocess
import re
from textwrap import fill
from tabulate import tabulate
from itertools import zip_longest
import datetime
import argparse
import time
import json
from func.query import run_query
from func.checklist import compare_checklist


def display_banner():  # Create random font
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


# gui function
def menu():
    # print("0. Install requirements")
    print("1. Auto Audit")
    print("2. Exit")
    while True:
        user_input = input("\nInput: ")
        if user_input.isdigit():
            choice = int(user_input)
            if choice == 1:
                execute(choice)
            elif choice == 2:
                exit()
            else:
                print("Invalid input! Try again.")
        else:
            print("Invalid input! Try again.")


'''
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
'''

'''
def run_query1():
    f = open("query.txt", "r")
    count = 0
    for line in f:
        count = count + 1
        cmd = '{0}'.format(line.strip())
        # print(cmd)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            # print(result.stdout)  # Output the command result
            print(result.stderr)  # Print any errors
        except Exception as e:
            print(f"Error running command: {e}")
'''

# dung de cho vao bang passed va failed
'''
def result_table1(passed, failed):
    # Create the table with two columns
    table = PrettyTable(max_table_width=100)
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
'''


def execute(choice):
    #if choice == 0:
    #    install_requirements()
    if choice == 1:
        #run_query()
        compare_checklist()
        return


if __name__ == "__main__":
    new_path = ".\\logs"
    if not os.path.exists(new_path):
        os.makedirs(new_path)
    new_path2 = ".\\results"
    if not os.path.exists(new_path2):
        os.makedirs(new_path2)
    display_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('--nogui', action='store_true', help='run without GUI')
    parser.add_argument('-l', '--loop', action='store_true', help='loop')
    parser.add_argument('-s', '--sec', type=int, help='set time loop (default 15s)')
    parser.add_argument('-i', '--intensive', action='store_true', help='Intensive mode')
    parser.add_argument('-b', '--basic', action='store_true', help='Basic mode')
    parser.add_argument('-vb', '--verbose', action='store_true', help='Verbose mode')
    '''
    parser.add_argument('-c1', '--checklist1', action='store_true', help='checklist 1: Password Policy')
    parser.add_argument('-cl1', '--checklist1', action='store_true', help='checklist 1: Password Policy')
    parser.add_argument('-cl2', '--checklist2', action='store_true', help='checklist 2: Account Lockout Policy')
    parser.add_argument('-cl3', '--checklist3', action='store_true', help='checklist 3: User Rights Assignment')
    parser.add_argument('-cl4', '--checklist4', action='store_true', help='checklist 4: Security Options')
    parser.add_argument('-cl5', '--checklist5', action='store_true', help='checklist 5: Windows Defender Firewall with Advanced Security')
    parser.add_argument('-cl6', '--checklist6', action='store_true', help='checklist 6: Audit Policy')
    parser.add_argument('-cl7', '--checklist7', action='store_true', help='checklist 7: MS Security Guide')
    parser.add_argument('-cl8', '--checklist8', action='store_true', help='checklist 8: Network Provider')
    parser.add_argument('-cl9', '--checklist9', action='store_true', help='checklist 9: Credentials Delegation')
    parser.add_argument('-cl10', '--checklist10', action='store_true', help='checklist 10: Windows Defender')
    parser.add_argument('-cl11', '--checklist11', action='store_true', help='checklist 11: Remote Desktop Services')
    parser.add_argument('-cl12', '--checklist12', action='store_true', help='checklist 12: Windows PowerShell')
    parser.add_argument('-cl13', '--checklist13', action='store_true', help='checklist 13: WinRM')
    parser.add_argument('-cl14', '--checklist14', action='store_true', help='checklist 14: Windows Remote Shell')
    parser.add_argument('-cl15', '--checklist15', action='store_true', help='checklist 15: System Services')
    parser.add_argument('-cl16', '--checklist16', action='store_true', help='checklist 16: Group Policy')
    '''
    args = parser.parse_args()

    condition_met = False
    current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')

    if (args.loop and args.sec) or args.loop:
        if not args.sec:
            args.sec = 15
        condition_met = True
        while True:
            current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
            run_query()
            compare_checklist()
            time.sleep(args.sec)
    if args.nogui:
        condition_met = True
        run_query()
        compare_checklist()

    '''
    if args.checklist1 or args.checklist2:
        condition_met = True
        run_query()
        clist1 = filter_info_1()
        checklist_1(clist1)
    if args.checklist3:
        condition_met = True
        clist3 = filter_info_secpol(".\\logs\\result3.txt")
        checklist_3(clist3)
    if args.checklist4:
        condition_met = True
        clist4 = filter_info_4()
        checklist_4(clist4)
    if args.checklist5:
        condition_met = True
        clist5 = filer_info_5()
        checklist_5(clist5)
    if args.checklist6:
        condition_met = True
        clist6 = filter_info_6()
        checklist_6(clist6)
    if args.checklist7:
        condition_met = True
        clist7 = filter_info_7()
        checklist_7(clist7)
    if args.checklist8:
        condition_met = True
        clist8 = filter_info_8()
        checklist_8(clist8)
    if args.checklist9:
        condition_met = True
        clist9 = filter_info_9()
        checklist_9(clist9)
    if args.checklist10:
        condition_met = True
        clist10 = filer_info_registry(".\\logs\\result10.txt")
        checklist_10(clist10)
    if args.checklist11:
        condition_met = True
        clist11 = filer_info_registry(".\\logs\\result11.txt")
        checklist_11(clist11)
    if args.checklist12:
        condition_met = True
        clist12 = filer_info_registry(".\\logs\\result12.txt")
        checklist_12(clist12)
    if args.checklist13:
        condition_met = True
        clist13 = filter_info_13()
        checklist_13(clist13)
    if args.checklist14:
        condition_met = True
        clist14 = filer_info_registry(".\\logs\\result14.txt")
        checklist_14(clist14)
    if args.checklist15:
        condition_met = True
        clist15 = filer_info_registry(".\\logs\\result15.txt")
        checklist_15(clist15)
    if args.checklist16:
        condition_met = True
        clist16 = filer_info_registry(".\\logs\\result16.txt")
        checklist_16(clist16)
    '''

    if not condition_met:
        menu()
