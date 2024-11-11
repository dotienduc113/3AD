import pyfiglet
import pyfiglet.fonts
import os
import random
import datetime
import argparse
from func.query import run_query
from func.checklist import compare_checklist
from func.export import delete_json, export_csv_table


def display_banner():
    fonts = pyfiglet.FigletFont.getFonts()
    rd = random.randint(0, len(fonts) - 1)

    banner = pyfiglet.figlet_format("TriAD", font=fonts[rd])

    if os.name == 'nt':
        os.system('color')

    print(banner)
    print("Welcome to TriAD! Starting up...\n")
    print("\033[0m")  # Reset text color to default


# gui function
def menu():
    # print("0. Install requirements")
    print("1. Auto Audit")
    print("2. Export CSV")
    print("3. Exit")
    while True:
        user_input = input("\nInput: ")
        if user_input.isdigit():
            choice = int(user_input)
            if choice == 1:
                execute(choice)
            elif choice == 2:
                file_name = input("Input file name (blank for default):")
                export_csv_table(file_name)
            elif choice == 3:
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
        run_query()
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
    parser.add_argument('-nogui', action='store_true', help='Run without GUI')
    parser.add_argument('-i', '--intensive', action='store_true', help='Intensive mode')
    parser.add_argument('-b', '--basic', action='store_true', help='Basic mode')
    parser.add_argument('-n', '--filename', nargs='?', default=None, help='Specify the name of the csv file')
    parser.add_argument('-csv', '--onlycsv', action='store_true', help='Return only cvs file')
    parser.add_argument('-vb', '--verbose', action='store_true', help='Verbose mode')
    args = parser.parse_args()
    condition_met = False
    current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')

    if args.nogui and args.verbose:
        print('Running query...')
        run_query()
    if args.nogui and args.verbose:
        print('Comparing checklist...')
        compare_checklist()
        exit()

    if args.nogui:
        condition_met = True
        run_query()
        compare_checklist()
    if args.nogui and (args.filename or args.filename is None):
        condition_met = True
        export_csv_table(args.filename)
    if args.nogui and args.onlycsv:
        condition_met = True
        delete_json()

    if not condition_met:
        menu()
