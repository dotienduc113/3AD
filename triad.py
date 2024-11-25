import pyfiglet
import pyfiglet.fonts
import os
import random
import datetime
import argparse
from func.query import run_query
from func.checklist import compare_checklist
from func.export import delete_json, export_csv_table
from sys import exit


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
    while True:
        print("\n1. Auto Audit")
        print("2. Export CSV")
        print("3. Exit")
        user_input = input("\nInput: ")

        if user_input.isdigit():
            choice = int(user_input)
            if choice == 1:
                run_query()  # Call your functions
                compare_checklist()
            elif choice == 2:
                file_name = input("Input file name (blank for default): ")
                export_csv_table(file_name)
            elif choice == 3:
                print("Exiting program...")
                break  # Exit the loop, and the program ends
            else:
                print("Invalid input! Try again.")
        else:
            print("Invalid input! Try again.")


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
