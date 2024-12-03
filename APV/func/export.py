import json
import datetime
import csv
import os

result = []
current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
timestamp = datetime.datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')
json_name = f"APV_result.json"
csv_name = f"APV_result.csv"


def export_json(arr, permission, secured_object, secured_object_type, security_principal_type):
    for i in arr:
        result.append(
            {"timestamp": timestamp,
             "permission": permission,
             "secured_object": secured_object,
             "secured_object_type": secured_object_type,
             "security_principal": i,
             "security_principal_type": security_principal_type})
    with open(f".\\results\\{json_name}", 'w') as f:
        json.dump(result, f, indent=4)


def export_csv_table(csv_table_name=None):
    if csv_table_name is not None and csv_table_name != "":
        csv_table_name = f"{csv_table_name}.csv"
    else:
        csv_table_name = f"{csv_name}"
    with open(f'.\\results\\{json_name}', 'r') as f:
        data = json.load(f)
    fieldnames = ['timestamp', 'permission', 'secured_object', "secured_object_type", 'security_principal',
                  'security_principal_type']
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
