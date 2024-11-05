import json
import datetime

ck1_miti = {
    "Enforce password history": ["mitigation1", "Critical"],
    "Maximum password age": ["mitigation2", "High"],
    "Minimum password age": ["mitigation3", "High"],
    "Minimum password length": ["mitigation4", "High"],
    "Password must meet complexity requirements": ["mitigation5", "Low"],
    "Store passwords using reversible encryption": ["mitigation6", "Low"],
    "Account lockout duration": ["mitigation7", "Low"],
    "Account lockout threshold": ["mitigation8", "Low"],
    "Reset account lockout counter after": ["mitigation9", "Low"]
}

ck3_miti = {
    "Access this computer from the network": ["mitigation1", "Critical"],
    "Deny access to this computer from the network": ["mitigation2", "High"],
    "Deny log on as a batch job": ["mitigation3", "High"],
    "Deny log on as a service": ["mitigation4", "High"],
    "Deny log on through Remote Desktop Services": ["mitigation5", "Low"],
    "Deny log on locally": ["mitigation6", "Low"],
    "Allow log on locally": ["mitigation7", "Low"],
    "Allow log on through Remote Desktop Services": ["mitigation8", "Low"],
    "Shut down the system": ["mitigation9", "Low"],
    "Act as part of the operating system": ["mitigation9", "Low"]
}

result = []
current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')


def export_json(json_name, arr, ck_mitigation, checklist_name, status):
    for i in arr:
        for v in ck_mitigation.keys():
            if v in i:
                mitigation = ck_mitigation.get(v)
                result.append(
                    {"name": i, "timestamp": current_time,
                     "checklist_name": checklist_name,
                     "status": status,
                     "mitigation": mitigation[0], "severity": mitigation[1]})
    with open(json_name, 'w') as f:
        json.dump(result, f, indent=4)
