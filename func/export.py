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

result = []
current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')


def export_json(json_name, arr, checklist_name,status):
    for i in arr:
        for v in ck1_miti.keys():
            if v in i:
                mitigation = ck1_miti.get(v)
                result.append(
                    {"name": i, "timestamp": current_time,
                     "checklist_name": checklist_name,
                     "status": status,
                     "mitigation": mitigation[0], "severity": mitigation[1]})
    with open(json_name, 'w') as f:
        json.dump(result, f, indent=4)
