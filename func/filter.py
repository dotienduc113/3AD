import re


def remove_extra_spaces(text):
    # Replace multiple spaces with a single space
    return re.sub(r'\s+', ' ', text).strip()

    # Iterate over the lines and extract settings


# add value to passed and failed array


def filter_info_1():
    file = open(".\\logs\\result1.txt", "r")
    settings = {}
    for line in file:
        line = remove_extra_spaces(line)
        line = line.strip()
        array_line = line.split(": ")
        settings[array_line[0]] = array_line[1]
    return settings


# loc du lieu trong trong query checklist 5
def filer_info_5():
    file = open(".\\logs\\result5.txt", "r")
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
    file = open(".\\logs\\result6.txt", "r")
    lines = file.read().split('\n')
    # Initialize dictionaries to store settings
    settings = {}

    # Iterate over the lines and extract settings
    for line in lines:
        if line.strip():
            match = re.match(r'(.+?)\s{2,}(.+)', line)
            if match:
                category, setting = match.groups()
                settings[category.strip()] = setting
    return settings


def filter_info_7():
    file = open(".\\logs\\result7.txt", "r")
    # Initialize dictionaries to store settings
    settings = {}
    for line in file:
        line = remove_extra_spaces(line.strip().replace(":", ""))
        parts = line.split()
        key = " ".join(parts[:-1])
        settings[key] = parts[-1]
    # Iterate over the lines and extract settings
    return settings


def filter_info_8():
    file = open(".\\logs\\result8.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            value = ' '.join(parts[2:]).replace(" ", "")
            settings[key] = value
    except:
        pass
    return settings


def filter_info_9():
    file = open(".\\logs\\result9.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def filter_info_10():
    file = open(".\\logs\\result10.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def filer_info_11():
    file = open(".\\logs\\result11.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def filer_info_registry(filename):
    file = open(filename, "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def filter_info_13():
    file = open(".\\logs\\result13.txt", "r")
    client_settings = []
    service_settings = []

    settings = {}
    try:
        parts = file.read().strip().split("HKEY_LOCAL_MACHINE")

        # Process the first part (Client)
        client_part = parts[1].strip().split("\n")
        for line in client_part[1:]:
            client_settings.append(line.strip())

        # Process the second part (Service)
        service_part = parts[2].strip().split("\n")
        for line in service_part[1:]:
            service_settings.append(line.strip())

        for line in client_settings:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = "Client " + parts[0]
            settings[key] = parts[-1]
        for line in service_settings:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            key = "Service " + parts[0]
            settings[key] = parts[-1]
    except:
        pass
    return settings


def filter_info_4():
    file = open(".\\logs\\result4.txt", "r")
    settings = {}
    try:
        for line in file:
            line = remove_extra_spaces(line.strip())
            parts = line.split()
            if parts[0].startswith("Account"):
                key = parts[0] + " " + parts[1]
            else:
                key = parts[0]
            settings[key] = parts[2]
    except:
        pass
    return settings


def filter_info_secpol(path):
    file = open(path, "r")
    settings = {}
    for line in file:
        line = remove_extra_spaces(line)
        line = line.strip()
        array_line = line.split("=")
        settings[array_line[0].strip()] = array_line[1].strip()
    return settings
