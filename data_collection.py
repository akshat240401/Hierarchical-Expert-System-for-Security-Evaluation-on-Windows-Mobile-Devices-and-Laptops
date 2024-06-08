import winreg
import subprocess
import numpy as np
# from sklearn.preprocessing import LabelEncoder

def get_installed_software():
    software_list = []
    for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        try:
            key = winreg.OpenKey(hkey, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                subkey = winreg.EnumKey(key, i)
                subkey_path = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" + "\\" + subkey
                subkey_handle = winreg.OpenKey(hkey, subkey_path)
                try:
                    software_list.append(winreg.QueryValueEx(subkey_handle, "DisplayName")[0])
                except FileNotFoundError:
                    continue
        except FileNotFoundError:
            continue
    return software_list

def get_firewall_rules():
    result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], stdout=subprocess.PIPE)
    return result.stdout.decode()

def get_password_policy():
    result = subprocess.run(['net', 'accounts'], stdout=subprocess.PIPE)
    return result.stdout.decode()

def get_driver_signatures():
    print("Fetching device driver info")
    result = subprocess.run(['driverquery', '/v'], stdout=subprocess.PIPE)
    drivers = result.stdout.decode().split('\n')
    d = []
    for k in drivers:
        n = k.split()
        if len(n) > 0:
            d.append([n[0],n[-2]])
    d = d[2:]
    signed_drivers = []
    unsigned_drivers = []
    print("Checking digital signature on device drivers")
    for driver in d:
        name = driver[0]
        path = driver[-1]
        try:
            output = subprocess.check_output(['sigcheck64.exe', '-i', path], stderr=subprocess.STDOUT, shell=True)
            signature = output.decode('utf-8').split('\n')[1]
            if "Signed" not in signature:
                unsigned_drivers.append(name)
            else:
                signed_drivers.append(name)
        except subprocess.CalledProcessError as e:
            # False error raised by subprocess, check as normal
            if "Signed" not in (f"{e.output}"):
                unsigned_drivers.append(name)
            else:
                signed_drivers.append(name)
    return signed_drivers, unsigned_drivers

def get_antivirus_status():
    result = subprocess.run(['wmic', 'antivirusproduct', 'get', 'displayName,productState'], stdout=subprocess.PIPE)
    lines = result.stdout.decode().split('\n')
    if len(lines) > 1:
        antivirus_name = lines[1].strip().split()[0]
        antivirus_version = lines[1].strip().split()[-1]
    else:
        antivirus_name = "Unknown"
        antivirus_version = "0.0"
    return antivirus_name, antivirus_version

def get_system_updates():
    result = subprocess.run(['wmic', 'qfe', 'get', 'HotFixID'], stdout=subprocess.PIPE)
    updates = result.stdout.decode().split('\n')[1:]
    updates = [update.strip() for update in updates if update.strip()]
    return updates

def get_encryption_status():
    result = subprocess.run(['manage-bde', '-status'], stdout=subprocess.PIPE)
    if 'Percentage Encrypted: 100%' in result.stdout.decode():
        return True
    return False

# def encode_installed_software(software_list):
#     le = LabelEncoder()
#     software_list_encoded = le.fit_transform(software_list)
#     return software_list_encoded

# def encode_firewall_rules(firewall_rules):
#     firewall_rules_encoded = np.array([1 if "AllowInbound" in firewall_rules else 0,
#                                        1 if "BlockOutbound" in firewall_rules else 0])
#     return firewall_rules_encoded

# def encode_password_policy(password_policy):
#     password_length = 1 if 'Minimum password length' in password_policy else 0
#     password_expires = 1 if 'Password expires' in password_policy else 0
#     password_policy_encoded = np.array([password_length, password_expires])
#     return password_policy_encoded

def collect_and_encode_data():
    installed_software = get_installed_software()
    firewall_rules = get_firewall_rules()
    password_policy = get_password_policy()
    signed_drivers, unsigned_drivers = get_driver_signatures()
    antivirus_name, antivirus_version = get_antivirus_status()
    system_updates = get_system_updates()
    encryption_status = get_encryption_status()

    # installed_software_encoded = encode_installed_software(installed_software)
    # firewall_rules_encoded = encode_firewall_rules(firewall_rules)
    # password_policy_encoded = encode_password_policy(password_policy)

    antivirus_version_num = float(antivirus_version.replace('.', '')) if antivirus_version != "Unknown" else 0.0

    X = np.hstack([installed_software_encoded[:2], firewall_rules_encoded, password_policy_encoded,
                   len(signed_drivers), len(unsigned_drivers), antivirus_version_num,
                   len(system_updates), int(encryption_status)])
    return X


def get_facts():
    print(get_encryption_status())
    # installed_software = get_installed_software()
    # firewall_rules = get_firewall_rules()
    # password_policy = get_password_policy()
    # signed_drivers, unsigned_drivers = get_driver_signatures()
    # antivirus_name, antivirus_version = get_antivirus_status()
    # system_updates = get_system_updates()
    # encryption_status = get_encryption_status()


if __name__ == "__main__":
    data = get_facts()
    print(data)




# signed and unsigned drivers
# registry
# updates
