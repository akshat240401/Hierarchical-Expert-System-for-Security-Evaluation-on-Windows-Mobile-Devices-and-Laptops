import winreg
import subprocess
import numpy as np
from sklearn.preprocessing import LabelEncoder

def get_installed_software():
    software_list = []
    for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        try:
            key = winreg.OpenKey(hkey, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                subkey = winreg.EnumKey(key, i)
                subkey_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" + "\\" + subkey
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

def encode_installed_software(software_list):
    le = LabelEncoder()
    software_list_encoded = le.fit_transform(software_list)
    return software_list_encoded

def encode_firewall_rules(firewall_rules):
    firewall_rules_encoded = np.array([1 if "AllowInbound" in firewall_rules else 0,
                                       1 if "BlockOutbound" in firewall_rules else 0])
    return firewall_rules_encoded

def encode_password_policy(password_policy):
    password_length = 1 if 'Minimum password length' in password_policy else 0
    password_expires = 1 if 'Password expires' in password_policy else 0
    password_policy_encoded = np.array([password_length, password_expires])
    return password_policy_encoded

def collect_and_encode_data():
    installed_software = get_installed_software()
    firewall_rules = get_firewall_rules()
    password_policy = get_password_policy()

    installed_software_encoded = encode_installed_software(installed_software)
    firewall_rules_encoded = encode_firewall_rules(firewall_rules)
    password_policy_encoded = encode_password_policy(password_policy)

    # Combine all features into a single array
    X = np.hstack([installed_software_encoded[:2], firewall_rules_encoded, password_policy_encoded])
    return X

if __name__ == "__main__":
    data = collect_and_encode_data()
    print(data)
