import wmi
import winreg
import subprocess
import numpy as np
from sklearn.preprocessing import LabelEncoder

def get_installed_software():
    try:
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
    except Exception as e:
        print(f"Error fetching installed software: {e}")
        return []

def get_firewall_rules():
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], stdout=subprocess.PIPE)
        return result.stdout.decode()
    except Exception as e:
        print(f"Error fetching firewall rules: {e}")
        return ""

def get_password_policy():
    try:
        result = subprocess.run(['net', 'accounts'], stdout=subprocess.PIPE)
        return result.stdout.decode()
    except Exception as e:
        print(f"Error fetching password policy: {e}")
        return ""

def get_driver_signatures():
    try:
        c = wmi.WMI()
        signed_drivers = []
        unsigned_drivers = []
        for driver in c.Win32_PnPSignedDriver():
            if hasattr(driver, 'SignatureStatus') and driver.SignatureStatus == 'Signed':
                signed_drivers.append(driver.DeviceName)
            else:
                unsigned_drivers.append(driver.DeviceName)
        return signed_drivers, unsigned_drivers
    except Exception as e:
        print(f"Error fetching driver signatures: {e}")
        return [], []

def get_antivirus_status():
    try:
        c = wmi.WMI()
        antivirus_list = c.Win32_Product(Name="Windows Defender")
        if antivirus_list:
            antivirus = antivirus_list[0]
            return antivirus.Name, antivirus.Version
        else:
            return "Unknown", "0.0"
    except Exception as e:
        print(f"Error fetching antivirus status: {e}")
        return "Unknown", "0.0"

def get_system_updates():
    try:
        result = subprocess.run(['wmic', 'qfe', 'list'], stdout=subprocess.PIPE)
        updates = result.stdout.decode().split('\n')
        return updates
    except Exception as e:
        print(f"Error fetching system updates: {e}")
        return []

def get_encryption_status():
    try:
        result = subprocess.run(['manage-bde', '-status'], stdout=subprocess.PIPE)
        return 'Fully Encrypted' in result.stdout.decode()
    except Exception as e:
        print(f"Error fetching encryption status: {e}")
        return False

def encode_installed_software(software_list):
    le = LabelEncoder()
    try:
        software_list_encoded = le.fit_transform(software_list)
    except Exception as e:
        print(f"Error encoding software list: {e}")
        software_list_encoded = []
    return software_list_encoded

def encode_firewall_rules(firewall_rules):
    try:
        firewall_rules_encoded = np.array([1 if "AllowInbound" in firewall_rules else 0,
                                           1 if "BlockOutbound" in firewall_rules else 0,
                                           1 if "DefaultInboundAction" in firewall_rules else 0,
                                           1 if "DefaultOutboundAction" in firewall_rules else 0])
    except Exception as e:
        print(f"Error encoding firewall rules: {e}")
        firewall_rules_encoded = np.array([])
    return firewall_rules_encoded

def encode_password_policy(password_policy):
    try:
        password_length = 1 if 'Minimum password length' in password_policy else 0
        password_expires = 1 if 'Password expires' in password_policy else 0
        password_policy_encoded = np.array([password_length, password_expires])
    except Exception as e:
        print(f"Error encoding password policy: {e}")
        password_policy_encoded = np.array([])
    return password_policy_encoded

def collect_and_encode_data():
    installed_software = get_installed_software()
    firewall_rules = get_firewall_rules()
    password_policy = get_password_policy()
    signed_drivers, unsigned_drivers = get_driver_signatures()
    antivirus_name, antivirus_version = get_antivirus_status()
    system_updates = get_system_updates()
    encryption_status = get_encryption_status()

    installed_software_encoded = encode_installed_software(installed_software)
    firewall_rules_encoded = encode_firewall_rules(firewall_rules)
    password_policy_encoded = encode_password_policy(password_policy)

    antivirus_version_num = float(antivirus_version.replace('.', '')) if antivirus_version != "Unknown" else 0.0

    X = np.hstack([
        installed_software_encoded[:2],
        firewall_rules_encoded,
        password_policy_encoded, 
        len(signed_drivers),
        len(unsigned_drivers),
        antivirus_version_num,
        len(system_updates),
        int(encryption_status)
    ])

    if len(X) < 13:
        X = np.pad(X, (0, 13 - len(X)), 'constant')
    
    return X

if __name__ == "__main__":
    data = collect_and_encode_data()
    print(data)
