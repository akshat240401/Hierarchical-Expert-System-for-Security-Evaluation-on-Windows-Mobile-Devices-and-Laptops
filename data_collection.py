import winreg

import subprocess

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

installed_software = get_installed_software()
print(installed_software)

def get_firewall_rules():
    result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], stdout=subprocess.PIPE)
    return result.stdout.decode()

firewall_rules = get_firewall_rules()
print(firewall_rules)

def get_password_policy():
    result = subprocess.run(['net', 'accounts'], stdout=subprocess.PIPE)
    return result.stdout.decode()

password_policy = get_password_policy()
print(password_policy)