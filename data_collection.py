import winreg

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