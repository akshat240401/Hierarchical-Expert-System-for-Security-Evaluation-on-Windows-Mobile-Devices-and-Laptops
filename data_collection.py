import winreg
import subprocess

def get_installed_software():
    print("Fetching installed software info\n")
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
    print("Fetching installed firewall rules\n")
    result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], stdout=subprocess.PIPE)
    return result.stdout.decode()

def get_password_policy():
    print("Fetching installed password policy info\n")
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
    print("Checking digital signature on device drivers\n")
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
    print("Fetching antivirus info\n")
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
    print("Fetching system updates info\n")
    result = subprocess.run(['wmic', 'qfe', 'get', 'HotFixID'], stdout=subprocess.PIPE)
    updates = result.stdout.decode().split('\n')[1:]
    updates = [update.strip() for update in updates if update.strip()]
    return updates

def get_encryption_status():
    print("Fetching encryption status info\n")
    result = subprocess.run(['manage-bde', '-status'], stdout=subprocess.PIPE)
    if 'Percentage Encrypted: 100%' in result.stdout.decode():
        return True
    return False


def calc_num_untrusted_apps(installed_software):
    print("Calculating number of untrusted apps\n")
    num_of_untrusted_apps = 0
    vulnerable_apps = ["Adobe Flash Player", "Java 6", "Java 7", "QuickTime", "RealPlayer", "VLC Media Player"]
    for app in installed_software:
        if app in vulnerable_apps:
            num_of_untrusted_apps += 1
    return num_of_untrusted_apps

def get_password_policy_params(password_policy):
    print("Extracting password length, duration and logoff policies\n")
    min_password_length = 'Minimum password length'
    password_expires = 'Maximum password age (days)'
    force_logoff = 'Force user logoff how long after time expires?'
    policy_lines = password_policy.split('\n')
    policy_dict = {}
    for line in policy_lines:
        if ':' in line:
            key, value = line.split(':', 1)
            policy_dict[key.strip()] = value.strip()
    password_length = 0
    password_duration = 0
    logoff = True
    if min_password_length in policy_dict:
        password_length = int(policy_dict[min_password_length])
    if password_expires in policy_dict:
        password_duration = int(policy_dict[password_expires])
    if force_logoff in policy_dict and policy_dict[force_logoff] == 'Never':
        logoff = False
    return password_length, password_duration, logoff 

def evaluate_firewall_rules(rules):
    print("Evaluating firewall rules\n")
    essential_rules = ["AllowInbound", "BlockOutbound", "DefaultInboundAction", "DefaultOutboundAction"]
    for rule in essential_rules:
        if rule not in rules:
            return False
    return True


def is_antivirus_active(antivirus_name, antivirus_version):
    print("Checking antivirus\n")
    if antivirus_name != "Unknown" and antivirus_version != "0.0":
        return True
    return False


def get_facts():
    print("DATA ACQUISITION ==============================")
    installed_software = get_installed_software()
    firewall_rules = get_firewall_rules()
    password_policy = get_password_policy()
    signed_drivers, unsigned_drivers = get_driver_signatures()
    antivirus_name, antivirus_version = get_antivirus_status()
    system_updates = get_system_updates()
    encryption_status = get_encryption_status()
    print("DATA PRE-PROCESSING ==============================")
    facts = dict()
    facts["untrusted_apps"] = calc_num_untrusted_apps(installed_software)
    facts["unsigned_drivers"] = len(unsigned_drivers)
    facts["pasword_length"], facts["password_duration"], facts["logoff"] = get_password_policy_params(password_policy)
    facts["intact_firewall"] = evaluate_firewall_rules(firewall_rules)
    facts["antivirus"] = is_antivirus_active(antivirus_name, antivirus_version)
    facts["updates"] = len(system_updates)
    facts["encryption"] = encryption_status
    return facts


if __name__ == "__main__":
    data = get_facts()
    print(data)
