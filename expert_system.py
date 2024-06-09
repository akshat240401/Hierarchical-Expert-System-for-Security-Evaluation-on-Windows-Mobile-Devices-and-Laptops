from experta import *
from data_collection import get_installed_software, get_firewall_rules, get_password_policy, get_driver_signatures, get_antivirus_status, get_system_updates, get_encryption_status, collect_and_encode_data

class SecurityEvaluation(KnowledgeEngine):

    __slots__ = "installed_apps", "firewall_rules", "password_policy", "drivers", "antivirus", "system_updates", "encryption_status"

    def __init__(self, installed_apps, firewall_rules, password_policy, drivers, antivirus, system_updates, encryption_status):
        self.installed_apps = installed_apps
        self.firewall_rules = firewall_rules
        self.password_policy = password_policy
        self.drivers = drivers
        self.antivirus = antivirus
        self.system_updates = system_updates
        self.encryption_status = encryption_status
        KnowledgeEngine.__init__(self)

    @DefFacts()
    def ES_init(self):
        print("Initialising expert sytem")
        yield Fact(action="check_system")

    @Rule(Fact(action='check_system'), NOT(Fact(apps=W())), salience=1)
    def check_system(self):
        self.declare(Fact(apps=self.installed_apps))

    @Rule(Fact(action='check_system'), NOT(Fact(firewall=W())))
    def check_system(self):
        self.declare(Fact(firewall=self.firewall_rules))

    @Rule(Fact(action='check_system'), NOT(Fact(pasword=W())))
    def check_system(self):
        self.declare(Fact(pasword=self.password_policy))

    @Rule(Fact(action='check_system'), NOT(Fact(drivers=W())))
    def check_system(self):
        self.declare(Fact(drivers=self.drivers))

    @Rule(Fact(action='check_system'), NOT(Fact(antivirus=W())))
    def check_system(self):
        self.declare(Fact(antivirus=self.antivirus))

    @Rule(Fact(action='check_system'), NOT(Fact(updates=W())))
    def check_system(self):
        self.declare(Fact(updates=self.system_updates))

    @Rule(Fact(action='check_system'), NOT(Fact(encryption=W())))
    def check_system(self):
        self.declare(Fact(encryption=self.encryption_status))

    #Apps score
    @Rule(Fact(action='check_system'), Fact(apps=0))
    def check_system(self):
        self.declare(Fact(apps_score=1.0))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x < 5)), Fact(apps=P(lambda x: x > 0)))
    def check_system(self):
        self.declare(Fact(apps_score=0.75))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x >= 5)), Fact(apps=P(lambda x: x < 10)))
    def check_system(self):
        self.declare(Fact(apps_score=0.50))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x >= 10)))
    def check_system(self):
        self.declare(Fact(apps_score=0.25))

    # driver score
    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x >= 10)))
    def check_system(self):
        self.declare(Fact(apps_score=0.25))

    @Rule(Fact(action='check_system'))
    def check_system(self):
        self.declare(Fact(integrity_score=self.check_integrity()))
        self.declare(Fact(authentication_score=self.check_authentication()))
        self.declare(Fact(network_security_score=self.check_network_security()))
        self.declare(Fact(driver_signatures_score=self.check_driver_signatures()))
        self.declare(Fact(antivirus_score=self.check_antivirus_status()))
        self.declare(Fact(updates_score=self.check_system_updates()))
        self.declare(Fact(encryption_score=self.check_encryption_status()))

    def check_integrity(self):
        installed_software = get_installed_software()
        if self.evaluate_installed_software(installed_software):
            return 1.0
        return 0.0

    def check_authentication(self):
        password_policy = get_password_policy()
        if self.evaluate_password_policy(password_policy):
            return 1.0
        return 0.0

    def check_network_security(self):
        firewall_rules = get_firewall_rules()
        if self.evaluate_firewall_rules(firewall_rules):
            return 1.0
        return 0.0

    def check_driver_signatures(self):
        signed_drivers, unsigned_drivers = get_driver_signatures()
        if len(unsigned_drivers) == 0:
            return 1.0
        return 0.0

    def check_antivirus_status(self):
        antivirus_name, antivirus_version = get_antivirus_status()
        if antivirus_name != "Unknown" and antivirus_version != "0.0":
            return 1.0
        return 0.0

    def check_system_updates(self):
        updates = get_system_updates()
        if len(updates) > 0:
            return 1.0
        return 0.0

    def check_encryption_status(self):
        if get_encryption_status():
            return 1.0
        return 0.0

    def evaluate_installed_software(self, software_list):
        vulnerable_software = ["Adobe Flash Player", "Java 6", "Java 7", "QuickTime", "RealPlayer", "VLC Media Player"]
        for software in software_list:
            if software in vulnerable_software:
                return False
        return True

    def evaluate_password_policy(self, policy):
        min_password_length = 'Minimum password length'
        password_expires = 'Maximum password age'
        
        policy_lines = policy.split('\n')
        policy_dict = {}
        for line in policy_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                policy_dict[key.strip()] = value.strip()
        
        if min_password_length in policy_dict and int(policy_dict[min_password_length]) >= 8:
            password_length_ok = True
        else:
            password_length_ok = False
        
        if password_expires in policy_dict and int(policy_dict[password_expires]) <= 90:
            password_expires_ok = True
        else:
            password_expires_ok = False
        
        return password_length_ok and password_expires_ok

    def evaluate_firewall_rules(self, rules):
        essential_rules = ["AllowInbound", "BlockOutbound", "DefaultInboundAction", "DefaultOutboundAction"]
        for rule in essential_rules:
            if rule not in rules:
                return False
        return True



engine = SecurityEvaluation()
engine.reset()
# engine.declare(Fact(action='check_system'))
engine.run()
X = collect_and_encode_data()
print("Collected Data:", X)

integrity_score = engine.check_integrity()
authentication_score = engine.check_authentication()
network_security_score = engine.check_network_security()
driver_signatures_score = engine.check_driver_signatures()
antivirus_score = engine.check_antivirus_status()
updates_score = engine.check_system_updates()
encryption_score = engine.check_encryption_status()

overall_score = (integrity_score + authentication_score + network_security_score + driver_signatures_score + antivirus_score + updates_score + encryption_score) / 7.0
print("Overall Security Score:", overall_score)
