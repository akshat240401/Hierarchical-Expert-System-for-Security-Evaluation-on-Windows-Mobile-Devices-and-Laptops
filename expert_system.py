from experta import *
from data_collection import *

class Score(Fact):
    def __init__(self, value):
        self.value = value
    pass

class SecurityEvaluation(KnowledgeEngine):

    __slots__ = "installed_apps", "firewall_rules", "password_policy", "drivers", "antivirus", "system_updates", "encryption_status"

    def __init__(self, facts):
        self.installed_apps = facts["untrusted_apps"]
        self.drivers = facts["unsigned_drivers"]
        self.password_length = facts["pasword_length"]
        self.password_duration = facts["password_duration"]
        self.logoff_policy = facts["logoff"]
        self.firewall_rules = facts["intact_firewall"]
        self.antivirus = facts["antivirus"]
        self.system_updates = facts["updates"]
        self.encryption_status = facts["encryption"]
        KnowledgeEngine.__init__(self)

    @DefFacts()
    def ES_init(self):
        print("\nInitialising expert system")
        yield Fact(action="check_system")

    @Rule(Fact(action='check_system'), NOT(Fact(apps=W())))
    def apps_metric_init(self):
        self.declare(Fact(apps=self.installed_apps))

    @Rule(Fact(action='check_system'), NOT(Fact(drivers=W())))
    def drivers_metric_init(self):
        self.declare(Fact(drivers=self.drivers))

    @Rule(Fact(action='check_system'), NOT(Fact(password_length=W())))
    def password_length_metric_init(self):
        self.declare(Fact(password_length=self.password_length))

    @Rule(Fact(action='check_system'), NOT(Fact(password_duration=W())))
    def password_duration_metric_init(self):
        self.declare(Fact(password_duration=self.password_duration))

    @Rule(Fact(action='check_system'), NOT(Fact(logoff_policy=W())))
    def password_duration_metric_init(self):
        self.declare(Fact(logoff_policy=self.logoff_policy))

    @Rule(Fact(action='check_system'), NOT(Fact(firewall=W())))
    def firewall_metric_init(self):
        self.declare(Fact(firewall=self.firewall_rules))

    @Rule(Fact(action='check_system'), NOT(Fact(antivirus=W())))
    def antivirus_metric_init(self):
        self.declare(Fact(antivirus=self.antivirus))

    @Rule(Fact(action='check_system'), NOT(Fact(updates=W())))
    def updates_metric_init(self):
        self.declare(Fact(updates=self.system_updates))

    @Rule(Fact(action='check_system'), NOT(Fact(encryption=W())))
    def encryption_metric_init(self):
        self.declare(Fact(encryption=self.encryption_status))

    #Apps score
    @Rule(Fact(action='check_system'), Fact(apps=0))
    def calc_apps_score_one(self):
        self.declare(Fact(apps_score=1.0))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x < 5)), Fact(apps=P(lambda x: x > 0)))
    def calc_apps_score_two(self):
        self.declare(Fact(apps_score=0.75))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x >= 5)), Fact(apps=P(lambda x: x < 10)))
    def calc_apps_score_three(self):
        self.declare(Fact(apps_score=0.50))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x >= 10)))
    def calc_apps_score_four(self):
        self.declare(Fact(apps_score=0.25))

    # driver score
    @Rule(Fact(action='check_system'), Fact(drivers=0))
    def calc_drivers_score_one(self):
        self.declare(Fact(drivers_score=1.0))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x < 5)), Fact(apps=P(lambda x: x > 0)))
    def calc_drivers_score_two(self):
        self.declare(Fact(drivers_score=0.80))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x >= 5)), Fact(apps=P(lambda x: x < 10)))
    def calc_drivers_score_three(self):
        self.declare(Fact(drivers_score=0.60))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x >= 10)), Fact(apps=P(lambda x: x < 15)))
    def calc_drivers_score_four(self):
        self.declare(Fact(drivers_score=0.40))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x >= 15)), Fact(apps=P(lambda x: x < 20)))
    def calc_drivers_score_five(self):
        self.declare(Fact(drivers_score=0.20))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x >= 20)))
    def calc_drivers_score_six(self):
        self.declare(Fact(drivers_score=0.1))

    # Middle layer metrics evaluation
    @Rule(Fact(action='mid_metrics_evaluation'), 
          Fact(apps_score=W()),
          Fact(updates_score=W()),
          NOT(Fact(os_integrity_score=W())))
    def calc_os_integrity_score(self, apps_score, updates_score):
        self.declare(Fact(os_integrity_score=((apps_score + updates_score) / 2)))

    @Rule(Fact(action='mid_metrics_evaluation'), 
          Fact(apps_score=W()),
          Fact(updates_score=W()),
          NOT(Fact(calc_os_integrity_score=W())))
    def calc_os_integrity_score(self, apps_score, updates_score):
        self.declare(Fact(os_integrity_score=((apps_score + updates_score) / 2)))

    @Rule(Fact(action='check_system'), Fact(apps_score=W()), Fact(MATCH.apps_score))
    def test(self, apps_score):
        print(apps_score)
        # self.declare(Fact(encryption=self.encryption_status))

    # @Rule(Fact(action='check_system'))
    # def check_system(self):
    #     self.declare(Fact(integrity_score=self.check_integrity()))
    #     self.declare(Fact(authentication_score=self.check_authentication()))
    #     self.declare(Fact(network_security_score=self.check_network_security()))
    #     self.declare(Fact(driver_signatures_score=self.check_driver_signatures()))
    #     self.declare(Fact(antivirus_score=self.check_antivirus_status()))
    #     self.declare(Fact(updates_score=self.check_system_updates()))
    #     self.declare(Fact(encryption_score=self.check_encryption_status()))

    # def check_integrity(self):
    #     installed_software = get_installed_software()
    #     if self.evaluate_installed_software(installed_software):
    #         return 1.0
    #     return 0.0

    # def check_authentication(self):
    #     password_policy = get_password_policy()
    #     if self.evaluate_password_policy(password_policy):
    #         return 1.0
    #     return 0.0

    # def check_network_security(self):
    #     firewall_rules = get_firewall_rules()
    #     if self.evaluate_firewall_rules(firewall_rules):
    #         return 1.0
    #     return 0.0

    # def check_driver_signatures(self):
    #     signed_drivers, unsigned_drivers = get_driver_signatures()
    #     if len(unsigned_drivers) == 0:
    #         return 1.0
    #     return 0.0

    # def check_antivirus_status(self):
    #     antivirus_name, antivirus_version = get_antivirus_status()
    #     if antivirus_name != "Unknown" and antivirus_version != "0.0":
    #         return 1.0
    #     return 0.0

    # def check_system_updates(self):
    #     updates = get_system_updates()
    #     if len(updates) > 0:
    #         return 1.0
    #     return 0.0

    # def check_encryption_status(self):
    #     if get_encryption_status():
    #         return 1.0
    #     return 0.0

    # def evaluate_installed_software(self, software_list):
    #     vulnerable_software = ["Adobe Flash Player", "Java 6", "Java 7", "QuickTime", "RealPlayer", "VLC Media Player"]
    #     for software in software_list:
    #         if software in vulnerable_software:
    #             return False
    #     return True

    # def evaluate_password_policy(self, policy):
    #     min_password_length = 'Minimum password length'
    #     password_expires = 'Maximum password age'
        
    #     policy_lines = policy.split('\n')
    #     policy_dict = {}
    #     for line in policy_lines:
    #         if ':' in line:
    #             key, value = line.split(':', 1)
    #             policy_dict[key.strip()] = value.strip()
        
    #     if min_password_length in policy_dict and int(policy_dict[min_password_length]) >= 8:
    #         password_length_ok = True
    #     else:
    #         password_length_ok = False
        
    #     if password_expires in policy_dict and int(policy_dict[password_expires]) <= 90:
    #         password_expires_ok = True
    #     else:
    #         password_expires_ok = False
        
    #     return password_length_ok and password_expires_ok

    # def evaluate_firewall_rules(self, rules):
    #     essential_rules = ["AllowInbound", "BlockOutbound", "DefaultInboundAction", "DefaultOutboundAction"]
    #     for rule in essential_rules:
    #         if rule not in rules:
    #             return False
    #     return True


facts = get_facts()
engine = SecurityEvaluation(facts)
engine.reset()
# engine.declare(Fact(action='check_system'))
engine.run()
# X = collect_and_encode_data()
# print("Collected Data:", X)

# integrity_score = engine.check_integrity()
# authentication_score = engine.check_authentication()
# network_security_score = engine.check_network_security()
# driver_signatures_score = engine.check_driver_signatures()
# antivirus_score = engine.check_antivirus_status()
# updates_score = engine.check_system_updates()
# encryption_score = engine.check_encryption_status()

# overall_score = (integrity_score + authentication_score + network_security_score + driver_signatures_score + antivirus_score + updates_score + encryption_score) / 7.0
# print("Overall Security Score:", overall_score)
