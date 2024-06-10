from experta import *
from data_collection import *

class SecurityEvaluation(KnowledgeEngine):

    __slots__ = "installed_apps", "firewall_rules", "password_policy", "drivers", "antivirus", "system_updates", "encryption_status", "recommendations", "issues"

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
        self.recommendations = ""
        self.issues = ""
        KnowledgeEngine.__init__(self)

    @DefFacts()
    def ES_init(self):
        print("INITIALIZING EXPERT SYSTEM\n")
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
        # print("duration" + str(self.password_duration))
        self.declare(Fact(password_duration=self.password_duration))

    @Rule(Fact(action='check_system'), NOT(Fact(logoff_policy=W())))
    def logoff_policy_metric_init(self):
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
        print("APPLICATION SECURITY RATING COMPLETE\n")
        self.declare(Fact(apps_score=1.0))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x < 5)), Fact(apps=P(lambda x: x > 0)))
    def calc_apps_score_two(self):
        print("APPLICATION SECURITY RATING COMPLETE\n")
        self.issues += "Potentially dangerous applications installed on device\n"
        self.recommendations += "Uninstall dangerous applications from devic\n"
        self.declare(Fact(apps_score=0.75))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x >= 5)), Fact(apps=P(lambda x: x < 10)))
    def calc_apps_score_three(self):
        print("APPLICATION SECURITY RATING COMPLETE\n")
        self.issues += "Potentially dangerous applications installed on device\n"
        self.recommendations += "Uninstall dangerous applications from device\n"
        self.declare(Fact(apps_score=0.50))

    @Rule(Fact(action='check_system'), Fact(apps=P(lambda x: x >= 10)))
    def calc_apps_score_four(self):
        print("APPLICATION SECURITY RATING COMPLETE\n")
        self.issues += "Potentially dangerous applications installed on device\n"
        self.recommendations += "Uninstall dangerous applications from device\n"
        self.declare(Fact(apps_score=0.25))

    # driver score
    @Rule(Fact(action='check_system'), Fact(drivers=0))
    def calc_drivers_score_one(self):
        print("DEVICE DRIVERS SECURITY RATING COMPLETE\n")
        self.declare(Fact(drivers_score=1.0))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x < 5)), Fact(drivers=P(lambda x: x > 0)))
    def calc_drivers_score_two(self):
        print("DEVICE DRIVERS SECURITY RATING COMPLETE\n")
        self.issues += "Unsigned drivers installed on device\n"
        self.recommendations += "Review drivers for malicious activity and update drivers to signed versions\n"
        self.declare(Fact(drivers_score=0.80))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x >= 5)), Fact(drivers=P(lambda x: x < 10)))
    def calc_drivers_score_three(self):
        print("DEVICE DRIVERS SECURITY RATING COMPLETE\n")
        self.issues += "Unsigned drivers installed on device\n"
        self.recommendations += "Review drivers for malicious activity and update drivers to signed versions\n"
        self.declare(Fact(drivers_score=0.60))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x >= 10)), Fact(drivers=P(lambda x: x < 15)))
    def calc_drivers_score_four(self):
        print("DEVICE DRIVERS SECURITY RATING COMPLETE\n")
        self.issues += "Unsigned drivers installed on device\n"
        self.recommendations += "Review drivers for malicious activity and update drivers to signed versions\n"
        self.declare(Fact(drivers_score=0.40))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x >= 15)), Fact(drivers=P(lambda x: x < 20)))
    def calc_drivers_score_five(self):
        print("DEVICE DRIVERS SECURITY RATING COMPLETE\n")
        self.issues += "Unsigned drivers installed on device\n"
        self.recommendations += "Review drivers for malicious activity and update drivers to signed versions\n"
        self.declare(Fact(drivers_score=0.20))

    @Rule(Fact(action='check_system'), Fact(drivers=P(lambda x: x >= 20)))
    def calc_drivers_score_six(self):
        print("DEVICE DRIVERS SECURITY RATING COMPLETE\n")
        self.issues += "Unsigned drivers installed on device\n"
        self.recommendations += "Review drivers for malicious activity and update drivers to signed versions\n"
        self.declare(Fact(drivers_score=0.1))

    # password score
    @Rule(Fact(action='check_system'), Fact(logoff_policy=True))
    def calc_logoff_score_one(self):
        self.declare(Fact(logoff_score=1.0))

    @Rule(Fact(action='check_system'), Fact(logoff_policy=False))
    def calc_logoff_score_two(self):
        self.issues += "User logoff on timeout not specified\n"
        self.recommendations += "Specify a timeout limit for automatic user logoff on device\n"
        self.declare(Fact(logoff_score=0.0))

    @Rule(Fact(action='check_system'), Fact(password_length=P(lambda x: x >= 8)))
    def calc_pass_length_score_one(self):
        self.declare(Fact(pass_length_score=1.0))

    @Rule(Fact(action='check_system'), Fact(password_length=P(lambda x: x < 8)))
    def calc_pass_length_score_two(self):
        self.issues += "Password length too short\n"
        self.recommendations += "Increase the minimum password length\n"
        self.declare(Fact(pass_length_score=0.0))

    @Rule(Fact(action='check_system'), Fact(password_duration=P(lambda x: x < 90)))
    def calc_pass_duration_score_one(self):
        self.declare(Fact(pass_duration_score=1.0))

    @Rule(Fact(action='check_system'), Fact(password_duration=P(lambda x: x >= 90)))
    def calc_pass_duration_score_two(self):
        self.issues += "Maximum time before password change required is too long\n"
        self.recommendations += "Decrease the maximum time required for password change\n"
        self.declare(Fact(pass_duration_score=0.0))

    @Rule(Fact(action='check_system'), 
          Fact(pass_length_score=MATCH.pass_length_score),
          Fact(pass_duration_score=MATCH.pass_duration_score),
          Fact(logoff_policy=MATCH.logoff_policy),
          NOT(Fact(password_score=W())))
    def calc_password_score(self, pass_length_score, pass_duration_score, logoff_policy):
        print("PASSWORD POLICY SECURITY RATING COMPLETE\n")
        self.declare(Fact(password_score=(pass_length_score + pass_duration_score + logoff_policy)/3))
    
    # firewall score
    @Rule(Fact(action='check_system'), Fact(firewall=True))
    def calc_firewall_score_one(self):
        print("FIREWALL RULES SECURITY RATING COMPLETE\n")
        self.declare(Fact(firewall_score=1.0))

    @Rule(Fact(action='check_system'), Fact(firewall=False))
    def calc_firewall_score_two(self):
        print("FIREWALL RULES SECURITY RATING COMPLETE\n")
        self.issues += "Insecure firewall rules detected\n"
        self.recommendations += "Increase security in firewall rules\n"
        self.declare(Fact(firewall_score=0.0))
    
    # antivirus score
    @Rule(Fact(action='check_system'), Fact(antivirus=True))
    def calc_antivirus_score_one(self):
        print("ANTIVIRUS SECURITY RATING COMPLETE\n")
        self.declare(Fact(antivirus_score=1.0))

    @Rule(Fact(action='check_system'), Fact(antivirus=False))
    def calc_antivirus_score_two(self):
        print("ANTIVIRUS SECURITY RATING COMPLETE\n")
        self.issues += "No antivirus detected\n"
        self.recommendations += "Install an antivirus on the system\n"
        self.declare(Fact(antivirus_score=0.0))

    # updates score
    @Rule(Fact(action='check_system'), Fact(updates=P(lambda x: x > 0)))
    def calc_updates_score_one(self):
        print("UPDATE LOGS SECURITY RATING COMPLETE\n")
        self.declare(Fact(updates_score=1.0))

    @Rule(Fact(action='check_system'), Fact(updates=0))
    def calc_updates_score_two(self):
        print("UPDATE LOGS SECURITY RATING COMPLETE\n")
        self.issues += "Nno security updates have been installed\n"
        self.recommendations += "Install the latest security updates from microsoft\n"
        self.declare(Fact(updates_score=0.0))
    
    # encryption score
    @Rule(Fact(action='check_system'), Fact(encryption=True))
    def calc_encryption_score_one(self):
        print("DRIVE ENCRYPTION SECURITY RATING COMPLETE\n")
        self.declare(Fact(encryption_score=1.0))

    @Rule(Fact(action='check_system'), Fact(encryption=False))
    def calc_encryption_score_two(self):
        print("DRIVE ENCRYPTION SECURITY RATING COMPLETE\n")
        self.issues += "No excryption detected on native drives\n"
        self.recommendations += "Setup a Bitlocker encryption on the native drives\n"
        self.declare(Fact(encryption_score=0.0))

    # Middle layer metrics evaluation
    @Rule(Fact(action='check_system'), 
          Fact(apps_score=MATCH.apps_score),
          Fact(updates_score=MATCH.updates_score),
          Fact(antivirus_score=MATCH.antivirus_score),
          NOT(Fact(os_integrity_score=W())))
    def calc_os_integrity_score(self, apps_score, updates_score, antivirus_score):
        print("CALCULATED OS INTEGRITY METRIC SCORE\n")
        self.declare(Fact(os_integrity_score=((apps_score + updates_score + antivirus_score) / 3)))

    @Rule(Fact(action='check_system'), 
          Fact(firewall_score=MATCH.firewall_score),
          NOT(Fact(network_integrity_score=W())))
    def calc_network_integrity_score(self, firewall_score):
        print("CALCULATED NETWORK INTEGRITY METRIC SCORE\n")
        self.declare(Fact(network_integrity_score=firewall_score))

    @Rule(Fact(action='check_system'), 
          Fact(password_score=MATCH.password_score),
          NOT(Fact(user_auth_score=W())))
    def calc_user_auth_score(self, password_score):
        print("CALCULATED USER AUTHENTICATION METRIC SCORE\n")
        self.declare(Fact(user_auth_score=password_score))

    @Rule(Fact(action='check_system'), 
          Fact(encryption_score=MATCH.encryption_score),
          NOT(Fact(data_protection_score=W())))
    def calc_data_protection_score(self, encryption_score):
        print("CALCULATED DATA PROTECTION METRIC SCORE\n")
        self.declare(Fact(data_protection_score=encryption_score))

    @Rule(Fact(action='check_system'), 
          Fact(drivers_score=MATCH.drivers_score),
          NOT(Fact(device_integrity_score=W())))
    def calc_device_integrity_score(self, drivers_score):
        print("CALCULATED DEVICE INTEGRITY METRIC SCORE\n")
        self.declare(Fact(device_integrity_score=drivers_score))

    # Top layer / Final score evaluation (weighted average)
    @Rule(Fact(action='check_system'), 
          Fact(os_integrity_score=MATCH.os_integrity_score),
          Fact(network_integrity_score=MATCH.network_integrity_score),
          Fact(user_auth_score=MATCH.user_auth_score),
          Fact(data_protection_score=MATCH.data_protection_score),
          Fact(device_integrity_score=MATCH.device_integrity_score))
    def calc_final_security_score(self, 
                                  os_integrity_score,
                                  network_integrity_score,
                                  user_auth_score,
                                  data_protection_score,
                                  device_integrity_score):
        sum = (os_integrity_score * 2) + network_integrity_score + user_auth_score + (data_protection_score * 3) + (device_integrity_score * 3)
        tot_weights = 2 + 1 + 1 + 3 + 3
        final_score = sum / tot_weights
        print("\nFINAL SECURITY SCORE FOR THE DEVICE IS : " + str(final_score))
        print("ISSUES DETECTED : ")
        print(self.issues)
        print("RECOMMENDATIONS TO INCREASE SECURITY ON DEVICE : ")
        print(self.recommendations)

facts = get_facts()
print("EXPERT SYSTEM ==================================")
engine = SecurityEvaluation(facts)
engine.reset()
engine.run()