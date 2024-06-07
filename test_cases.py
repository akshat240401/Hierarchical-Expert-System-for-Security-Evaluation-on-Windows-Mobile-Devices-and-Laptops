import torch
import torch.nn as nn
import numpy as np
from data_collection import encode_installed_software, encode_firewall_rules, encode_password_policy

def run_test_case(test_name, installed_software, firewall_rules, password_policy, signed_drivers, unsigned_drivers, antivirus_version, system_updates, encryption_status):
    print(f"Running {test_name}...")

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

    X_numeric = [float(i) if isinstance(i, (int, float)) else 0 for i in X]
    X_tensor = torch.tensor(X_numeric, dtype=torch.float32).view(1, -1)

    class Net(nn.Module):
        def __init__(self):
            super(Net, self).__init__()
            self.fc1 = nn.Linear(X_tensor.shape[1], 5)
            self.fc2 = nn.Linear(5, 1)

        def forward(self, x):
            x = torch.relu(self.fc1(x))
            x = torch.sigmoid(self.fc2(x))
            return x

    model = Net()
    model.load_state_dict(torch.load('model.pth'))

    prediction = model(X_tensor)
    print(f"{test_name} - Prediction: {prediction.item()}\n")

test_cases = [
    {
        "test_name": "Test Case 1 - Secure Scenario",
        "installed_software": [],
        "firewall_rules": "AllowInbound\nBlockOutbound\nDefaultInboundAction\nDefaultOutboundAction",
        "password_policy": "Minimum password length: 8\nPassword expires: 30",
        "signed_drivers": ["Driver1", "Driver2"],
        "unsigned_drivers": [],
        "antivirus_version": "4.18.2001",
        "system_updates": ["Update1", "Update2"],
        "encryption_status": True
    },
    {
        "test_name": "Test Case 2 - Insecure Scenario",
        "installed_software": ["VLC Media Player"],
        "firewall_rules": "AllowInbound",
        "password_policy": "Minimum password length: 6\nPassword expires: 0",
        "signed_drivers": ["Driver1"],
        "unsigned_drivers": ["Driver2"],
        "antivirus_version": "Unknown",
        "system_updates": [],
        "encryption_status": False
    },
    {
        "test_name": "Test Case 3 - Mixed Scenario",
        "installed_software": [],
        "firewall_rules": "AllowInbound\nDefaultInboundAction",
        "password_policy": "Minimum password length: 8\nPassword expires: 0",
        "signed_drivers": ["Driver1", "Driver2"],
        "unsigned_drivers": [],
        "antivirus_version": "4.18.2001",
        "system_updates": ["Update1"],
        "encryption_status": False
    }
]

for test_case in test_cases:
    run_test_case(**test_case)
