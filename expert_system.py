from experta import *
import subprocess
import winreg
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from data_collection import get_installed_software, get_firewall_rules, get_password_policy, collect_and_encode_data

class SecurityEvaluation(KnowledgeEngine):
    @Rule(Fact(action='check_system'))
    def check_system(self):
        self.declare(Fact(integrity=self.check_integrity()))
        self.declare(Fact(authentication=self.check_authentication()))
        self.declare(Fact(network_security=self.check_network_security()))

    def check_integrity(self):
        installed_software = get_installed_software()
        if self.evaluate_installed_software(installed_software):
            return 'secure'
        return 'insecure'

    def check_authentication(self):
        password_policy = get_password_policy()
        if self.evaluate_password_policy(password_policy):
            return 'secure'
        return 'insecure'

    def check_network_security(self):
        firewall_rules = get_firewall_rules()
        if self.evaluate_firewall_rules(firewall_rules):
            return 'secure'
        return 'insecure'

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
engine.declare(Fact(action='check_system'))
engine.run()

X = collect_and_encode_data()
X_tensor = torch.tensor(X, dtype=torch.float32).view(1, -1)
y_tensor = torch.tensor([1], dtype=torch.float32)

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
criterion = nn.BCELoss()
optimizer = optim.SGD(model.parameters(), lr=0.01)

for epoch in range(1000):
    optimizer.zero_grad()
    outputs = model(X_tensor)
    loss = criterion(outputs, y_tensor.view(-1, 1))
    loss.backward()
    optimizer.step()

torch.save(model.state_dict(), 'model.pth')

model = Net()
model.load_state_dict(torch.load('model.pth'))
prediction = model(X_tensor)
print(prediction.item())