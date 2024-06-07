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
        # List of known vulnerable software
        vulnerable_software = ["Adobe Flash Player", "Java 6", "Java 7", "QuickTime", "RealPlayer", "VLC Media Player"]
        for software in software_list:
            if software in vulnerable_software:
                return False
        return True

    def evaluate_password_policy(self, policy):
        # Ensure these match the actual policy names on your system
        if 'Minimum password length' in policy and 'Password expires' in policy:
            return True
        return False

    def evaluate_firewall_rules(self, rules):
        # Ensure these match the actual rules relevant to your system
        essential_rules = ["AllowInbound", "BlockOutbound", "DefaultInboundAction", "DefaultOutboundAction"]
        for rule in essential_rules:
            if rule not in rules:
                return False
        return True

# Define the engine
engine = SecurityEvaluation()

# Define the rules
engine.reset()  # Prepare the engine for the execution.
engine.declare(Fact(action='check_system'))
engine.run()  # Run it!

# Collect real data
X = collect_and_encode_data()

# Convert the data to PyTorch tensors
X_tensor = torch.tensor(X, dtype=torch.float32).view(1, -1)  # Reshape to 1 sample with multiple features
# Ensure this label aligns with your actual data; it represents the security status
y_tensor = torch.tensor([1], dtype=torch.float32)  # Example label (1 for secure, 0 for insecure)

# Define a simple neural network
class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.fc1 = nn.Linear(X_tensor.shape[1], 5)  # Adjust the input size to match the number of features
        self.fc2 = nn.Linear(5, 1)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.sigmoid(self.fc2(x))
        return x

# Create the model
model = Net()

# Define loss and optimizer
criterion = nn.BCELoss()
optimizer = optim.SGD(model.parameters(), lr=0.01)

# Training loop
for epoch in range(1000):
    optimizer.zero_grad()
    outputs = model(X_tensor)
    loss = criterion(outputs, y_tensor.view(-1, 1))
    loss.backward()
    optimizer.step()

# Save the model
torch.save(model.state_dict(), 'model.pth')

# Load the trained model
model = Net()
model.load_state_dict(torch.load('model.pth'))

# Evaluate new data (use the same X_tensor for demonstration)
prediction = model(X_tensor)
print(prediction.item())
