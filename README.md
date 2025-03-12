# SNMP Demo

This repository demonstrates how to use **SNMP (Simple Network Management Protocol)** in a Node.js application. Follow the steps below to **set up the SNMP daemon in WSL**, install dependencies, and run the application.

---

## 🚀 Setup Instructions

### **1️⃣ Install SNMP Daemon in WSL**
To use SNMP in WSL, you need to install and configure the `snmpd` service.

#### **Step 1: Install SNMP Daemon**
Open your WSL terminal and run:
```bash
sudo apt update && sudo apt install snmpd -y
Step 2: Configure SNMP Daemon
Open the SNMP configuration file:

sudo nano /etc/snmp/snmpd.conf
Modify the file to allow access from localhost. Add or update the following lines:
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1


# rocommunity: a SNMPv1/SNMPv2c read-only access community name
#   arguments:  community [default|hostname|network/bits] [oid | -V view]

# Read-only access to everyone to the systemonly view
rocommunity public default
rwcommunity private default


# Define trap community
trapsink localhost:16200
# or for SNMPv2c
trap2sink localhost:16200
trapcommunity public
# Enable sending coldStart traps (when the SNMP agent starts)
trap_enable 1

Save the file (CTRL + X, then Y and Enter).
Step 3: Restart SNMP Daemon
After updating the configuration, restart the SNMP service:

sudo systemctl restart snmpd

To check if it's running:
sudo systemctl status snmpd

It should show "active (running)".

2️⃣ Install Node.js Dependencies
After setting up SNMP, install the required Node.js dependencies for this app.

Step 1: Install Node.js and npm (if not installed)

sudo apt install nodejs npm -y
Step 2: Clone this repository

git clone https://github.com/your-username/snmp-demo.git
cd snmp-demo

Step 3: Install npm packages
npm install

3️⃣ Start the Application
Once everything is set up, start the app using:
node app.js

This will run the Node.js application, which interacts with SNMP.

🛠 Troubleshooting
Check if SNMP Daemon is Running

sudo systemctl status snmpd

If not running, restart it:
sudo systemctl restart snmpd
