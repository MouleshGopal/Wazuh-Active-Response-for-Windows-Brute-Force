Wazuh Active Response for Windows Brute Force

## 📌 Overview
This project extends **Wazuh Active Response** to handle brute‑force login attempts on **Windows servers**.  
By default, Wazuh expects the source IP address to be reported in the `data.srcip` field. While this works on Linux logs, Windows Event Logs report the IP address in a different field: `data.win.eventdata.ipAddress`.  

This repository provides the necessary **custom rules, decoders, and an executable active response script** to bridge that gap. With this setup, 
Wazuh can automatically detect failed login attempts (Event ID 4625) and block the offending IP address on Windows.

---

## 📂 Repository Contents
- **Custom Decoder.txt** → Defines how Wazuh parses Windows Event Logs to extract the IP address field.  
- **Custom Rules.txt** → Contains detection rules for failed login attempts (Event ID 4625).  
- **Windows-ip-block.py** → Python script that blocks the source IP using Windows Firewall.  

---

## ⚙️ Prerequisites
- Wazuh Manager (Linux/Ubuntu).  
- Wazuh Agent installed on Windows.  
- Python 3.x installed on Windows.  
- **PyInstaller** (to convert the Python script into an executable).  
- Administrative privileges on Windows (required for firewall modifications).  

---

## 🚀 Setup Instructions

### 1. Convert Python Script to Executable
Open **Windows PowerShell** and run:
```powershell
pip install pyinstaller
pyinstaller --onefile Windows-ip-block.py
```
The `.exe` file will be created in the `dist` folder.

---

### 2. Deploy Rules and Decoders (Wazuh Manager)
Copy the provided files into the Wazuh Manager configuration:

```bash
# Rules
sudo cp Custom\ Rules.txt /var/ossec/etc/rules/local_rules.xml

# Decoders
sudo cp Custom\ Decoder.txt /var/ossec/etc/decoders/local_decoder.xml
```

Restart Wazuh Manager:
```bash
sudo systemctl restart wazuh-manager
```

---

### 3. Place Executable in Agent Directory (Windows)
Copy the generated `.exe` file into:
```
C:\Program Files (x86)\ossec-agent\active-response\bin\
```

Grant **Full Control permissions** to the executable:
- Right‑click → Properties → Security → Edit → Allow Full Control.  
- Ensure the **Local System account** has full control, since Wazuh runs under Local System.

---

### 4. Configure Active Response (Wazuh Manager)
Edit the `ossec.conf`:
```xml
<command> 
<name>windows_ip_block</name> 
<executable>windows_ip_block.exe</executable> 
<expect>command,srcip</expect> 
<timeout_allowed>yes</timeout_allowed>  
</command> 
 
<active-response>   
<disabled>no</disabled>   
<command>windows_ip_block</command>   
<location>local</location> 
<rules_id>60122</rules_id>    
<timeout>600</timeout>  
</active-response>
```

Restart the agent service:
```powershell
net stop wazuh-agent
net start wazuh-agent
```

---

## ✅ Verification
1. Trigger failed login attempts on the Windows server (Event ID **4625**).  
2. Confirm logs are visible in the **Wazuh Dashboard GUI**.  
3. Check **active response logs** to verify execution of the `.exe` file.  
4. Ensure the attacker’s IP is blocked in Windows Firewall:
```powershell
netsh advfirewall firewall show rule name=all
```

---

## 🎯 Why This Process Is Needed
- **Linux logs** → Report source IP in `data.srcip`.  
- **Windows logs** → Report source IP in `data.win.eventdata.ipAddress`.  
- Without custom decoders and rules, Wazuh cannot correctly identify the source IP in Windows logs.  
- This solution ensures Wazuh can parse Windows Event Logs and automatically block brute‑force sources.
