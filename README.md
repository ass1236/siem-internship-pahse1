# siem-internship-pahse1
# Wazuh SIEM Training Lab

## Project Overview
This project demonstrates the deployment and usage of the Wazuh Security Information and Event Management (SIEM) solution in a controlled lab environment. The primary goal is to simulate various cyber attack scenarios and detect them using Wazuh's capabilities combined with Sysmon and native Windows event logs.

The project covers multiple realistic attack scenarios to illustrate how Wazuh can identify and alert on suspicious activities and threats within a network.

## Lab Setup
The lab environment consists of the following components:

- **Wazuh Server:** Installed on Kali Linux, acting as the central SIEM server collecting and analyzing security events.
- **Victim Machine (Windows VM):** Runs Windows with Wazuh agent installed, monitored via Sysmon and native Windows event logs to capture detailed system and security events.
- **Attacker Machine:** An Ubuntu VM used to simulate attacker behaviors and generate attack traffic and actions targeting the victim machine.

## Detection Scenarios
The following security scenarios have been implemented and tested in the lab to showcase Wazuh's detection capabilities:

1. **Brute Force Detection**  
   Detect multiple failed login attempts indicating a brute force attack.

2. **Malware Detection**  
   Identify suspicious processes and behaviors consistent with malware infections.

3. **Data Exfiltration Detection**  
   Monitor unusual data transfers or extraction of sensitive information.

4. **Suspicious Network Activity**  
   Detect abnormal network connections that may indicate reconnaissance or attack.

5. **Phishing Email Detection**  
   Recognize indicators of phishing attempts through email analysis.

6. **Unauthorized Access Attempt**  
   Alert on attempts to access resources without proper authorization.

7. **Suspicious File Download**  
   Detect downloads of potentially malicious files.

8. **Privilege Escalation Attempt**  
   Identify attempts to gain elevated permissions on the system.

9. **Lateral Movement Detection**  
   Track activities related to attackers moving laterally within the network.

10. **Command and Control (C2) Traffic Detection**  
    Detect communication with known or suspected Command and Control servers.

## Conclusion
This lab serves as a practical demonstration of how Wazuh can be effectively used to monitor, detect, and respond to various cyber threats in a networked environment. It highlights the importance of centralized log analysis and endpoint monitoring in a comprehensive security strategy.
