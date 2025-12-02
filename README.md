<img width="460" height="460" alt="image" src="https://github.com/user-attachments/assets/942a58cd-28ec-46e5-99d7-9dbe8076b230" />

# 🚨 Incident Response Brute-Force Attack Detection via Microsoft Sentinel

## Overview
This incident response lab demonstrates how to detect and respond to brute force attacks against virtual machines using Microsoft Sentinel and Defender for Endpoint. Create detection rules, investigate incidents, and follow the NIST 800-61 incident response lifecycle.

## Prerequisites
- Access to Azure Portal
- Microsoft Sentinel workspace configured
- Log Analytics workspace attached to Sentinel
- Virtual machines onboarded to Defender for Endpoint (optional: create your own VM)
- Basic understanding of KQL (Kusto Query Language)

## 🧩 Detection Lab Architecture
Virtual machines are onboarded to Microsoft Defender for Endpoint, which forwards login event logs to Microsoft Sentinel. Sentinel uses scheduled query rules to detect brute force attempts and automatically creates incidents when thresholds are exceeded.
## Data Flow

1. Windows/Linux VM
Generates authentication logs (Event ID 4625 for Windows, SSH failures for Linux)

2. Microsoft Defender for Endpoint (MDE)
Receives endpoint telemetry and forwards to Log Analytics.

3. Log Analytics Workspace
Stores DeviceLogonEvents table.

4. Microsoft Sentinel
Runs scheduled KQL rule → triggers alert → creates incident.
<img width="490" height="490" alt="image" src="https://github.com/user-attachments/assets/9f173649-afa4-4d2e-8b49-35bac21dba1c" />

----
## Part 1: Create Alert Rule (Brute Force Attempt Detection)
- Open Microsoft Sentinel
- Go to portal.azure.com
- Search for Microsoft Sentinel
- Open the Sentinel instance attached to the Cyber Range Log Analytics workspace
- Go to:
Analytics → Create → Scheduled query rule

`Design a Sentinel Scheduled Query Rule within Log Analytics that will discover when the same remote IP address has failed to log in to the same local host (Azure VM) 10 times or more within the last 5 hours`

Analytics Rule Settings:
- Enable the Rule
- Mapped the detection rule to relevant MITRE ATT&CK techniques
- Run query every 4 hours
- Lookup data for last 5 hours (can define in query)
- Stop running query after alert is generated == Yes
- Configure Entity Mappings for the Remote IP and DeviceName
- Automatically create an Incident if the rule is triggered
- Group all alerts into a single Incident per 24 hours
- Stop running query after alert is generated (24 hours)

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/5547f412-79e1-4abd-b02c-2cef9b6f8c7d" />
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/e900f1ed-fd9e-497f-9341-755b0c08765b" />
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/3d202e45-0706-4dc9-b695-ca488cb31b10" />
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/6cf7f813-461d-4052-a13a-b524623158ec" />
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/390b6903-1de5-4b98-8b21-42cccad903ba" />
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/92dd822e-179b-4723-a0e4-0ea8bb717547" />
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/6f525f8d-6249-4d5b-ad65-dc3739959597" />
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/fec4ab68-afa1-4e44-a796-b3926bb323cf" />
<img width="500" height="400" alt="image" src="https://github.com/user-attachments/assets/5d0ea0c1-a33a-4f39-bd86-8e5f6f51c929" />

----
## Part 2: Work Incident
- Work your incident to completion and close it out, in accordance with the NIST 800-61: Incident Response Lifecycle
<img width="400" height="326" alt="image" src="https://github.com/user-attachments/assets/297520ba-91fd-4724-bd47-ccb6d23d41ee" />
---

## Preparation
- Document roles, responsibilities, and procedures.
- Ensure tools, systems, and training are in place.

## Detection and Analysis
- Identify and validate the incident.
 Observe the incident and assign it to yourself, set the status to Active
 Investigate the Incident by Actions → Investigate (sometimes takes time for entities to appear)
- Gather relevant evidence and assess impact.
  Observe the different entity mappings and take notes:
    The Brute Force Detection - Josh incident was triggered from 6 different IP addresses against 2 different hosts. <Lists Hosts and IPs>
    Check to make sure none of the IP addresses attempting to brute force the machine actually logged in. 
   Record Findings
<img width="500" height="400" alt="image" src="https://github.com/user-attachments/assets/2a4b21f5-02ed-4ca6-a6f5-e03804339f11" />
<img width="483" height="560" alt="image" src="https://github.com/user-attachments/assets/c7e1e366-5abf-4752-bd54-f97225c29c92" />

"This visualization shows the different entities affected. Windows Target One had enough activity to trigger the alert. The alert also triggered on Threat Hunt Lab, which is another virtual machine. These are the malicious IP addresses that triggered the brute force attacks against the different virtual machines."

`Note: Three different virtual machines were potentially impacted by butre force attempts from 3 different public  IP addresses on the internet `
```
 DeviceName            RemoteIP          ActionType     FailedAttempts 
 windows-target-1     45.136.68.84       LogonFailed         87
 soclab               95.214.55.202      LogonFailed         100
 threat-hunt-lab      95.214.55.202      LogonFailed         77
```
<img width="600" height="600" alt="image" src="https://github.com/user-attachments/assets/082007a0-acc2-41b0-8ffd-95ac6e51b209" />

`Note:I checked to see if any of the IP address attempting to brute force successfully loggeed in with the following query, but none were successful`: 

```
DeviceLogonEvents
| where RemoteIP in ("95.214.55.202", "45.136.68.84", "72.241.84.72") 
| where ActionType == "LogonSuccess" 
```
<img width="500" height="292" alt="image" src="https://github.com/user-attachments/assets/d07df377-4e7c-4b5f-8998-65efd9890052" />


## Containment, Eradication, and Recovery
- Isolate Devices in MDE on all three devices 
Run antimalware scan on three devices within MDE 
<img width="1910" height="507" alt="image" src="https://github.com/user-attachments/assets/9815ea28-ab5a-4593-a402-41ad105c165c" />

 NSG was locked down to prevent RDP attempts from the public internet, only allowing my home IP address.
- Policy was proposed to require this for all VMs going forward.

Remove the threat and restore systems to normal.
- Brute force was not successful, so no threats related to this incident.

<img width="500" height="487" alt="image" src="https://github.com/user-attachments/assets/100f147b-0e9a-4c05-a0c3-6d998e3e121f" />


## Post-Incident Activities
Document findings and lessons learned.
- Record your notes within the incident.
<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/81d72485-91ff-4151-8cab-a71df5a17437" />
<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/50986984-4ec5-43b5-9f8d-df3b9fca8a89" />

## Closure
Review and confirm incident resolution.
- Review/observe your notes for the incident.
Finalize reporting and close the case.
- Close out the Incident within Sentinel as a “True Positive”

