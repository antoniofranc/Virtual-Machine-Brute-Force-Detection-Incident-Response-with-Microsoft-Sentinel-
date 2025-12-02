# Incident Response Report – Brute Force 

Framework: NIST SP 800-61 – Incident Response Lifecycle

Incident Type: Brute Force (Multiple Failed Logons)

Affected Assets: windows-target-1, soclab, threat-hunt-lab

Date: 12/2/2025

---

## 1. Preparation
- IR roles, responsibilities, and escalation procedures documented.
- Required tools available and validated:
- Microsoft Defender for Endpoint (MDE)
- Azure Sentinel logs / KQL analytics
- Network Security Group (NSG) access controls
- Systems patched and configured with baseline security settings.
- SOC playbooks for brute-force attacks available for reference.

## 2. Detection & Analysis
Initial Alert
A Brute Force Detection – alert was triggered in Microsoft Defender.
The alert indicated repeated failed authentication attempts originating from `multiple external IP addresses` targeting `three virtual machines`.

Incident Handling Actions

1. Observed the alert details and `assigned the incident` to myself.

2. Set incident status to `Active`.

3. Selected `Actions → Investigate`, allowing MDE to load entities associated with the event.

Entity Mapping & Evidence Collection

The brute-force attempts originated from six external IPs across two hosts, according to alert metadata.

```
DeviceName            RemoteIP          ActionType       FailedAttempts
-------------------   ----------------  ---------------  ---------------
windows-target-1      45.136.68.84      LogonFailed      87
soclab                95.214.55.202     LogonFailed      100
threat-hunt-lab       95.214.55.202     LogonFailed      77
```
Validation of Successful Logons

A query was run to determine whether any brute-force attempts resulted in a successful login:
```
DeviceLogonEvents
| where RemoteIP in ("95.214.55.202", "45.136.68.84", "72.241.84.72")
| where ActionType == "LogonSuccess"
```
Result:

No successful authentication events were identified.

This confirms that the brute-force activity was unsuccessful.

## 3. Containment, Eradication & Recovery
Containment Actions
- Isolated all three devices in MDE to prevent further lateral movement or remote access.
- Executed full antimalware scans on:
- `windows-target-1`
- `soclab`
- `threat-hunt-lab`

Network-Level Containment

The Azure Network Security Group (NSG) was modified to:
- Block all inbound RDP (3389) from the public internet
- Only allow RDP access from my home IP address
- A policy recommendation was made to enforce restricted RDP access for all VMs going forward.

Eradication
- Since no successful logons occurred and no malware was detected during the scans, no additional eradication actions were required.

Recovery
- Systems were restored to normal network operation.
- Monitoring was continued to ensure no further brute-force activity reoccurred.

## 4. Lessons Learned
- Public RDP exposure significantly increases risk of brute-force attacks.
- NSG hardening should be a mandatory baseline for all cloud-hosted assets.
- Automated alerting in MDE provided actionable visibility, validating the strength of existing monitoring.
