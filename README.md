Microsoft-azure-soc-live-attacks
=================================

## Overview

This project is an Azure honeypot + Security Operations Center (SOC) style lab. It exposes a Windows virtual machine to the public internet, collects real failed login attempts, enriches them with GeoIP data, and uses Microsoft Sentinel dashboards, KQL queries, and automated alerts to detect and visualize attacks.

## Skills demonstrated

- Azure: resource groups, virtual machines, VNets, NSGs, Log Analytics Workspace, Defender for Cloud, Microsoft Sentinel.  
- SIEM and detection engineering: log collection, KQL querying, IP GeoIP enrichment, workbook/dashboard design, analytic rules, and automated playbooks.  
- Security operations: honeypot design, brute‑force detection, attacker behavior analysis, documenting findings for a SOC‑style use case.

## Architecture

**Components**

- Azure subscription and single resource group for the lab  
- Windows 11 VM with public IP  
- Virtual Network (VNet) and Network Security Group (NSG) allowing all source of trafffics from the internet  
- Log Analytics Workspace for log collection  
- Microsoft Defender for Cloud for security recommendations and alerts  
- Microsoft Sentinel connected to the workspace (SIEM)  
- GeoIP watchlist (country/city data) used to enrich attacker IP addresses  
- Sentinel workbooks, analytic rules, and automation rules (playbooks)

**High‑level data flow**

Public attackers → Windows VM (failed logons) → Log Analytics Workspace → Microsoft Sentinel (KQL queries, maps, incidents, alerts).

## Project setup (high level)

1. Created a resource group and deployed a Windows VM with a public IP in an Azure VNet.  
2. Configured NSG to allow any inbound traffic from the internet for honeypot purposes.  
3. Created a Log Analytics Workspace and connected the VM using the Azure Monitor agent to send SecurityEvent logs.  
4. Enabled Microsoft Defender for Cloud for the subscription and workspace.  
5. Enabled Microsoft Sentinel on the Log Analytics Workspace and connected relevant data connectors (Windows Security Events, Azure Activity, Defender for Cloud).  
6. Imported a GeoIP watchlist and joined it with SecurityEvent data using KQL.  
7. Built Sentinel workbooks (map, time‑series charts, tables) and analytic rules with automation.

## Dashboards and KQL

### 1. Global map of failed user logons

**Purpose**

Visualize where failed login attempts (EventID 4625) are coming from, grouped by city and country, and highlight the most active attacker IPs.

**KQL**

```kusto
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")");
```

**Visualization**

<img width="1344" height="575" alt="image" src="https://github.com/user-attachments/assets/0875eda9-984f-45de-b476-f7abbd451d43" />

- Bubble size: `FailedLogons`.  

### 2. Top attacker IPs and attack window

**Purpose**

Identify the loudest attacker IPs, where they are located, and how long they have been actively generating failed user logons. This helps distinguish short scans from persistent brute‑force activity.  

**KQL**

```kusto
let GeoIP = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| where AccountType == "User"
| project TimeGenerated, IpAddress, TargetUserName
| evaluate ipv4_lookup(GeoIP, IpAddress, network)
| summarize FailedLogons = count(),
          FirstSeen = min(TimeGenerated),
          LastSeen  = max(TimeGenerated)
  by AttackerIp    = IpAddress,
     City          = cityname,
     Country       = countryname,
     latitude, longitude
| extend AttackWindowHours = datetime_diff('hour', LastSeen, FirstSeen) * -1
| extend LocationLabel = strcat(City, " - ", Country)
| order by FailedLogons desc

```

**Visualization**

<img width="1661" height="428" alt="image" src="https://github.com/user-attachments/assets/49c51fc7-4970-4cca-a0ad-ce46baf9cd9e" />

- Table with columns such as: AttackerIp, LocationLabel, FailedLogons, AttackWindowHours, FirstSeen, LastSeen.

- This view allows quick spotting of IPs that generate many failures over a long time window, which are strong candidates for blocking or further investigation.

## Alerts and automation

- Created a Microsoft Sentinel analytic rule that triggers when a single IP generates a high number of failed logons within a short time window.  
- Configured an automation rule with a Logic App playbook to send email notifications when the analytic rule fires (including attacker IP, location, and counts from KQL).

## Findings and observations

- The lab collected real failed login attempts from multiple countries against the exposed Windows VM.  
- Certain IP addresses generated a very high number of failed logons and targeted multiple different user accounts, indicating password‑spray behavior.  
- Attack activity occurred continuously across different hours of the day, demonstrating constant background internet scanning against exposed RDP services.  


