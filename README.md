# Honeypot Network and Incident Response in Microsoft Azure

# Introduction

The purpose of this project was to create a honeynet cloud infrastructure, and then tighten that infrastructure so it can withstand cyber threats and adhere to security regulations. I will walk through the completed cloud infrastructure and explain each screenshot.

# Outer Topology

![Region.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Region.png)

Network Watcher | Topology is a tool within Microsoft Azure which allows you to visualize and manage your cloud network infrastructure by using an interactive interface. This tool provides a graphical representation of resources and relationships across multiple Azure subscriptions, regions, and resource groups. This allows you to diagnose and troubleshoot network issues by gaining contextual access to other Network Watcher diagnostic tools.

However, the entire project only used resources from a single location: the East US region as pictured above.

![SOC Subnet.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/SOC_Subnet.png)

Additionally, the project was contained within its own virtual network, or VNet. The VNet associated with the SOC resource group (RG-SOC), which is SOC-vnet, as pictured above.

VNets are isolated network environments, where your Azure resources can be deployed and securely communicate with each other. It is a private space in the Azure cloud, which works similarly to an on-premises data center.

Within the Vnet, you can define IP address ranges, subnets, and routing tables to control traffic flow and network access.

![External Firewall.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/External_Firewall.png)

Pictured above is the external firewall, a crucial security component for cloud networks, on-premise networks, physical data center networks, and the internet. An external firewall is typically implemented as part of a perimeter network, which is a secure subnet that screens incoming packets before allowing those packets to enter the secured network. This project used Network Security Groups in order to create the external firewall.

An external firewall controls both inbound and outbound traffic through user-defined rules that can be defined based on things such as source and destination IP addresses, ports, and protocols to enforce the security policies.

When integrated with Azure Security Center, it provides logging, monitoring, and threat detection, which ensures continuous protection of your Azure envrionment.

![NSG-Subnet AllowAnyInbound.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/NSG-Subnet_AllowAnyInbound.png)

However, in order to prepare the honeynet, a dangerous rule was added so that malicious actors could get inside the network to generate incidents that could later be logged.

Pictured above is a user defined rule named DANGERAllowAnyCustomInbound. It allows traffic using any protocol from any source IP and any source port, going to any destination IP and any destination port. This rule should not be used in a proper cloud infrastructure.

When enough incidents were gathered through the honeynet, this rule was deleted in order to secure the network.

![AllowMyIPAddressAndScannerInbound.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/AllowMyIPAddressAndScannerInbound.png)

Pictured above is the AllowMyIPAddressAndScannerInbound, which allows traffic from the VNet’s public facing IP address, as well as traffic from a qualys Scanner’s IP address.

The final inbound rule, BlockList, is a block list of all of the IPs judged as malicious when working on security incidents.

![AllowQualysScannerOutbound.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/AllowQualysScannerOutbound.png)

Pictured above is the AllowQualysScannerOutbound rule, which allows traffic to go to the Qualys scanner’s IP address. Without this rule, the Qualys scanner in the network does not work.

# Inner Topology

![External Firewall Detailed.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/External_Firewall_Detailed.png)

Pictured above is the network within the subnet, and relationships between each resource.

## Private Endpoint

![Private Endpoint List.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Private_Endpoint_List.png)

Private endpoints are network interfaces that connects you privately and securely to the resource attached to the endpoint by using a private IP address within your virtual network. This eliminates exposure of the resource to the public internet, which reduces the attack surface.

If the resource you’re creating a private endpoint for resides in your directory, you can approve connection requests for the resource if you have sufficient permissions. Upon approval, the user is connected to an instance of the Azure resource.

This project has two private endpoints, one for the Azure Key Vault, and one for the Private Storage. Besides the services used in this project, private endpoints are supported for other services such as Azure Files and Azure Tables.

## Private Key Vault

![Azure Key Vault.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Azure_Key_Vault.png)

![PE-Azure-Key-Vault Child Nodes.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/PE-Azure-Key-Vault_Child_Nodes.png)

Pictured above is the private key vault associated with this project, as well as the toplogy showcasing that the private key vault is connected to a private endpoint.

The private endpoint allows for keys, secrets, and certificates to be accessed securely from the Azure Services within the VNet.

![Disable Public Access to Key Vault.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Disable_Public_Access_to_Key_Vault.png)

![Creating Access Policy for GlobalAdministrator.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Creating_Access_Policy_for_GlobalAdministrator.png)

In order to further secure the key vault, after creating the private endpoint, pubilc access to the key vault was disabled. This is shown in the first image.

In the second image, an access policy for a group called GlobalAdministrator was created.  The “List” next to secret permissions means that the Global Administrator can only view a list of the secrets in the key vault, and is unable to add or modify secrets. Even if a user connects through the private endpoint, they will not be able to view the key vault unless they have the proper permissions.

## Private Storage

![Blob Storage.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Blob_Storage.png)

![PE-Storage Child Nodes.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/PE-Storage_Child_Nodes.png)

![Disabling Public Network Access for Storage Accounts For SC-7 v2.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Disabling_Public_Network_Access_for_Storage_Accounts_For_SC-7_v2.png)

Pictured above is the Azure Storage account associated with this project, its topology, and disabling public access to the storage. This allows a user to access resources within the Azure Storage account through a secure connection without exposure to the public internet.

The private endpoint allows for Azure Storage to be accessed securely from the Azure Services within the VNet, which allows for data privacy and confidentiality.

## Windows Virtual Machine

![windowsvm174 Child Nodes.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/windowsvm174_Child_Nodes.png)

Pictured above is the topology for a Windows Virtual Machine on the network, turned off at the time of the screenshot. The network interface is connected to the machine itself (WindowsVM), a firewall (WindowsVM-nsg), and the ip configuration (ipconfig1).

This Windows VM had Microsoft SQL Server installed with an easy to crack password to generate security incidents.

The firewall was configured with identical DANGERAllowAnyCustomInbound rule as seen in the external firewall before the honeynet was secured, and like in the external firewall, this rule was also deleted when the honeynet was secured. It also hasidentical AllowMyIPAddressAndScannerInbound and AllowQualysScannerOutbound rules to the ones in the external firewall.

It provides a scalable and flexible environment for running Windows-based applications and services in the cloud by allowing you to deploy a Windows Server or Windows client operating system on the Azure infrastructure. It can be assigned a public IP address for internet connectivity. The agent provides various configuration options for customizing the VM’s behavior.

## Linux Virtual Machine

![linuxvm294 Child Nodes.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/linuxvm294_Child_Nodes.png)

Pictured above is the topology for a Linux Virtual Machine on the network, turned on at the time of the screenshot. The network interface is connected to the machine itself (LinuxVM), a firewall (LinuxVM-nsg), and the ip configuration (ipconfig1).

The firewall was configured with identical DANGERAllowAnyCustomInbound rule as seen in the external firewall before the honeynet was secured, and like in the external firewall, this rule was also deleted when the honeynet was secured. It also has identical AllowMyIPAddressAndScannerInbound and AllowQualysScannerOutbound rules to the ones in the external firewall.

It provides a scalable and flexible environment for running Linux-based applications and services in the cloud by allowing you to deploy a Linux client on the Azure infrastructure. It can be assigned a public IP address for internet connectivity. The agent provides various configuration options for customizing the VM’s behavior.

## Qualys Virtual Machine

![QualysVM-NetInt-97b3 Child Nodes.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/QualysVM-NetInt-97b3_Child_Nodes.png)

Pictured above is the topology for a Linux Virtual Machine on the network, turned on at the time of the screenshot. The network interface is connected to the machine itself (QualysVM), a firewall (QualysVM-Nsg-97b3), and the ip configuration (ipconfig1).

The Qualys Virtual Machine for Microsoft Azure is a cloud-based solution that allows you to continuously assess the security posture of your Azure Virtual Machines by offering continuous monitoring, real-time alerts, and detailed reports to help organizations stay compliant with security standards and regulations. It automates vulnerability management by identifying, prioritizing, and remediating security vulnerabilities within your infrastructure. It integrates seamlessly with Azure, which allows it to provide comprehensive visibility into the security of the Azure envrionment.

![QualysVM-Nsg-97b3 security rules.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/QualysVM-Nsg-97b3_security_rules.png)

Pictured above are the security rules for QualysVM-Nsg-97b3.

# Log Analytics Workspace

![Monitor for Windows .png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Monitor_for_Windows_.png)

![Monitor for Linux.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Monitor_for_Linux.png)

Log Analytics Workspace integrates Windows and Linux servers with Azure’s Log Analytics service, which offers monitoring, management, and analytic capabilities. The integration allows the collection and analysis of logs, performance data, and systems events from the linked workstations. By connectiong a workspace to a Log Analytics Workspace, administrators gain insight s into system health, security, and performance metrics in near real time. With these insights, administrators can troubleshoot, proactively monitor, and generate reports to enhance operational effeciency and ensure compliance of the infrastructure.

## Data Collection Rules

![Data Collection Rules All.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Data_Collection_Rules_All.png)

Data Collection Rules (DCRs) in Microsoft Azure define what data is collected from various sources and how it is processed. These rules are part of Azure Monitor and gather data from both Azure and non-Azure sources such as virtual machines, applications, and services. DCRs specify the types of logs, metrics, and traces to collect, where to send the data, and how to process it. They allow customization of data collection based on specific requirements and preferences. DCRs enable monitoring, analysis, and visualization of data, providing insights into system performance, health and security.

Data sources in Microsoft Azure include services such as Azure virtual machines and Azure storage, as well as non-Azure resources such as on-premise servers and third party services. These sources output data such as logs, metrics and traces, which Azure Monitor can collect for monitoring and analysis and then sending it to a Log Analytics Workspace. Aggregating the data from diverse sources allows the administrator to gain comprehensive insights into the performance, health, and security of cloud and hybrid environments.

![Data Source Destination.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Data_Source_Destination.png)

I sent both the Windows Event Log and the Linux Syslog to the Log Analytics Workspace for this project, LAW-Honeynet, in the RG-SOC resource group. It says the selected subscription is disabled ebcause I forgot to get this picture before I disabled the Azure subscription at the conclusion of the project. Normally, it would not have that error.

Both Windows Event Log and Linux Syslog provide critical insights into system performance, security, and operational health. The centralized logging and analysis offers a comprehensive solution for monitoring Windows Event Logs or Linux Syslogs across a variety of Azure resources, and enables efficient troubleshooting, monitoring, and compliance.

### Windows Event Log

![Windows Event Log.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Windows_Event_Log.png)

![Windows Event Log 2.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Windows_Event_Log_2.png)

Pictured above is the configuration for the Windows Event Log data collection rule. Windows Event Logs can be customized in Microsoft Azure depending on the specific needs of the administrator. These logs can include application-specific events, operational metrics, or business-related activities.

### Linux Syslog

![Linux Syslog.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Linux_Syslog.png)

![Linux Syslog 2.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Linux_Syslog_2.png)

Pictured above is the configuration for the Linux Syslog collection rule. It collects data such as system logs, application logs, and custom logs, providing insights into the performance and health of the system.

## Sentinel Analytics

![Sentinel Analytics Rules.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Sentinel_Analytics_Rules.png)

Microsoft Sentinel Analytics is a powerful security information and event management (SIEM) solution offered by Microsoft. Among its services are advanced threat detection, investigation, and response capabilities across the entire environment. Sentinel Analytics uses AI and machine learning to detect anomalies, suspicious activity, and security threats in real time. It aggregates data from various sources including logs and threat intelligence feeds.

Pictured above is the Sentinel Analytics Rules used for the project. These rules came from the Sentinel-Analytics-Rules(KQL Alert Queries).json file.

## Microsoft Fusion Rules

![Sentinel Fusion Rule.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Sentinel_Fusion_Rule.png)

Microsoft Fusion rules enable advanced threat detection by combining multiple detection logics and data sources, while integrating signals from various security products. These rules use machine learning algorithms to analyze correlated data and identify complex attack patterns, and allow analysts to create customized detection rules for the specific needs of their organization.

Consolidating multiple detection logics into a single rule streamlines the dection process and provides more comprehensive threat detection capabilities, allowing organizations to strengthen security posture and respond effectively to emerging threats.

Pictured above are the fusion rules set for the project

## Watchlist

![Watchlist.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Watchlist.png)

A watchlist in Microsoft Azure is a feature in Microsoft Sentinel that allows security teams to create and manage lists of entities such as IP addresses, URLs, or file hashes that they want to monitor for security-related activities. These lists can include known malicious entities, trusted assets, or entities specific to the environment, and provide a flexible way to tailor threat detection and response to the needs of each organization.

Microsoft Sentinel uses these watchlists to enrich security analysis and threat detection by comparing incoming data against the watchlist. If the data matches, an alert can be triggered, or automatic response actions can be taken, which allows security teams to respond to threats more effectively.

Pictured above is the Watchlist used for the project. This data came from a file named geo-ip-summarized.csv

# Incidents

![Analytics List-Incidents.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Analytics_List-Incidents.png)

Pictured above is a small selection of incidents. Incidents refer to unexpected events or disruption that impact the availability, performance, or security of Azure services or resources.

Microsoft Azure provides a robust incident management process to detect, respond to, and mitigate incidents promptly. Using Microsoft Sentienl, I received near real time updates on inicdents including severity, impact, and resolution status.

In this example, as this list is entirely brute force attempt incidents, these incidents im pact the security of resources. These were only the attempts made, and there was no success in the brute force attempts shown in this image.

## Sample Incident

![Brute Force Attempt - Emerging Threat.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Brute_Force_Attempt_-_Emerging_Threat.png)

Custom brute force attempts were a common inicident type found during this project. It signifies unauthorized login attempts by using repeated, automated login guesses. Due to the data collection rules, these attempts are aggregated together by IP to provide visibility into a potential security threat, such as multiple failed login attempts within a short period. These incidents trigger an alert, allowins security teams to swiftly respond to the potential danger and strengthen security measures.

Pictured above is an example of a user Lin Smith working on a custom brute force incident. The attempts are being triggered from IP address 189.10.74.146.

![Located an Emerging Threat According to AbuseIPDB.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Located_an_Emerging_Threat_According_to_AbuseIPDB.png)

![Reported IP to AbuseIPDB.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Reported_IP_to_AbuseIPDB.png)

This IP was reported one time on Abuseipdb.com, which indicates it is an emerging threat because it was not reported before. But as shown in the incident above, it attempted to brute force its way into the network.

![IP not found in Greynoise.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/IP_not_found_in_Greynoise.png)

![Located an Emerging Thread According to Greynoise.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Located_an_Emerging_Thread_According_to_Greynoise.png)

Pictured above is me cross referencing this particular IP to viz.greynoise.io, which confirms abuseipdb’s assessment of this IP address as one belonging to an emerging threat.

# Tightening the Network

![Applying NIST SP 800-53 Rev. 5.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/Applying_NIST_SP_800-53_Rev._5.png)

Pictured above is the securtity policy configuration used to tighten the network.  NIST SP 800-53 Rev. 5 is a catalogue of flexible and customizable security and privacy controls that address the diverse requirements based on business needs, laws, executive orders, directives, regulations, policies, standards, and guidelines.

# Workbooks, Before and After Tightening the Network

Workbooks are tools in Microsoft Azure that provide insights into potential security threats. These workbooks include visualizations of a specific event or group of events, and provides recommendations for mitigating identified threats to improve security posture.  They analyze data from places such as Microsoft Sentinel and Microsoft Azure Logs to help the security team identify and respond to threats. Workbooks provide a comprehensive solution for monitoring and responding to security threads in Azure environments.

## Linux SSH Threat Workbook

This workbook looks at data related to Linux Secure Shell (SSH) such as failed login attempts, brute force attacks, and suspicious activities from known malicious IPs.

This workbook was generated using the linux-ssh-auth-fail-.json file.

### Before

![linux-ssh-auth-fail-workbook after.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/linux-ssh-auth-fail-workbook_after.png)

### After

![linux-ssh-auth-fail-workbook.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/linux-ssh-auth-fail-workbook.png)

## MS-SQL Auth Fail Workbook

This workbook looks at data related to failed login attempts on a Microsoft SQL Server (MSSQL) database.

This workbook was generated using the mssql-auth-fail-.json file.

### Before

![mssql-auth-fail-workbook.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/mssql-auth-fail-workbook.png)

### After

![mssql-auth-fail-workbook 2.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/mssql-auth-fail-workbook_2.png)

## NSG Malicious Threat Workbook

This workbook looks at data related to the identification of malicioius threats on the network.

This workbook was generated using the nsg-malicious-allowed-in.json file.

### Before

![nsg-malicious-allowed-in.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/nsg-malicious-allowed-in.png)

### After

![nsg-malicious-allowed-in 2.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/nsg-malicious-allowed-in_2.png)

## Windows RDP Threat Workbook

This workbook looks at data related to Windows Remote Desktop Protocol (RDP). It outlines common threats and attacks related to RDP such as brute-force attacks, man-in-the-middle attacks, and ransomware.

This workbook was generated using the nsg-malicious-allowed-in.json file.

### Before

![windows-rdp-auth-fail-workbook 2.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/windows-rdp-auth-fail-workbook_2.png)

### After

![windows-rdp-auth-fail-workbook.png](Honeypot%20Network%20and%20Incident%20Response%20in%20Microsoft/windows-rdp-auth-fail-workbook.png)

# Before and After Threat Summary

As shown in the following tables, after securing the environment, the number of incidents decreased by over 95% for all incidents except Security Events, which decreased by about 75% instead.

| BEFORE SECURING ENVIRONMENT |  |
| --- | --- |
|  |  |
| Start Time | 2024-04-09T22:41:40.2596165Z |
| Stop Time | 2024-04-10T22:41:40.2596165Z |
| Security Events (Windows VMs) | 58880 |
| Syslog (Linux VMs) | 6170 |
| SecurityAlert (Microsoft Defender for Cloud) | 39 |
| SecurityIncident (Sentinel Incidents) | 277 |
| NSG Inbound Malicious Flows Allowed | 932 |
| NSG Inbound Malicious Flows Blocked | 0 |

| AFTER SECURING ENVIRONMENT |  |
| --- | --- |
|  |  |
| Start Time | 2024-04-11T00:02:50.9043451Z |
| Stop Time | 2024-04-12T00:02:50.9043451Z |
| Security Events (Windows VMs) | 12059 |
| Syslog (Linux VMs) | 1 |
| SecurityAlert (Microsoft Defender for Cloud) | 1 |
| SecurityIncident (Sentinel Incidents) | 9 |
| NSG Inbound Malicious Flows Allowed | 0 |
| NSG Inbound Malicious Flows Blocked | 1004 |

| RESULTS  |  |
| --- | --- |
|  | Change after security environment |
| Security Events (Windows VMs) | -79.52% |
| Syslog (Linux VMs) | -99.98% |
| SecurityAlert (Microsoft Defender for Cloud) | -97.44% |
| Security Incident (Sentinel Incidents) | -96.75% |
| NSG Inbound Malicious Flows Allowed | -100.00% |
| NSG Inbound Malicious Flows Blocked | 100.00% |
