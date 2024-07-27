# Incident Response KQLs

# Malware Detection

```
// Malware detection 
// Malware detected grouped by threat. 
// To create an alert for this query, click '+ New alert rule'
ProtectionStatus
| where ThreatStatus != "No threats detected" 
| summarize AggregatedValue = count() by Threat, Computer, _ResourceId
```

**Query Breakdown**

- ProtectionStatus
    - It specifies that this query works on the ProtectionStatus table.
- | where ThreatStatus != "No threats detected"
    - It checks to see if the value ThreatStatus is something other than “No threats detected”.
- | summarize AggregatedValue = count() by Threat, Computer, _ResourceId
    - It creates a column called AggregatedValue, which contains the count of records for each group.
    - It specifies the data should be grouped by “Threat”, “Computer” and “_ResourceId”
    

**Incident Description**

- This incident involves the detection of malware on the network.

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Alert internal teams about the threat so containment measures can begin.
- Depending on the severity of the malware, also alert external parties about the impacts.

**Containment and Recovery**

- Disconnect the infected system from the network to prevent the malware from spreading.
- Isolate critical systems from the network to further protect it from malware if possible.
- Use specialized tools and antivirus software to remove the malware.
- Perform a thorough scan to confirm all malware has been detected and removed.
- If unsuccessful in removing the malware, perform a system restore from a clean backup, and apply necessary patches and updates.

**Document Findings and Close out Incident**

- Investigate how the malware enetered the network.
- Determine the extent of the damage caused by the malware.
- If necessary, educate users on the importance of strong passwords, recognizing phyising attempts, and following security best practices.

---

# CUSTOM: Malware Detected

```
Event
| where EventLog == "Microsoft-Windows-Windows Defender/Operational"
| where EventID == "1116" or EventID == "1117"
```

**Query Breakdown**

- Event
- | where EventLog == "Microsoft-Windows-Windows Defender/Operational"
- | where EventID == "1116" or EventID == "1117"

**Incident Description**

- This incident involves events where malware has entered the system, but Windows Defender has detected and taken action on it already.

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Alert internal teams about the threat for proper logging.
- Depending on the severity of the malware, also alert external parties about the impacts.

**Containment and Recovery**

- Disconnect the infected system from the network to prevent the malware from spreading.
- Isolate critical systems from the network to further protect it from malware if possible.
- Perform a thorough scan to confirm all malware has been detected and removed.
- Use specialized tools and antivirus software to remove any malware that was not fully removed.
- If unsuccessful in removing the malware, perform a system restore from a clean backup, and apply necessary patches and updates.

**Document Findings and Close out Incident**

- Investigate how the malware enetered the network.
- Determine the extent of the damage caused by the malware.
- If necessary, educate users on the importance of strong passwords, recognizing phyising attempts, and following security best practices.

---

# CUSTOM: Brute Force ATTEMPT - Azure Key Vault

```
// Failed access attempts
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" 
| where ResultSignature == "Forbidden"
```

**Query Breakdown**

- AzureDiagnostics
    - It specifies that this query works on the AzureDiagnostics table.
- | where ResourceProvider == "MICROSOFT.KEYVAULT"
    - It checks to see if the user is performing an operation using the key vault resource.
- | where ResultSignature == "Forbidden"
    - It checks to see if the HTTP status is “Forbidden”, meaning the user does not have permission.
    

**Incident Description**

- This incident documents if an account that does not have access to the key vault tries to access the key vault.

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Alert senior management that a breech has occurred.
- Ensure Multi-Factor Authentication is enabled for all users accessing the key vault.
- Restrict access to the key vault to specific IP ranges using service endpoints.
- Ensure only Azure active directory accounts can access the key vault, and enforce strong password policies.

**Containment and Recovery**

- Temporarily restrict access to the key vault by updating network security rules and firewall settings.
- Change access policies for accounts showing suspicious activity.
- Revoke and reissue affected credentials, keys, and secrets.
- Rotate all secrets, keys, and certificates in the affected key vault, and update any applications or services to use the new credentials.
- If necessary, restore compromised or deleted keys from backups.
- Thoroughly review the network to ensure no residual traces of the attack remain and that all security measures are effective.

**Document Findings and Close out Incident**

- Investigate how the brute force attempt was initiated and why it was able to reach the key vault.
- If necessary, educate users on the importance of strong passwords, recognizing phyising attempts, and following security best practices.

---

# CUSTOM: Possible Privilege Escalation (Azure Key Vault Critical Credential Retrieval or Update)

```
// Updating a specific existing password Success
let CRITICAL_PASSWORD_NAME = "Top-Secret-Value";
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" 
| where OperationName == "SecretGet" or OperationName == "SecretSet"
| where id_s contains CRITICAL_PASSWORD_NAME
```

**Query Breakdown**

- let CRITICAL_PASSWORD_NAME = "Top-Secret-Value";
    - It sets the CRITICAL_PASSWORD_NAME (the secret) to “Top-Secret-Value”
- AzureDiagnostics
    - It specifies that this query works on the AzureDiagnostics table.
- | where ResourceProvider == "MICROSOFT.KEYVAULT"
    - It checks to see if the user is performing an operation using the key vault resource.
- | where OperationName == "SecretGet" or OperationName == "SecretSet"
    - It checks to see if the user is attempting to get or set the secret.
- | where id_s contains CRITICAL_PASSWORD_NAME
    - It checks to see if the id_s field contains the secret defined earlier in the KQL

**Incident Description**

- This incident documents if an account attempts to retrieve the secret or set a new secret.

**Initial Response Actions**

- Verify the authenticity of the alert or report.
- Alert senior management that a breech has occured.
- Immediately disable or isolate the user account/s that performed the operation.
- Ensure Multi-Factor Authentication is enabled for all users accessing the key vault.
- Restrict access to the key vault to specific IP ranges using service endpoints.
- 

**Containment and Recovery**

- Revoke all credentials, secrets, and keys that may have been compromised.
- Ensure systems are clean and that no backdoors or malware remain before restoring service.
- Conduct an audit to ensure that only necessary permissions are granted.
- Rotate all secrets, keys, and certificates in the affected key vault, and update any applications or services to use the new credentials.

**Document Findings and Close out Incident**

- Investigate how the privilege escalation occured and investigate the attack path.
- Determine if any sensitive data was accessed or exfiltrated using the compromised credentials and assess business impact.
- Update network security rules to restrict access to the key vault.
- Ensure software is patched and up to date.
- Tighten security configurations based on best practices

---

# CUSTOM: Brute Force ATTEMPT - MS SQL Server

```
// Brute Force Attempt MS SQL Server
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Event
| where EventLog == "Application"
| where EventID == 18456
| where TimeGenerated > ago(1hr)
| project TimeGenerated, AttackerIP = extract(IpAddress_REGEX_PATTERN, 0, RenderedDescription), DestinationHostName = Computer, RenderedDescription
| summarize FailureCount = count() by AttackerIP, DestinationHostName
| where FailureCount >= 5
```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

---

# CUSTOM: Brute Force ATTEMPT - Azure Active Directory

```
SigninLogs
| where ResultDescription == "Invalid username or password or Invalid on-premise username or password."
| project TimeGenerated, ResultDescription, UserPrincipalName, UserId, AppDisplayName, IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

---

# CUSTOM: Brute Force ATTEMPT - Linux Syslog

```
// Brute Force Success Linux
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Syslog
| where Facility == "auth" and SyslogMessage startswith "Failed password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, AttackerIP = extract(IpAddress_REGEX_PATTERN, 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize FailureCount = count() by AttackerIP, DestinationHostName, DestinationIP
| where FailureCount >= 10
```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

---

# CUSTOM: Brute Force ATTEMPT - Windows

```
// Failed logon 
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, DestinationHostName = Computer
| where FailureCount >= 10
```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

---

# CUSTOM: Brute Force SUCCESS - Azure Active Directory

```
// Failed AAD logon
let FailedLogons = SigninLogs
| where Status.failureReason == "Invalid username or password or Invalid on-premise username or password."
| where TimeGenerated > ago(1h)
| project TimeGenerated, Status = Status.failureReason, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, AttackerIP = IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
| summarize FailureCount = count() by AttackerIP, UserPrincipalName;
let SuccessfulLogons = SigninLogs
| where Status.errorCode == 0 
| where TimeGenerated > ago(1h)
| project TimeGenerated, Status = Status.errorCode, UserPrincipalName, UserId, UserDisplayName, AppDisplayName, AttackerIP = IPAddress, IPAddressFromResourceProvider, City = LocationDetails.city, State = LocationDetails.state, Country = LocationDetails.country, Latitude = LocationDetails.geoCoordinates.latitude, Longitude = LocationDetails.geoCoordinates.longitude
| summarize SuccessCount = count() by AuthenticationSuccessTime = TimeGenerated, AttackerIP, UserPrincipalName, UserId, UserDisplayName;
let BruteForceSuccesses = SuccessfulLogons
| join kind = inner FailedLogons on AttackerIP, UserPrincipalName;
BruteForceSuccesses
| project AttackerIP, TargetAccount = UserPrincipalName, UserId, FailureCount, SuccessCount, AuthenticationSuccessTime
```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

---

# CUSTOM: Brute Force SUCCESS - Linux Syslog

```
// Brute Force Success Linux
let FailedLogons = Syslog
| where Facility == "auth" and SyslogMessage startswith "Failed password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize FailureCount = count() by AttackerIP = SourceIP, DestinationHostName
| where FailureCount >= 5;
let SuccessfulLogons = Syslog
| where Facility == "auth" and SyslogMessage startswith "Accepted password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize SuccessfulCount = count() by SuccessTime = TimeGenerated, AttackerIP = SourceIP, DestinationHostName
| where SuccessfulCount >= 1
| project DestinationHostName, SuccessfulCount, AttackerIP, SuccessTime;
let BruteForceSuccesses = SuccessfulLogons 
| join kind = inner FailedLogons on AttackerIP, DestinationHostName;
BruteForceSuccesses
```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

---

# CUSTOM: Brute Force SUCCESS - Windows

```
// Brute Force Success Windows
let FailedLogons = SecurityEvent
| where EventID == 4625 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer
| where FailureCount >= 5;
let SuccessfulLogons = SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize SuccessfulCount = count() by AttackerIP = IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;
SuccessfulLogons
| join kind = inner FailedLogons on DestinationHostName, AttackerIP, LogonType
| project AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, SuccessfulCount

```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

| Name | CUSTOM: Brute Force SUCCESS - Windows |
| --- | --- |
| Description | If you see a SUCCESS but the Account is "NT AUTHORITY\ANONYMOUS LOGON", check out this article: https://www.inversecos.com/2020/04/successful-4624-anonymous-logons-to.html |

---

# CUSTOM: Possible Privilege Escalation (Global Administrator Role Assignment)

```
AuditLogs
| where OperationName == "Add member to role" and Result == "success"
| where TargetResources[0].modifiedProperties[1].newValue == '"Global Administrator"' or TargetResources[0].modifiedProperties[1].newValue == '"Company Administrator"' and TargetResources[0].type == "User"
| where TimeGenerated > ago(60m)
| project
    TimeGenerated,
    OperationName,
    AssignedRole = TargetResources[0].modifiedProperties[1].newValue,
    Status = Result,
    TargetResources,
    InitiatorID = InitiatedBy["user"]["id"],
    TargetID = TargetResources[0]["id"]
```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

---

# CUSTOM: Windows Host Firewall Tampering

```
Event
| where EventLog == "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
| where EventID == 2003
```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]

---

CUSTOM: Possible Lateral Movement (Excessive Password Resets)

```
AuditLogs
| where OperationName startswith "Change" or OperationName startswith "Reset"
| order by TimeGenerated
| summarize count() by tostring(InitiatedBy)
| project Count = count_, InitiatorId = parse_json(InitiatedBy).user.id, InitiatorUpn = parse_json(InitiatedBy).user.userPrincipalName, InitiatorIpAddress = parse_json(InitiatedBy).user.ipAddress 
| where Count >= 10

```

**Query Breakdown**

**Incident Description**

- This incident […]

**Initial Response Actions**

- Verify the authenticity of the alert or report.

**Containment and Recovery**

- 

**Document Findings and Close out Incident**

- Investigate how […] and […]