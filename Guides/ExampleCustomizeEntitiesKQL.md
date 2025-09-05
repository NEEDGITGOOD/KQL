## 1. **Administrative Tool Execution Timeline**
Track legitimate but important admin tool usage for context around incidents.

```kql
DeviceProcessEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where FileName in~ ("mmc.exe", "compmgmt.msc", "services.msc", "eventvwr.exe", 
    "perfmon.exe", "resmon.exe", "taskmgr.exe", "msconfig.exe", "regedit.exe",
    "gpedit.msc", "secpol.msc", "wf.msc", "diskmgmt.msc")
| extend ToolCategory = case(
    FileName in~ ("services.msc", "msconfig.exe"), "ServiceManagement",
    FileName in~ ("regedit.exe", "gpedit.msc", "secpol.msc"), "PolicyConfig",
    FileName in~ ("eventvwr.exe", "perfmon.exe", "resmon.exe"), "Diagnostics",
    FileName in~ ("wf.msc"), "NetworkSecurity",
    "SystemAdmin"
)
| project TimeGenerated = Timestamp,
    AdminTool = FileName,
    ToolCategory,
    User = AccountName,
    ParentProcess = InitiatingProcessFileName,
    SessionId = tostring(LogonId),
    DeviceName
```
**Activity Title**: "{{User}} opened {{ToolCategory}} tool: {{AdminTool}}"

## 2. **Archive and Compression Operations**
Critical for understanding potential data staging without being inherently malicious.

```kql
DeviceFileEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where FileName endswith_any (".zip", ".rar", ".7z", ".tar", ".gz", ".cab")
    or InitiatingProcessFileName in~ ("7z.exe", "winrar.exe", "tar.exe", "compact.exe", "makecab.exe")
| where ActionType in ("FileCreated", "FileModified")
| extend ArchiveSize = FileSize / (1024*1024) // Convert to MB
| where ArchiveSize > 10 // Only archives > 10MB
| project TimeGenerated = Timestamp,
    ArchiveFile = FileName,
    SizeMB = round(ArchiveSize, 2),
    Tool = InitiatingProcessFileName,
    User = InitiatingProcessAccountName,
    FolderPath = FolderPath,
    DeviceName
```
**Activity Title**: "{{User}} created {{SizeMB}}MB archive: {{ArchiveFile}}"

## 3. **Browser Download Patterns**
Track what was downloaded and when - crucial for threat hunting.

```kql
DeviceFileEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe")
| where ActionType == "FileCreated" 
| where FolderPath has_any ("Downloads", "Desktop", "Documents")
| where FileName !endswith_any (".tmp", ".partial", ".part", ".crdownload")
| extend FileType = case(
    FileName endswith_any (".exe", ".msi", ".scr", ".com"), "Executable",
    FileName endswith_any (".ps1", ".bat", ".cmd", ".vbs", ".js"), "Script",
    FileName endswith_any (".zip", ".rar", ".7z"), "Archive",
    FileName endswith_any (".dll", ".sys"), "Binary",
    FileName endswith_any (".pdf", ".doc", ".docx", ".xls", ".xlsx"), "Document",
    "Other"
)
| project TimeGenerated = Timestamp,
    DownloadedFile = FileName,
    FileType,
    Browser = InitiatingProcessFileName,
    User = InitiatingProcessAccountName,
    FullPath = strcat(FolderPath, "\\", FileName),
    DeviceName
```
**Activity Title**: "{{User}} downloaded {{FileType}}: {{DownloadedFile}} via {{Browser}}"

## 4. **Network Profile and Firewall State Changes**
Important context for understanding security posture changes.

```kql
DeviceRegistryEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where RegistryKey has_any (
    @"CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
)
| where ActionType == "RegistryValueSet"
| extend Context = case(
    RegistryKey has "FirewallPolicy" and RegistryValueName == "EnableFirewall", "FirewallStateChanged",
    RegistryKey has "FirewallPolicy" and RegistryValueName == "DoNotAllowExceptions", "FirewallExceptionsModified",
    RegistryKey has "NetworkList" and RegistryValueName == "Category", "NetworkProfileChanged",
    "NetworkConfigModified"
)
| project TimeGenerated = Timestamp,
    ChangeType = Context,
    NewValue = RegistryValueData,
    User = InitiatingProcessAccountName,
    Process = InitiatingProcessFileName,
    DeviceName
```
**Activity Title**: "Network security change: {{ChangeType}} to {{NewValue}}"

## 5. **Remote Management Tool Usage**
Track legitimate remote access tools that provide investigation context.

```kql
DeviceNetworkEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where InitiatingProcessFileName in~ (
    "teamviewer.exe", "anydesk.exe", "mstsc.exe", "vnc.exe", 
    "screenconnect.exe", "bomgar.exe", "dameware.exe", "radmin.exe",
    "pcanywherehost.exe", "logmein.exe", "gotomypc.exe"
)
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count(), 
    UniqueDestinations = dcount(RemoteIP),
    Destinations = make_set(RemoteIP, 10) 
    by bin(TimeGenerated = Timestamp, 5m), 
    Tool = InitiatingProcessFileName,
    User = InitiatingProcessAccountName,
    DeviceName
| project TimeGenerated,
    RemoteTool = Tool,
    User,
    ConnectionCount,
    UniqueDestinations,
    TargetIPs = tostring(Destinations),
    DeviceName
```
**Activity Title**: "{{User}} initiated {{ConnectionCount}} {{RemoteTool}} connections to {{UniqueDestinations}} hosts"

## 6. **Certificate Store Modifications**
Track certificate operations that might indicate trust relationship changes.

```kql
DeviceProcessEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ProcessCommandLine has_any ("certutil", "cert:", "CertMgr")
| where ProcessCommandLine has_any ("import", "add", "delete", "store", "addstore", "delstore")
| extend Operation = case(
    ProcessCommandLine has_any ("import", "add", "addstore"), "CertificateAdded",
    ProcessCommandLine has_any ("delete", "delstore"), "CertificateRemoved",
    "CertificateModified"
)
| extend Store = extract(@'-store\s+(\w+)', 1, ProcessCommandLine)
| project TimeGenerated = Timestamp,
    Operation,
    CertStore = iff(isnotempty(Store), Store, "Unknown"),
    User = AccountName,
    CommandLine = ProcessCommandLine,
    DeviceName
```
**Activity Title**: "Certificate operation: {{Operation}} in {{CertStore}} store by {{User}}"

## 7. **Shadow Copy and Backup Operations**
Context around data protection/recovery attempts or potential ransomware prep.

```kql
DeviceProcessEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ProcessCommandLine has_any ("vssadmin", "wbadmin", "shadow", "backup")
    or FileName in~ ("vssadmin.exe", "wbadmin.exe", "wmic.exe")
| where ProcessCommandLine has_any ("create", "delete", "list", "resize", "backup", "restore")
| extend BackupAction = case(
    ProcessCommandLine has "delete", "ShadowCopyDeleted",
    ProcessCommandLine has "create", "ShadowCopyCreated",
    ProcessCommandLine has "list", "ShadowCopyQueried",
    ProcessCommandLine has "resize", "ShadowStorageResized",
    ProcessCommandLine has "backup", "BackupInitiated",
    "BackupOperation"
)
| project TimeGenerated = Timestamp,
    Action = BackupAction,
    User = AccountName,
    CommandDetails = substring(ProcessCommandLine, 0, 200),
    DeviceName
```
**Activity Title**: "Backup/Recovery action: {{Action}} by {{User}}"

## 8. **Local Group Membership Changes**
Track local admin and RDP group changes that matter for lateral movement.

```kql
DeviceProcessEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ProcessCommandLine has "net " and ProcessCommandLine has_any ("localgroup", "group")
| where ProcessCommandLine has_any ("/add", "/delete", "/del")
| extend GroupName = extract(@'localgroup\s+"?([^"\s/]+)"?', 1, ProcessCommandLine)
| extend Operation = iff(ProcessCommandLine has "/add", "UserAdded", "UserRemoved")
| extend TargetUser = extract(@'(?:/add|/del|/delete)\s+"?([^"\s]+)"?', 1, ProcessCommandLine)
| where GroupName in~ ("Administrators", "Remote Desktop Users", "Power Users", 
    "Backup Operators", "Remote Management Users")
| project TimeGenerated = Timestamp,
    Operation,
    GroupName,
    TargetUser,
    ExecutingUser = AccountName,
    DeviceName
```
**Activity Title**: "Local group change: {{TargetUser}} {{Operation}} to {{GroupName}}"

## 9. **WMI Operations and Queries**
WMI activity that shows reconnaissance or remote execution context.

```kql
DeviceProcessEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where FileName in~ ("wmic.exe", "wbemtest.exe") 
    or ProcessCommandLine has_any ("Get-WmiObject", "Invoke-WmiMethod", "Get-CimInstance")
| extend WMIOperation = case(
    ProcessCommandLine has_any ("process", "PROCESS"), "ProcessQuery",
    ProcessCommandLine has_any ("service", "SERVICE"), "ServiceQuery",
    ProcessCommandLine has_any ("startup", "STARTUP"), "StartupQuery",
    ProcessCommandLine has_any ("qfe", "HOTFIX"), "PatchQuery",
    ProcessCommandLine has_any ("product", "PRODUCT"), "SoftwareQuery",
    ProcessCommandLine has_any ("share", "SHARE"), "ShareQuery",
    ProcessCommandLine has_any ("useraccount", "USERACCOUNT"), "UserQuery",
    ProcessCommandLine has_any ("group", "GROUP"), "GroupQuery",
    ProcessCommandLine has_any ("/node:", "-ComputerName"), "RemoteWMI",
    "GeneralWMI"
)
| where WMIOperation != "GeneralWMI"
| project TimeGenerated = Timestamp,
    QueryType = WMIOperation,
    User = AccountName,
    QueryDetails = substring(ProcessCommandLine, 0, 250),
    DeviceName
```
**Activity Title**: "WMI activity: {{QueryType}} by {{User}}"

## 10. **Application Crash and Hang Analysis**
System stability issues that might indicate exploitation attempts or system compromise.

```kql
DeviceProcessEvents
| where (DeviceName == '{{Host_HostName}}' and InitiatingProcessAccountDomain == '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where FileName in~ ("werfault.exe", "wermgr.exe", "drwtsn32.exe")
| join kind=leftouter (
    DeviceProcessEvents
    | where ActionType == "ProcessTerminated"
    | project CrashedProcess = FileName, CrashTime = Timestamp, DeviceId
) on DeviceId
| where abs(datetime_diff('second', TimeGenerated, CrashTime)) < 5
| extend Context = case(
    CrashedProcess in~ ("outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe"), "OfficeCrash",
    CrashedProcess in~ ("chrome.exe", "firefox.exe", "msedge.exe"), "BrowserCrash",
    CrashedProcess in~ ("lsass.exe", "csrss.exe", "winlogon.exe"), "CriticalSystemProcess",
    CrashedProcess endswith ".exe", "ApplicationCrash",
    "UnknownCrash"
)
| project TimeGenerated = Timestamp,
    CrashContext = Context,
    CrashedApplication = CrashedProcess,
    ReportingProcess = FileName,
    User = AccountName,
    DeviceName
```
**Activity Title**: "Application stability issue: {{CrashContext}} - {{CrashedApplication}}"

## 2

## 1. **Critical Security Process Termination**
Track when critical security services/processes are terminated on the host.

```kql
DeviceProcessEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ActionType == "ProcessTerminated"
| where FileName in~ ("MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseCncProxy.exe", 
    "SenseNdr.exe", "WdBoot.exe", "WdFilter.exe", "WdNisDrv.exe", "WdNisSvc.exe")
| project TimeGenerated, ProcessName=FileName, TerminatedBy=InitiatingProcessFileName, 
    AccountName=InitiatingProcessAccountName, CommandLine=InitiatingProcessCommandLine
```
**Activity Title**: `Security process {{ProcessName}} terminated by {{AccountName}}`

## 2. **Suspicious PowerShell Execution**
Track potentially malicious PowerShell activities on the host.

```kql
DeviceProcessEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc", "-encoded", "-e ", "bypass", "-nop", "-noni", 
    "hidden", "downloadstring", "invoke-expression", "iex", "webclient")
| project TimeGenerated, User=InitiatingProcessAccountName, 
    SuspiciousCommand=substring(ProcessCommandLine, 0, 200), 
    ParentProcess=InitiatingProcessFileName
```
**Activity Title**: `Suspicious PowerShell executed by {{User}}`

## 3. **New Service Installation**
Monitor new services being installed on hosts.

```kql
DeviceRegistryEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\"
| where RegistryValueName == "ImagePath"
| extend ServiceName = extract(@"Services\\([^\\]+)", 1, RegistryKey)
| project TimeGenerated, ServiceName, ServicePath=RegistryValueData, 
    InstalledBy=InitiatingProcessAccountName, Process=InitiatingProcessFileName
```
**Activity Title**: `New service '{{ServiceName}}' installed by {{InstalledBy}}`

## 4. **Persistence via Registry Run Keys**
Track registry modifications commonly used for persistence.

```kql
DeviceRegistryEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
| project TimeGenerated, PersistenceName=RegistryValueName, 
    PersistenceValue=RegistryValueData, User=InitiatingProcessAccountName,
    Process=InitiatingProcessFileName
```
**Activity Title**: `Registry persistence '{{PersistenceName}}' created by {{User}}`

## 5. **Network Scanning Activity**
Detect potential network scanning from the host.

```kql
DeviceNetworkEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ActionType == "ConnectionSuccess" or ActionType == "ConnectionFailed"
| summarize ConnectionCount = count(), 
    UniqueDestinations = dcount(RemoteIP),
    UniquePorts = dcount(RemotePort),
    PortList = make_set(RemotePort, 20)
    by bin(TimeGenerated, 1m), InitiatingProcessFileName, InitiatingProcessAccountName
| where UniqueDestinations > 10 or UniquePorts > 10
| project TimeGenerated, Process=InitiatingProcessFileName, 
    User=InitiatingProcessAccountName, UniqueDestinations, UniquePorts, PortList
```
**Activity Title**: `Network scanning detected from {{Process}} - {{UniqueDestinations}} IPs scanned`

## 6. **Privileged Account Logon**
Track when privileged accounts log onto the host.

```kql
DeviceLogonEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ActionType in ("LogonSuccess", "LogonAttempted")
| where AccountName endswith "-adm" or AccountName in~ ("Administrator", "admin", "root")
    or IsLocalAdmin == true
| project TimeGenerated, AccountName, AccountDomain, LogonType, 
    RemoteIP, RemoteDeviceName, Protocol
```
**Activity Title**: `Privileged account {{AccountName}} logged on via {{LogonType}}`

## 7. **USB Device Connection**
Monitor USB device connections to the host.

```kql
DeviceEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ActionType == "PnpDeviceConnected"
| extend ParsedFields = parse_json(AdditionalFields)
| where ParsedFields.ClassName in~ ("USB", "USBSTOR", "DiskDrive", "WPD")
| extend DeviceDescription = tostring(ParsedFields.DeviceDescription)
| extend VendorId = tostring(ParsedFields.VendorIds)
| project TimeGenerated, DeviceDescription, VendorId, 
    User=InitiatingProcessAccountName, DeviceId=tostring(ParsedFields.DeviceId)
```
**Activity Title**: `USB device connected: {{DeviceDescription}}`

## 8. **Firewall Rule Modifications**
Track changes to Windows Firewall rules.

```kql
DeviceProcessEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ProcessCommandLine has "netsh" and ProcessCommandLine has_any ("firewall", "advfirewall")
| where ProcessCommandLine has_any ("add", "set", "delete", "rule")
| project TimeGenerated, User=InitiatingProcessAccountName, 
    FirewallCommand=substring(ProcessCommandLine, 0, 300),
    Process=InitiatingProcessFileName
```
**Activity Title**: `Firewall rule modified by {{User}}`

## 9. **Scheduled Task Creation**
Monitor creation of scheduled tasks that could be used for persistence.

```kql
DeviceProcessEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| extend TaskName = extract(@'\/tn\s+"?([^"\s]+)"?', 1, ProcessCommandLine)
| extend TaskCommand = extract(@'\/tr\s+"?([^"]+)"?', 1, ProcessCommandLine)
| project TimeGenerated, TaskName, TaskCommand, 
    CreatedBy=InitiatingProcessAccountName, 
    ParentProcess=InitiatingProcessFileName
```
**Activity Title**: `Scheduled task '{{TaskName}}' created by {{CreatedBy}}`

## 10. **Remote Desktop Connections**
Track incoming RDP connections to the host.

```kql
DeviceLogonEvents
| where (ComputerName == '{{Host_HostName}}' and DeviceName contains '{{Host_NTDomain}}') 
    or DeviceId == '{{Host_AzureID}}'
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive" or Protocol == "RDP"
| where RemoteIP != "" and not(ipv4_is_private(RemoteIP))
| project TimeGenerated, AccountName, AccountDomain, 
    SourceIP=RemoteIP, SourceDevice=RemoteDeviceName, 
    IsAdmin=IsLocalAdmin
```
**Activity Title**: `RDP connection from {{SourceIP}} by {{AccountName}}`
