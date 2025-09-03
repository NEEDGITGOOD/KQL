# 1. Enable Managed Identity on Logic App
Logic app -> Identity -> System Assigned
Status: ON

# 2. Get the Object (Principal) ID from the System Assigned Identity
Logic app -> Identity -> System Assigned
Object (principal) ID -> COPY

# 3. Find the role we want (Service Principle ID & Role ID)
Lets says we want to have the role: 'WindowsDefenderATP.MachineIsolate'

List servicePrincipals: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0&tabs=http

POWERSHELL
```powershell
Import-Module Microsoft.Graph.Applications

$Permissions = Get-MgServicePrincipal -Filter "DisplayName eq 'WindowsDefenderATP'" 
$Permissions.AppRoles | Select-Object DisplayName, Value, Id, Description | ft
```

This shows you what Permissions you can assign:
```
DisplayName                                                        Value                                Id                                   Description
-----------                                                        -----                                --                                   -----------
Run live response on a specific machine                            Machine.LiveResponse                 1629b959-c0af-42a1-92f0-f6162060bdf1 Allows the app to run a live response on a specific machine
Read all IOCs                                                      Ti.Read.All                          528ca142-c849-4a5b-935e-10b8b9c38a84 Allows the app to read all IOCs
Read and Write Integration settings                                IntegrationConfiguration.ReadWrite   7c6f6912-60e9-4fcd-bb2a-c25bc35e8c59 Allows the app to read and modify integration settings between itself and the service
Security Operations - Read Only                                    readonly                             f820e656-f1d1-4cb8-a566-31d18eeecb40 Users assign to this role will be able to access the Windows Defender ATP portal, view all the data but will not be able to perform an…
Security Operations - Read & Write                                 secop                                2261fd4a-5f23-4b74-9e4d-f4ac92dc86a2 Users assign to this role will be able to access the Windows Defender ATP portal, view all the data and be able to perform actions suc…
Read and write all alerts                                          Alert.ReadWrite.All                  0f7000ec-157b-497f-b70e-ef0b0584f140 Allows the app to create or update any alert
Read and write IOCs belonging to the app                           Ti.ReadWrite                         a8bc2240-f96a-46a1-bad5-6a960b7327a1 Allows the app to create IOCs and to read or update IOCs it created
Write timeline events                                              Event.Write                          84ddd701-5fac-4c30-b0ad-aa73a67bea1a Allows the app to create events in the machine timeline
Run advanced queries                                               AdvancedQuery.Read.All               93489bf5-0fbc-4f2d-b901-33f2fe08ff05 Allows the app to run advanced queries
Read all machine profiles                                          Machine.Read.All                     ea8291d3-4b9a-44b5-bc3a-6cea3026dc79 Allows the app to read all machine profiles, including the commands that were sent to each machine
Read and write all machine information                             Machine.ReadWrite.All                aa027352-232b-4ed4-b963-a705fc4d6d2c Allows the app to create machine records and to read or update any machine record
Isolate machine                                                    Machine.Isolate                      7e4e1300-e1b9-4102-88ba-f0cb6e6d5974 Allows the app to isolate a machine
Scan machine                                                       Machine.Scan                         a86d9824-b2b6-45f8-b042-16bc4922ed4e Allows the app to scan a machine
Restrict code execution                                            Machine.RestrictExecution            96b6b35d-074d-4e2d-b167-8d68d9269648 Allows the app to restrict code execution on a machine according to policy
Stop and quarantine file                                           Machine.StopAndQuarantine            96e72b5e-7e68-4171-aad1-3937599e4751 Allows the app to stop a file running on a machine and to quarantine that file
Offboard machine                                                   Machine.Offboard                     594435bf-36dd-4548-83bd-1bdafe157d7a Allows the app to offboard a machine from the service
Read file profiles                                                 File.Read.All                        8788f1a9-beca-4e26-ba58-10513f3b896f Allows the app to read all file profiles
Read URL profiles                                                  Url.Read.All                         721af526-ffa8-42d7-9b84-1a56244dd99d Allows the app to read all URL profiles
Read IP address profiles                                           Ip.Read.All                          47bf842d-354b-49ef-b741-3a6dd815bc13 Allows the app to read all IP address profiles
Read user profiles                                                 User.Read.All                        a833834a-4cf1-4732-8acf-bbcfa13fb610 Allows the app to read all user profiles
Read all alerts                                                    Alert.Read.All                       71fe6b80-7034-4028-9ed8-0f316df9c3ff Allows the app to read any alert
Collect forensics                                                  Machine.CollectForensics             15405ab2-2103-4a3c-ad80-e829841cedcc Allows the app to collect forensics from a machine
Read and write all IOCs                                            Ti.ReadWrite.All                     fc511a58-3adf-4d71-af24-00f13e35e479 Allows the app to manage all IOCs of the tenant
Read Threat and Vulnerability Management security recommendations  SecurityRecommendation.Read.All      6443965c-7dd2-4cfd-b38f-bb7772bee163 Allows the app to read any Threat and Vulnerability Management security recommendation
Read Threat and Vulnerability Management software information      Software.Read.All                    37f71c98-d198-41ae-964d-2c49aab74926 Allows the app to read any Threat and Vulnerability Management software information
Read Threat and Vulnerability Management vulnerability information Vulnerability.Read.All               41269fc5-d04d-4bfd-bce7-43a51cea049a Allows the app to read any Threat and Vulnerability Management vulnerability information
Read Threat and Vulnerability Management score                     Score.Read.All                       02b005dd-f804-43b4-8fc7-078460413f74 Allows the app to read any Threat and Vulnerability Management  score
Read all remediation tasks                                         RemediationTasks.Read.All            6a33eedf-ba73-4e5a-821b-f057ef63853a Allows the app to read all remediation tasks
Manage live response library files                                 Library.Manage                       41d209c7-2511-4fc9-b899-8008a3976f09 Allows the app to manage live response library files
Read all security configurations                                   SecurityConfiguration.Read.All       227f2ea0-c2c2-4428-b7af-9ff40f1a720e Allows the app to read all security configurations
Read and write all security configurations                         SecurityConfiguration.ReadWrite.All  e5e05709-32a3-4c85-89c8-67596eb94f24 Allows the app to read and write all security configurations
Read all security baselines assessment information                 SecurityBaselinesAssessment.Read.All e870c0c1-c1a2-41ca-948e-a33912d2d3f0 Allows the app to read all security baselines assessment information
```

We need to get the ID of the Permission we want so we want "Isolate machine" the Id for it is "7e4e1300-e1b9-4102-88ba-f0cb6e6d5974"

# 3.1 Save Permission to Variable
Lets save that in an variable:

```powershell
$PermissionID = $Permissions.AppRoles | Select-Object DisplayName, Value, Id, Description | Where-Object DisplayName -eq "Isolate machine" | Select-Object Id
```

I'll complete the documentation with the final step to add the permission to the Logic App's service principal.

# 4. Add Permission to ServicePrincipal

Now we need to assign the app role to the Logic App's managed identity. We'll need:
- The Object (Principal) ID from the Logic App's managed identity (from Step 2)
- The Service Principal ID of WindowsDefenderATP
- The Permission/App Role ID (from Step 3)

## 4.1 Get the WindowsDefenderATP Service Principal ID

```powershell
$ServicePrincipalId = (Get-MgServicePrincipal -Filter "DisplayName eq 'WindowsDefenderATP'").Id
```

## 4.2 Assign the App Role to the Logic App's Managed Identity

Replace `<LOGIC_APP_PRINCIPAL_ID>` with the Object (Principal) ID you copied in Step 2:

```powershell
# Set the Logic App's Principal ID (from Step 2)
$LogicAppPrincipalId = "<LOGIC_APP_PRINCIPAL_ID>"

# Create the app role assignment
New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $LogicAppPrincipalId `
    -PrincipalId $LogicAppPrincipalId `
    -ResourceId $ServicePrincipalId `
    -AppRoleId "7e4e1300-e1b9-4102-88ba-f0cb6e6d5974"  # Isolate Machine ID as per Step 3.
```

## 4.3 Verify the Assignment

To verify that the permission has been successfully assigned:

```powershell
# Check the app role assignments for the Logic App
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $LogicAppPrincipalId | 
    Select-Object PrincipalDisplayName, ResourceDisplayName, AppRoleId | 
    Format-Table
```

You should see an entry showing:
- **PrincipalDisplayName**: Your Logic App name
- **ResourceDisplayName**: WindowsDefenderATP
- **AppRoleId**: 7e4e1300-e1b9-4102-88ba-f0cb6e6d5974

## Complete Script Example

Here's the complete PowerShell script that combines all steps:

```powershell
# Import required module
Import-Module Microsoft.Graph.Applications

# Step 1: Get the Logic App's Principal ID (replace with your actual ID)
$LogicAppPrincipalId = "<YOUR_LOGIC_APP_PRINCIPAL_ID>"

# Step 2: Get WindowsDefenderATP service principal and permissions
$DefenderService = Get-MgServicePrincipal -Filter "DisplayName eq 'WindowsDefenderATP'"
$ServicePrincipalId = $DefenderService.Id

# Step 3: Find the specific permission ID (Machine.Isolate)
$PermissionId = ($DefenderService.AppRoles | 
    Where-Object {$_.DisplayName -eq "Isolate machine"}).Id

# Step 4: Assign the app role to the Logic App
New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $LogicAppPrincipalId `
    -PrincipalId $LogicAppPrincipalId `
    -ResourceId $ServicePrincipalId `
    -AppRoleId $PermissionId

Write-Host "Permission 'Isolate machine' has been assigned to the Logic App" -ForegroundColor Green
```

LogicApp has the  Machine.Isolate Permission:
![LogicApp has the Machine.Isolate Permission](./Pasted%20image%2020250830184008.png)


# User Revoke Session

For UserRevokeSession do this:

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.All"

# Your Logic App Principal ID
$LogicAppPrincipalId = "<ID>"

# Get Microsoft Graph service principal
$GraphServicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'"

# Find User.RevokeSessions.All permission
$Permission = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq "User.RevokeSessions.All"}

if ($Permission) {
    Write-Host "Found permission: $($Permission.DisplayName) with ID: $($Permission.Id)" -ForegroundColor Green
    
    # Assign the permission
    New-MgServicePrincipalAppRoleAssignment `
        -ServicePrincipalId $LogicAppPrincipalId `
        -PrincipalId $LogicAppPrincipalId `
        -ResourceId $GraphServicePrincipal.Id `
        -AppRoleId $Permission.Id
    
    Write-Host "Permission 'User.RevokeSessions.All' has been assigned to the Logic App" -ForegroundColor Green
} else {
    Write-Host "Permission 'User.RevokeSessions.All' not found" -ForegroundColor Red
}
```

LogicApp has now the RevokeUserSessions Permission:
![LogicApp has now the RevokeUserSessions Permission](./Pasted%20image%2020250830184023.png)

# Adding new rights (quick and easy)

You can add new rights really easily like for "User.Read.All":
```powershell
$LogicAppPrincipalId = "<ID>"
$GraphServicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'"

# Add User.Read.All permission
$UserReadPermission = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq "User.Read.All"}
New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $LogicAppPrincipalId `
    -PrincipalId $LogicAppPrincipalId `
    -ResourceId $GraphServicePrincipal.Id `
    -AppRoleId $UserReadPermission.Id
```
