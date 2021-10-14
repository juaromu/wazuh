**WAZUH AND SYSINTERNALS**
# Intro

Wazuh and Sysinternals integrations.

Some of the integrations included here require remote commands execution enabled in the agents.

File “local_internal_options.conf”:


```
# Wazuh Command Module - If it should accept remote commands from the manager
wazuh_command.remote_commands=1
```

All settings and configurations in this document assume that sysinternals binaries have been placed in the folder “C:\Program Files\sysinternals”.

Review Wazuh rule IDs used for detection to discard overlapping in your own Wazuh deployment.


# 


# Sysinternals - Autoruns


## Description

[Sysinternals Autoruns - Official documentation.](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)


## Wazuh Integration

Wazuh Capability: Wodles Command

Log Output: Active Response Log

MITRE: [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

Edit agent configuration in Wazuh manager (shared/groups)
(/var/ossec/etc/shared/your_windows_agents_group/agent.conf)

```
<wodle name="command">
  <disabled>no</disabled>
  <tag>autoruns</tag>
  <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\autoruns.ps1"</command>
  <interval>1d</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>

```
Content of “autoruns.ps1”:

```
################################
### Script to execute Sysinternals/Autoruns
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# Script execution triggered by Wazuh Manager, wodles-command
# Output converted to JSON and appended to active-responses.log
##########
$ErrorActionPreference = "SilentlyContinue"
# If Autoruns already running do nothing
$autoruns_running = Get-Process autorunsc64 -ErrorAction SilentlyContinue
if ($autoruns_running) { Exit }
# TEMP FOLDER TO STORE AUTORUNS OUTPUT, CSV FILE
$OutPath = $env:TMP
$autorunsCsv = 'autorunsCsv.csv'
# RUN AUTORUNS AND STORE CSV
Start-Process -FilePath "c:\Program Files\Sysinternals\Autorunsc64.exe" -ArgumentList '-nobanner', '/accepteula', '-a *', '-c', '-h', '-s', '-v', '-vt' -RedirectStandardOut $OutPath\$autorunsCsv -WindowStyle hidden -Passthru -Wait
# REMOVE SPACES IN CSV HEADER AND CONVERT TO ARRAY
$autorunsArray = Get-Content $OutPath\$autorunsCsv
$autorunsArray[0] = $autorunsArray[0] -replace " ", ""
$autorunsArray | Set-Content $OutPath\$autorunsCsv
$autorunsArray = Import-Csv $OutPath\$autorunsCsv
# GO THRU THE ARRAY, CONVERT TO JSON AND APPEND TO active-responses.log
$count = 0
Foreach ($item in $autorunsArray) {
# CHECK IF VIRUS TOTAL MATCH OR UNKNOWN HASH
    if ($item."VTdetection") {
     if (-Not ($item."VTdetection" -match '^0')) {
     echo  $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
# Sleep 2 seconds every 5 runs
     if(++$count % 5 -eq 0) {Start-Sleep -Seconds 2}
     }
    }
}
# DETECTION RULE:
#<group name="windows,">
#<rule id="91550" level="12">
#  <decoded_as>json</decoded_as>
#  <field name="Entry">\.+</field>
#  <field name="EntryLocation">\.+</field>
#  <description>Windows Autoruns - VirusTotal Hit</description>
#  <mitre>
#   <id>T1547</id>
#  </mitre>
#  <options>no_full_log</options>
#  <group>windows_autoruns,</group>
#</rule>
#<rule id="91551" level="10">
#  <if_sid>91550</if_sid>
#  <field name="VTdetection">Unknown</field>
#  <description>Windows Autoruns - VirusTotal Unknown Signature</description>
#  <mitre>
#   <id>T1547</id>
#  </mitre>
#  <options>no_full_log</options>
#  <group>windows_autoruns,</group>
#</rule>
#</group>
```

Wazuh Rules: `/var/ossec/etc/rules/win_autoruns_rules.xml`

```
<group name="windows,">
<rule id="91550" level="12">
  <decoded_as>json</decoded_as>
  <field name="Entry">\.+</field>
  <field name="EntryLocation">\.+</field>
  <description>Windows Autoruns - VirusTotal Hit</description>
  <mitre>
   <id>T1547</id>
  </mitre>
  <options>no_full_log</options>
  <group>windows_autoruns,</group>
</rule>
<rule id="91551" level="10">
  <if_sid>91550</if_sid>
  <field name="VTdetection">Unknown</field>
  <description>Windows Autoruns - VirusTotal Unknown Signature</description>
  <mitre>
   <id>T1547</id>
  </mitre>
  <options>no_full_log</options>
  <group>windows_autoruns,</group>
</rule>
</group>
```

Alerts (examples) - Unknown signature in VirusTotal:

```
{
  "timestamp":"2021-10-02T18:08:51.174+1000",
  "rule":{
     "level":10,
     "description":"Windows Autoruns - VirusTotal Unknown Signature",
     "id":"91551",
     "mitre":{
        "id":[
           "T1547"
        ]
     },
     "firedtimes":7,
     "mail":false,
     "groups":[
        "windows",
        "windows_autoruns"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1633162131.503091800",
  "decoder":{
     "name":"json"
  },
  "data":{
     "EntryLocation":"HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls",
     "Entry":"wow64win",
     "Enabled":"enabled",
     "Category":"Known DLLs",
     "Profile":"System-wide",
     "ImagePath":"c:\\windows\\syswow64\\wow64win.dll",
     "LaunchString":"wow64win.dll",
     "VTdetection":"Unknown",
     "VTpermalink":"n/a"
  },
  "location":"active-response\\active-responses.log"
}
```

Alerts (examples) - Signature found in VirusTotal:

```
 {
  "timestamp":"2021-10-02T18:08:51.065+1000",
  "rule":{
     "level":12,
     "description":"Windows Autoruns - VirusTotal Hit",
     "id":"91550",
     "mitre":{
        "id":[
           "T1547"
        ]
     },
     "firedtimes":3,
     "mail":true,
     "groups":[
        "windows",
        "windows_autoruns"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1633162131.503082888",
  "decoder":{
     "name":"json"
  },
  "data":{
     "Time":"14/04/1954 6:59 PM",
     "EntryLocation":"HKLM\\System\\CurrentControlSet\\Services",
     "Entry":"RasGre",
     "Enabled":"enabled",
     "Category":"Drivers",
     "Profile":"System-wide",
     "Description":"WAN Miniport (GRE): WAN Miniport (GRE)",
     "Signer":"Microsoft Corporation",
     "Company":"Microsoft Corporation",
     "ImagePath":"c:\\windows\\system32\\drivers\\rasgre.sys",
     "Version":"10.0.17763.1",
     "LaunchString":"\\SystemRoot\\System32\\drivers\\rasgre.sys",
     "VTdetection":"1|72",
     "VTpermalink":"https://www.virustotal.com/gui/file/d2b3066d4290ca61dd82e57dc9a1c4cbee49b4de31897b86bcd4dcdb46582f81/detection",
     "MD5":"5008678D3AC377C4D6EC605D75F56C6E",
     "SHA-1":"690EB8BB80C9A27AC33DC8AF784A7F3D678098F4",
     "PESHA-1":"B9FDF1E913C753AA2FC69AF6A2AB596946D6DC44",
     "PESHA-256":"09F88B061C6055CB5A43BE3A565227DB8447DC0151ABABE95FC6BF81AA4E6DE2",
     "SHA-256":"D2B3066D4290CA61DD82E57DC9A1C4CBEE49B4DE31897B86BCD4DCDB46582F81",
     "IMP":"3AF9DD088A7CF3AF92624C65B215F2AB"
  },
  "location":"active-response\\active-responses.log"
}
```

# Sysinternals - Logonsessions


## Description

[Sysinternals Logonsessions - Official documentation.](https://docs.microsoft.com/en-us/sysinternals/downloads/logonsessions)

## Wazuh Integration

Wazuh Capability: Wodles Command

Log Output: Active Response Log

MITRE: [T1078](https://attack.mitre.org/techniques/T1078/)

Edit agent configuration in Wazuh manager (shared/groups)

(/var/ossec/etc/shared/your_windows_agents_group/agent.conf)

```
 <wodle name="command">
  <disabled>no</disabled>
  <tag>autoruns</tag>
  <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\logonsessions.ps1"</command>
  <interval>1h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>

```

File “logonsessions.ps1”:

```
################################
### Script to execute Sysinternals/Logonsessions
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# Script execution triggered by Wazuh Manager, wodles-command
# Output converted to JSON and appended to active-responses.log
##########
# RUN LOGONSESSIONS AND STORE CSV
$Sessions_Output_CSV = c:\"Program Files"\Sysinternals\logonsessions.exe  -nobanner -c -p
# REMOVE SPACES IN CSV HEADER AND CONVERT TO ARRAY
$Sessions_Output_Array = $Sessions_Output_CSV.PSObject.BaseObject.Trim(' ') -Replace '\s','' | ConvertFrom-Csv
# GO THRU THE ARRAY, CONVERT TO JSON AND APPEND TO active-responses.log
Foreach ($item in $Sessions_Output_Array) {
  echo  $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
 }
# DETECTION RULE:
#<group name="windows,">
#<rule id="91570" level="3">
#  <decoded_as>json</decoded_as>
#  <field name="LogonSession">\.+</field>
#  <field name="UserName">\.+</field>
#  <description>Windows Logon Sessions - Snapshot</description>
#  <mitre>
#   <id>T1078</id>
#  </mitre>
#  <options>no_full_log</options>
#  <group>windows_logonsessions,</group>
#</rule>
#</group>
```
Rules “win_logonsessions_rules.xml”:

```
<group name="windows,">
<rule id="91570" level="3">
  <decoded_as>json</decoded_as>
  <field name="LogonSession">\.+</field>
  <field name="UserName">\.+</field>
  <description>Windows Logon Sessions - Snapshot</description>
  <mitre>
   <id>T1078</id>
  </mitre>
  <options>no_full_log</options>
  <group>windows_logonsessions,</group>
</rule>
</group>
```

Alerts (example):

```
{
   "timestamp":"2021-10-04T07:39:53.313+1100",
   "rule":{
      "level":3,
      "description":"Windows Logon Sessions - Snapshot",
      "id":"91570",
      "mitre":{
         "id":[
            "T1078"
         ],
         "tactic":[
            "Defense Evasion",
            "Initial Access",
            "Persistence",
            "Privilege Escalation"
         ],
         "technique":[
            "Valid Accounts"
         ]
      },
      "firedtimes":75,
      "mail":false,
      "groups":[
         "windows",
         "windows_logonsessions"
      ]
   },
   "agent":{
      "id":"034",
      "name":"WIN-7FK8M79Q5R6",
      "ip":"192.168.252.105"
   },
   "manager":{
      "name":"tactical"
   },
   "id":"1633293593.309209621",
   "decoder":{
      "name":"json"
   },
   "data":{
      "LogonSession":"00000000:000003e5",
      "UserName":"NTAUTHORITY\\LOCALSERVICE",
      "AuthPackage":"Negotiate",
      "LogonType":"Service",
      "Session":"0",
      "Sid":"S-1-5-19",
      "LogonTime":"14/09/20219:25:03AM",
      "Processes":"376:svchost.exe;464:svchost.exe;444:svchost.exe;344:svchost.exe;1168:svchost.exe;1188:svchost.exe;1312:svchost.exe;1428:svchost.exe;1708:svchost.exe;1740:svchost.exe;1944:svchost.exe;2728:svchost.exe;2836:svchost.exe;2816:svchost.exe;1156:svchost.exe;1680:svchost.exe;6936:svchost.exe;4980:svchost.exe;"
   },
   "location":"active-response\\active-responses.log"
}
```


## 

# Sysinternals - Sigcheck

## Description

[Sysinternals Sigcheck - Official documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck).

## Wazuh Integration

Wazuh Capability: Wodles Command

Log Output: Active Response Log


## MITRE: [T1036](https://attack.mitre.org/techniques/T1036/)

Rationale: Identify executables in Users folders and run their file hashes in VirusTotal.

Edit agent configuration in Wazuh manager (shared/groups)

(/var/ossec/etc/shared/your_windows_agents_group/agent.conf)

```
 <wodle name="command">
  <disabled>no</disabled>
  <tag>autoruns</tag>
  <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\sigcheck.ps1"</command>
  <interval>1d</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>

```

File “sigcheck.ps1”:

```
################################
### Script to execute Sysinternals/Sigcheck - Identify VirusTotal hits in Binaries/Exec Files
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# Sigcheck will be run against all executables found in C:\Users\ and subfolders
# Script execution triggered by Wazuh Manager, wodles-command
# Output converted to JSON and appended to active-responses.log
##########
# If Sigcheck already running do nothing
$ErrorActionPreference = "SilentlyContinue"
$sigcheck_running = Get-Process sigcheck -ErrorAction SilentlyContinue
if ($sigcheck_running) { Exit }
# RUN SIGCHECK AND STORE CSV
$Sigcheck_Output_CSV = c:\"Program Files"\Sysinternals\sigcheck.exe -nobanner -accepteula -u -c -v -vt -e -s C:\Users\
# REMOVE SPACES IN CSV HEADER AND CONVERT TO ARRAY
$Sigcheck_Output_Array = $Sigcheck_Output_CSV.PSObject.BaseObject.Trim(' ') -Replace '\s','' | ConvertFrom-Csv
# GO THRU THE ARRAY, CONVERT TO JSON AND APPEND TO active-responses.log
$count = 0
Foreach ($item in $Sigcheck_Output_Array) {
# Discard alert if No VT Hits
 if ((-Not ($item."VTdetection" -match '^0')) -And ($item."VTdetection" -match '^\d+')) {
  echo $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
# Sleep 2 seconds every 5 runs
 if(++$count % 5 -eq 0) 
    {
        Start-Sleep -Seconds 2
    }
 }
}
####### Wazuh Rule
#<group name="windows,">
#<rule id="91560" level="12">
#  <decoded_as>json</decoded_as> 
#  <field name="Path">\.+</field>    
#  <field name="Verified">\.+</field>
#  <description>Windows Sigcheck - VirusTotal Hit</description>
#  <mitre>
#   <id>T1036</id>
#  </mitre>
#  <options>no_full_log</options>
#  <group>windows_sigcheck,</group>
#</rule>
#</group>
```

Rules “win_sigcheck_rules.xml”:

```
<group name="windows,">
<rule id="91560" level="12">
  <decoded_as>json</decoded_as>
  <field name="Path">\.+</field>
  <field name="Verified">\.+</field>
  <description>Windows Sigcheck - VirusTotal Hit</description>
  <mitre>
   <id>T1036</id>
  </mitre>
  <options>no_full_log</options>
  <group>windows_sigcheck,</group>
</rule>
</group>
```

Alerts (example):

```
{
   "timestamp":"2021-10-05T08:04:57.315+1100",
   "rule":{
      "level":12,
      "description":"Windows Sigcheck - VirusTotal Hit",
      "id":"91560",
      "mitre":{
         "id":[
            "T1036"
         ],
         "tactic":[
            "Defense Evasion"
         ],
         "technique":[
            "Masquerading"
         ]
      },
      "firedtimes":13,
      "mail":false,
      "groups":[
         "windows",
         "windows_sigcheck"
      ]
   },
   "agent":{
      "id":"009",
      "name":"ANSYDWDC01",
      "ip":"192.168.252.108"
   },
   "manager":{
      "name":"tactical"
   },
   "id":"1633381497.280732828",
   "decoder":{
      "name":"json"
   },
   "data":{
      "Path":"c:\\users\\Administrator\\Documents\\Vbs_To_Exe\\Portable\\Vbs_To_Exe_(x64).exe",
      "Verified":"Unsigned",
      "Date":"11:50AM4/20/2015",
      "Publisher":"n/a",
      "Company":"FatihKodak",
      "Description":"VbsToExe",
      "Product":"VbsToExe",
      "ProductVersion":"2.0.2",
      "FileVersion":"2.0.2",
      "MachineType":"64-bit",
      "VTdetection":"1|76",
      "VTlink":"https://www.virustotal.com/gui/file/fb142d66c5b92a9db6c82d78abee0ebc7ac756e33bcf931cd9ce116a42c867c1/detection"
   },
   "location":"active-response\\active-responses.log"
}
```

# Sysinternals - Sysmon

## Description

[Sysinternals Sysmon - Official documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

## Wazuh Integration

Wazuh Capability: Existing Sysmon Rules

Log Output: Wazuh Alerts


## MITRE: Several TTPs. (see below for details)

Sysmon Config File: [Olaf Hartong](https://github.com/olafhartong/sysmon-modular)

Map TTPs already included in the sysmon events to Wazuh’s MITRE ID.

(See each rule file for details).
