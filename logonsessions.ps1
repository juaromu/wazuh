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