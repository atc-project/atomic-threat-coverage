| Title                    | System File Execution Location Anomaly       |
|:-------------------------|:------------------|
| **Description**          | Detects a Windows program executable started in a suspicious folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Exotic software</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/GelosSnake/status/934900723426439170](https://twitter.com/GelosSnake/status/934900723426439170)</li></ul>  |
| **Author**               | Florian Roth, Patrick Bareiss |


## Detection Rules

### Sigma rule

```
title: System File Execution Location Anomaly
id: e4a6b256-3e47-40fc-89d2-7a477edd6915
status: experimental
description: Detects a Windows program executable started in a suspicious folder
references:
    - https://twitter.com/GelosSnake/status/934900723426439170
author: Florian Roth, Patrick Bareiss
date: 2017/11/27
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\svchost.exe'
            - '*\rundll32.exe'
            - '*\services.exe'
            - '*\powershell.exe'
            - '*\regsvr32.exe'
            - '*\spoolsv.exe'
            - '*\lsass.exe'
            - '*\smss.exe'
            - '*\csrss.exe'
            - '*\conhost.exe'
            - '*\wininit.exe'
            - '*\lsm.exe'
            - '*\winlogon.exe'
            - '*\explorer.exe'
            - '*\taskhost.exe'
    filter:
        Image:
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\system32\\*'
            - 'C:\Windows\SysWow64\\*'
            - 'C:\Windows\SysWOW64\\*'
            - 'C:\Windows\explorer.exe'
            - 'C:\Windows\winsxs\\*'
            - 'C:\Windows\WinSxS\\*'
            - '\SystemRoot\System32\\*'
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - Image
falsepositives:
    - Exotic software
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\svchost.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\services.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\spoolsv.exe" -or $_.message -match "Image.*.*\\lsass.exe" -or $_.message -match "Image.*.*\\smss.exe" -or $_.message -match "Image.*.*\\csrss.exe" -or $_.message -match "Image.*.*\\conhost.exe" -or $_.message -match "Image.*.*\\wininit.exe" -or $_.message -match "Image.*.*\\lsm.exe" -or $_.message -match "Image.*.*\\winlogon.exe" -or $_.message -match "Image.*.*\\explorer.exe" -or $_.message -match "Image.*.*\\taskhost.exe") -and  -not (($_.message -match "Image.*C:\\Windows\\System32\\.*" -or $_.message -match "Image.*C:\\Windows\\system32\\.*" -or $_.message -match "Image.*C:\\Windows\\SysWow64\\.*" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\.*" -or $_.message -match "C:\\Windows\\explorer.exe" -or $_.message -match "Image.*C:\\Windows\\winsxs\\.*" -or $_.message -match "Image.*C:\\Windows\\WinSxS\\.*" -or $_.message -match "Image.*\\SystemRoot\\System32\\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\svchost.exe OR *\\rundll32.exe OR *\\services.exe OR *\\powershell.exe OR *\\regsvr32.exe OR *\\spoolsv.exe OR *\\lsass.exe OR *\\smss.exe OR *\\csrss.exe OR *\\conhost.exe OR *\\wininit.exe OR *\\lsm.exe OR *\\winlogon.exe OR *\\explorer.exe OR *\\taskhost.exe) AND (NOT (winlog.event_data.Image.keyword:(C\:\\Windows\\System32\\* OR C\:\\Windows\\system32\\* OR C\:\\Windows\\SysWow64\\* OR C\:\\Windows\\SysWOW64\\* OR C\:\\Windows\\explorer.exe OR C\:\\Windows\\winsxs\\* OR C\:\\Windows\\WinSxS\\* OR \\SystemRoot\\System32\\*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e4a6b256-3e47-40fc-89d2-7a477edd6915 <<EOF
{
  "metadata": {
    "title": "System File Execution Location Anomaly",
    "description": "Detects a Windows program executable started in a suspicious folder",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\svchost.exe OR *\\\\rundll32.exe OR *\\\\services.exe OR *\\\\powershell.exe OR *\\\\regsvr32.exe OR *\\\\spoolsv.exe OR *\\\\lsass.exe OR *\\\\smss.exe OR *\\\\csrss.exe OR *\\\\conhost.exe OR *\\\\wininit.exe OR *\\\\lsm.exe OR *\\\\winlogon.exe OR *\\\\explorer.exe OR *\\\\taskhost.exe) AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\system32\\\\* OR C\\:\\\\Windows\\\\SysWow64\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\* OR C\\:\\\\Windows\\\\explorer.exe OR C\\:\\\\Windows\\\\winsxs\\\\* OR C\\:\\\\Windows\\\\WinSxS\\\\* OR \\\\SystemRoot\\\\System32\\\\*))))"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "(winlog.event_data.Image.keyword:(*\\\\svchost.exe OR *\\\\rundll32.exe OR *\\\\services.exe OR *\\\\powershell.exe OR *\\\\regsvr32.exe OR *\\\\spoolsv.exe OR *\\\\lsass.exe OR *\\\\smss.exe OR *\\\\csrss.exe OR *\\\\conhost.exe OR *\\\\wininit.exe OR *\\\\lsm.exe OR *\\\\winlogon.exe OR *\\\\explorer.exe OR *\\\\taskhost.exe) AND (NOT (winlog.event_data.Image.keyword:(C\\:\\\\Windows\\\\System32\\\\* OR C\\:\\\\Windows\\\\system32\\\\* OR C\\:\\\\Windows\\\\SysWow64\\\\* OR C\\:\\\\Windows\\\\SysWOW64\\\\* OR C\\:\\\\Windows\\\\explorer.exe OR C\\:\\\\Windows\\\\winsxs\\\\* OR C\\:\\\\Windows\\\\WinSxS\\\\* OR \\\\SystemRoot\\\\System32\\\\*))))",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'System File Execution Location Anomaly'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n       Image = {{_source.Image}}================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
(Image.keyword:(*\\svchost.exe *\\rundll32.exe *\\services.exe *\\powershell.exe *\\regsvr32.exe *\\spoolsv.exe *\\lsass.exe *\\smss.exe *\\csrss.exe *\\conhost.exe *\\wininit.exe *\\lsm.exe *\\winlogon.exe *\\explorer.exe *\\taskhost.exe) AND (NOT (Image.keyword:(C\:\\Windows\\System32\\* C\:\\Windows\\system32\\* C\:\\Windows\\SysWow64\\* C\:\\Windows\\SysWOW64\\* C\:\\Windows\\explorer.exe C\:\\Windows\\winsxs\\* C\:\\Windows\\WinSxS\\* \\SystemRoot\\System32\\*))))
```


### splunk
    
```
((Image="*\\svchost.exe" OR Image="*\\rundll32.exe" OR Image="*\\services.exe" OR Image="*\\powershell.exe" OR Image="*\\regsvr32.exe" OR Image="*\\spoolsv.exe" OR Image="*\\lsass.exe" OR Image="*\\smss.exe" OR Image="*\\csrss.exe" OR Image="*\\conhost.exe" OR Image="*\\wininit.exe" OR Image="*\\lsm.exe" OR Image="*\\winlogon.exe" OR Image="*\\explorer.exe" OR Image="*\\taskhost.exe") NOT ((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\system32\\*" OR Image="C:\\Windows\\SysWow64\\*" OR Image="C:\\Windows\\SysWOW64\\*" OR Image="C:\\Windows\\explorer.exe" OR Image="C:\\Windows\\winsxs\\*" OR Image="C:\\Windows\\WinSxS\\*" OR Image="\\SystemRoot\\System32\\*"))) | table ComputerName,User,Image
```


### logpoint
    
```
(Image IN ["*\\svchost.exe", "*\\rundll32.exe", "*\\services.exe", "*\\powershell.exe", "*\\regsvr32.exe", "*\\spoolsv.exe", "*\\lsass.exe", "*\\smss.exe", "*\\csrss.exe", "*\\conhost.exe", "*\\wininit.exe", "*\\lsm.exe", "*\\winlogon.exe", "*\\explorer.exe", "*\\taskhost.exe"]  -(Image IN ["C:\\Windows\\System32\\*", "C:\\Windows\\system32\\*", "C:\\Windows\\SysWow64\\*", "C:\\Windows\\SysWOW64\\*", "C:\\Windows\\explorer.exe", "C:\\Windows\\winsxs\\*", "C:\\Windows\\WinSxS\\*", "\\SystemRoot\\System32\\*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\svchost\.exe|.*.*\rundll32\.exe|.*.*\services\.exe|.*.*\powershell\.exe|.*.*\regsvr32\.exe|.*.*\spoolsv\.exe|.*.*\lsass\.exe|.*.*\smss\.exe|.*.*\csrss\.exe|.*.*\conhost\.exe|.*.*\wininit\.exe|.*.*\lsm\.exe|.*.*\winlogon\.exe|.*.*\explorer\.exe|.*.*\taskhost\.exe))(?=.*(?!.*(?:.*(?=.*(?:.*C:\Windows\System32\\.*|.*C:\Windows\system32\\.*|.*C:\Windows\SysWow64\\.*|.*C:\Windows\SysWOW64\\.*|.*C:\Windows\explorer\.exe|.*C:\Windows\winsxs\\.*|.*C:\Windows\WinSxS\\.*|.*\SystemRoot\System32\\.*))))))'
```



