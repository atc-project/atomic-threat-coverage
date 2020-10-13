| Title                    | Netsh Program Allowed with Suspcious Location       |
|:-------------------------|:------------------|
| **Description**          | Detects Netsh commands that allows a suspcious application location on Windows Firewall |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1562.004: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1562.004: Disable or Modify System Firewall](../Triggers/T1562.004.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate administration</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.virusradar.com/en/Win32_Kasidet.AD/description](https://www.virusradar.com/en/Win32_Kasidet.AD/description)</li><li>[https://www.hybrid-analysis.com/sample/07e789f4f2f3259e7559fdccb36e96814c2dbff872a21e1fa03de9ee377d581f?environmentId=100](https://www.hybrid-analysis.com/sample/07e789f4f2f3259e7559fdccb36e96814c2dbff872a21e1fa03de9ee377d581f?environmentId=100)</li></ul>  |
| **Author**               | Sander Wiebing |


## Detection Rules

### Sigma rule

```
title: Netsh Program Allowed with Suspcious Location
id: a35f5a72-f347-4e36-8895-9869b0d5fc6d 
description: Detects Netsh commands that allows a suspcious application location on Windows Firewall
references:
    - https://www.virusradar.com/en/Win32_Kasidet.AD/description
    - https://www.hybrid-analysis.com/sample/07e789f4f2f3259e7559fdccb36e96814c2dbff872a21e1fa03de9ee377d581f?environmentId=100
date: 2020/05/25
modified: 2020/09/01
tags:
    - attack.defense_evasion
    - attack.t1089          # an old one
    - attack.t1562.004
status: experimental
author: Sander Wiebing
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - 'netsh'
            - 'firewall add allowedprogram'
    selection2:
        CommandLine|contains|all:
            - netsh
            - advfirewall firewall add rule
            - action=allow
            - program=
    susp_image:
        CommandLine|contains:
            - '*%TEMP%*'
            - '*:\RECYCLER\\*'
            - '*C:\$Recycle.bin\\*'
            - '*:\SystemVolumeInformation\\*'
            - 'C:\\Windows\\Tasks\\*'
            - 'C:\\Windows\\debug\\*'
            - 'C:\\Windows\\fonts\\*'
            - 'C:\\Windows\\help\\*'
            - 'C:\\Windows\\drivers\\*'
            - 'C:\\Windows\\addins\\*'
            - 'C:\\Windows\\cursors\\*'
            - 'C:\\Windows\\system32\tasks\\*'
            - '*C:\Windows\Temp\\*'
            - '*C:\Temp\\*'
            - '*C:\Users\Public\\*'
            - '%Public%\\*'
            - '*C:\Users\Default\\*'
            - '*C:\Users\Desktop\\*'
            - '*\Downloads\\*'
            - '*\Temporary Internet Files\Content.Outlook\\*'
            - '*\Local Settings\Temporary Internet Files\\*'
    condition: (selection1 or selection2) and susp_image
falsepositives:
    - Legitimate administration
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*netsh.*" -and ($_.message -match "CommandLine.*.*firewall add allowedprogram.*" -or ($_.message -match "CommandLine.*.*advfirewall firewall add rule.*" -and $_.message -match "CommandLine.*.*action=allow.*" -and $_.message -match "CommandLine.*.*program=.*")) -and ($_.message -match "CommandLine.*.*%TEMP%.*" -or $_.message -match "CommandLine.*.*:\\RECYCLER\\.*" -or $_.message -match "CommandLine.*.*C:\\$Recycle.bin\\.*" -or $_.message -match "CommandLine.*.*:\\SystemVolumeInformation\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\Tasks\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\debug\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\fonts\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\help\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\drivers\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\addins\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\cursors\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\system32\\tasks\\.*" -or $_.message -match "CommandLine.*.*C:\\Windows\\Temp\\.*" -or $_.message -match "CommandLine.*.*C:\\Temp\\.*" -or $_.message -match "CommandLine.*.*C:\\Users\\Public\\.*" -or $_.message -match "CommandLine.*.*%Public%\\.*" -or $_.message -match "CommandLine.*.*C:\\Users\\Default\\.*" -or $_.message -match "CommandLine.*.*C:\\Users\\Desktop\\.*" -or $_.message -match "CommandLine.*.*\\Downloads\\.*" -or $_.message -match "CommandLine.*.*\\Temporary Internet Files\\Content.Outlook\\.*" -or $_.message -match "CommandLine.*.*\\Local Settings\\Temporary Internet Files\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*netsh* AND (winlog.event_data.CommandLine.keyword:*firewall\ add\ allowedprogram* OR (winlog.event_data.CommandLine.keyword:*advfirewall\ firewall\ add\ rule* AND winlog.event_data.CommandLine.keyword:*action\=allow* AND winlog.event_data.CommandLine.keyword:*program\=*)) AND winlog.event_data.CommandLine.keyword:(*%TEMP%* OR *\:\\RECYCLER\\* OR *C\:\\$Recycle.bin\\* OR *\:\\SystemVolumeInformation\\* OR *C\:\\Windows\\Tasks\\* OR *C\:\\Windows\\debug\\* OR *C\:\\Windows\\fonts\\* OR *C\:\\Windows\\help\\* OR *C\:\\Windows\\drivers\\* OR *C\:\\Windows\\addins\\* OR *C\:\\Windows\\cursors\\* OR *C\:\\Windows\\system32\\tasks\\* OR *C\:\\Windows\\Temp\\* OR *C\:\\Temp\\* OR *C\:\\Users\\Public\\* OR *%Public%\\* OR *C\:\\Users\\Default\\* OR *C\:\\Users\\Desktop\\* OR *\\Downloads\\* OR *\\Temporary\ Internet\ Files\\Content.Outlook\\* OR *\\Local\ Settings\\Temporary\ Internet\ Files\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a35f5a72-f347-4e36-8895-9869b0d5fc6d <<EOF
{
  "metadata": {
    "title": "Netsh Program Allowed with Suspcious Location",
    "description": "Detects Netsh commands that allows a suspcious application location on Windows Firewall",
    "tags": [
      "attack.defense_evasion",
      "attack.t1089",
      "attack.t1562.004"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*netsh* AND (winlog.event_data.CommandLine.keyword:*firewall\\ add\\ allowedprogram* OR (winlog.event_data.CommandLine.keyword:*advfirewall\\ firewall\\ add\\ rule* AND winlog.event_data.CommandLine.keyword:*action\\=allow* AND winlog.event_data.CommandLine.keyword:*program\\=*)) AND winlog.event_data.CommandLine.keyword:(*%TEMP%* OR *\\:\\\\RECYCLER\\\\* OR *C\\:\\\\$Recycle.bin\\\\* OR *\\:\\\\SystemVolumeInformation\\\\* OR *C\\:\\\\Windows\\\\Tasks\\\\* OR *C\\:\\\\Windows\\\\debug\\\\* OR *C\\:\\\\Windows\\\\fonts\\\\* OR *C\\:\\\\Windows\\\\help\\\\* OR *C\\:\\\\Windows\\\\drivers\\\\* OR *C\\:\\\\Windows\\\\addins\\\\* OR *C\\:\\\\Windows\\\\cursors\\\\* OR *C\\:\\\\Windows\\\\system32\\\\tasks\\\\* OR *C\\:\\\\Windows\\\\Temp\\\\* OR *C\\:\\\\Temp\\\\* OR *C\\:\\\\Users\\\\Public\\\\* OR *%Public%\\\\* OR *C\\:\\\\Users\\\\Default\\\\* OR *C\\:\\\\Users\\\\Desktop\\\\* OR *\\\\Downloads\\\\* OR *\\\\Temporary\\ Internet\\ Files\\\\Content.Outlook\\\\* OR *\\\\Local\\ Settings\\\\Temporary\\ Internet\\ Files\\\\*))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*netsh* AND (winlog.event_data.CommandLine.keyword:*firewall\\ add\\ allowedprogram* OR (winlog.event_data.CommandLine.keyword:*advfirewall\\ firewall\\ add\\ rule* AND winlog.event_data.CommandLine.keyword:*action\\=allow* AND winlog.event_data.CommandLine.keyword:*program\\=*)) AND winlog.event_data.CommandLine.keyword:(*%TEMP%* OR *\\:\\\\RECYCLER\\\\* OR *C\\:\\\\$Recycle.bin\\\\* OR *\\:\\\\SystemVolumeInformation\\\\* OR *C\\:\\\\Windows\\\\Tasks\\\\* OR *C\\:\\\\Windows\\\\debug\\\\* OR *C\\:\\\\Windows\\\\fonts\\\\* OR *C\\:\\\\Windows\\\\help\\\\* OR *C\\:\\\\Windows\\\\drivers\\\\* OR *C\\:\\\\Windows\\\\addins\\\\* OR *C\\:\\\\Windows\\\\cursors\\\\* OR *C\\:\\\\Windows\\\\system32\\\\tasks\\\\* OR *C\\:\\\\Windows\\\\Temp\\\\* OR *C\\:\\\\Temp\\\\* OR *C\\:\\\\Users\\\\Public\\\\* OR *%Public%\\\\* OR *C\\:\\\\Users\\\\Default\\\\* OR *C\\:\\\\Users\\\\Desktop\\\\* OR *\\\\Downloads\\\\* OR *\\\\Temporary\\ Internet\\ Files\\\\Content.Outlook\\\\* OR *\\\\Local\\ Settings\\\\Temporary\\ Internet\\ Files\\\\*))",
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
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Netsh Program Allowed with Suspcious Location'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
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
(CommandLine.keyword:*netsh* AND (CommandLine.keyword:*firewall add allowedprogram* OR (CommandLine.keyword:*advfirewall firewall add rule* AND CommandLine.keyword:*action=allow* AND CommandLine.keyword:*program=*)) AND CommandLine.keyword:(*%TEMP%* *\:\\RECYCLER\\* *C\:\\$Recycle.bin\\* *\:\\SystemVolumeInformation\\* *C\:\\Windows\\Tasks\\* *C\:\\Windows\\debug\\* *C\:\\Windows\\fonts\\* *C\:\\Windows\\help\\* *C\:\\Windows\\drivers\\* *C\:\\Windows\\addins\\* *C\:\\Windows\\cursors\\* *C\:\\Windows\\system32\\tasks\\* *C\:\\Windows\\Temp\\* *C\:\\Temp\\* *C\:\\Users\\Public\\* *%Public%\\* *C\:\\Users\\Default\\* *C\:\\Users\\Desktop\\* *\\Downloads\\* *\\Temporary Internet Files\\Content.Outlook\\* *\\Local Settings\\Temporary Internet Files\\*))
```


### splunk
    
```
(CommandLine="*netsh*" (CommandLine="*firewall add allowedprogram*" OR (CommandLine="*advfirewall firewall add rule*" CommandLine="*action=allow*" CommandLine="*program=*")) (CommandLine="*%TEMP%*" OR CommandLine="*:\\RECYCLER\\*" OR CommandLine="*C:\\$Recycle.bin\\*" OR CommandLine="*:\\SystemVolumeInformation\\*" OR CommandLine="*C:\\Windows\\Tasks\\*" OR CommandLine="*C:\\Windows\\debug\\*" OR CommandLine="*C:\\Windows\\fonts\\*" OR CommandLine="*C:\\Windows\\help\\*" OR CommandLine="*C:\\Windows\\drivers\\*" OR CommandLine="*C:\\Windows\\addins\\*" OR CommandLine="*C:\\Windows\\cursors\\*" OR CommandLine="*C:\\Windows\\system32\\tasks\\*" OR CommandLine="*C:\\Windows\\Temp\\*" OR CommandLine="*C:\\Temp\\*" OR CommandLine="*C:\\Users\\Public\\*" OR CommandLine="*%Public%\\*" OR CommandLine="*C:\\Users\\Default\\*" OR CommandLine="*C:\\Users\\Desktop\\*" OR CommandLine="*\\Downloads\\*" OR CommandLine="*\\Temporary Internet Files\\Content.Outlook\\*" OR CommandLine="*\\Local Settings\\Temporary Internet Files\\*"))
```


### logpoint
    
```
(CommandLine="*netsh*" (CommandLine="*firewall add allowedprogram*" OR (CommandLine="*advfirewall firewall add rule*" CommandLine="*action=allow*" CommandLine="*program=*")) CommandLine IN ["*%TEMP%*", "*:\\RECYCLER\\*", "*C:\\$Recycle.bin\\*", "*:\\SystemVolumeInformation\\*", "*C:\\Windows\\Tasks\\*", "*C:\\Windows\\debug\\*", "*C:\\Windows\\fonts\\*", "*C:\\Windows\\help\\*", "*C:\\Windows\\drivers\\*", "*C:\\Windows\\addins\\*", "*C:\\Windows\\cursors\\*", "*C:\\Windows\\system32\\tasks\\*", "*C:\\Windows\\Temp\\*", "*C:\\Temp\\*", "*C:\\Users\\Public\\*", "*%Public%\\*", "*C:\\Users\\Default\\*", "*C:\\Users\\Desktop\\*", "*\\Downloads\\*", "*\\Temporary Internet Files\\Content.Outlook\\*", "*\\Local Settings\\Temporary Internet Files\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*netsh.*)(?=.*(?:.*(?:.*.*firewall add allowedprogram.*|.*(?:.*(?=.*.*advfirewall firewall add rule.*)(?=.*.*action=allow.*)(?=.*.*program=.*)))))(?=.*(?:.*.*%TEMP%.*|.*.*:\RECYCLER\\.*|.*.*C:\\$Recycle\.bin\\.*|.*.*:\SystemVolumeInformation\\.*|.*.*C:\\Windows\\Tasks\\.*|.*.*C:\\Windows\\debug\\.*|.*.*C:\\Windows\\fonts\\.*|.*.*C:\\Windows\\help\\.*|.*.*C:\\Windows\\drivers\\.*|.*.*C:\\Windows\\addins\\.*|.*.*C:\\Windows\\cursors\\.*|.*.*C:\\Windows\\system32\tasks\\.*|.*.*C:\Windows\Temp\\.*|.*.*C:\Temp\\.*|.*.*C:\Users\Public\\.*|.*.*%Public%\\.*|.*.*C:\Users\Default\\.*|.*.*C:\Users\Desktop\\.*|.*.*\Downloads\\.*|.*.*\Temporary Internet Files\Content\.Outlook\\.*|.*.*\Local Settings\Temporary Internet Files\\.*)))'
```



