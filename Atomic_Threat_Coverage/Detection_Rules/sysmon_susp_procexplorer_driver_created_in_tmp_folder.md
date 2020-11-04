| Title                    | Suspicious PROCEXP152.sys File Created In TMP       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)</li></ul>  |
| **Author**               | xknow (@xknow_infosec), xorxes (@xor_xes) |


## Detection Rules

### Sigma rule

```
title: Suspicious PROCEXP152.sys File Created In TMP
id: 3da70954-0f2c-4103-adff-b7440368f50e
description: Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.
status: experimental
date: 2019/04/08
author: xknow (@xknow_infosec), xorxes (@xor_xes)
references:
    - https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
tags:
    - attack.t1089
    - attack.defense_evasion
logsource:
    product: windows
    service: sysmon
detection:
    selection_1:
        EventID: 11
        TargetFilename: '*\AppData\Local\Temp\*\PROCEXP152.sys'
    selection_2:
        Image|contains:
            - '*\procexp64.exe'
            - '*\procexp.exe'
            - '*\procmon64.exe'
            - '*\procmon.exe'
    condition: selection_1 and not selection_2
falsepositives:
    - Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\.*\\PROCEXP152.sys") -and  -not (($_.message -match "Image.*.*\\procexp64.exe.*" -or $_.message -match "Image.*.*\\procexp.exe.*" -or $_.message -match "Image.*.*\\procmon64.exe.*" -or $_.message -match "Image.*.*\\procmon.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:*\\AppData\\Local\\Temp\*\\PROCEXP152.sys) AND (NOT (winlog.event_data.Image.keyword:(*\\procexp64.exe* OR *\\procexp.exe* OR *\\procmon64.exe* OR *\\procmon.exe*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3da70954-0f2c-4103-adff-b7440368f50e <<EOF
{
  "metadata": {
    "title": "Suspicious PROCEXP152.sys File Created In TMP",
    "description": "Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder. This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.",
    "tags": [
      "attack.t1089",
      "attack.defense_evasion"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\AppData\\\\Local\\\\Temp\\*\\\\PROCEXP152.sys) AND (NOT (winlog.event_data.Image.keyword:(*\\\\procexp64.exe* OR *\\\\procexp.exe* OR *\\\\procmon64.exe* OR *\\\\procmon.exe*))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*\\\\AppData\\\\Local\\\\Temp\\*\\\\PROCEXP152.sys) AND (NOT (winlog.event_data.Image.keyword:(*\\\\procexp64.exe* OR *\\\\procexp.exe* OR *\\\\procmon64.exe* OR *\\\\procmon.exe*))))",
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
        "subject": "Sigma Rule 'Suspicious PROCEXP152.sys File Created In TMP'",
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
((EventID:"11" AND TargetFilename.keyword:*\\AppData\\Local\\Temp\*\\PROCEXP152.sys) AND (NOT (Image.keyword:(*\\procexp64.exe* *\\procexp.exe* *\\procmon64.exe* *\\procmon.exe*))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="11" TargetFilename="*\\AppData\\Local\\Temp\*\\PROCEXP152.sys") NOT ((Image="*\\procexp64.exe*" OR Image="*\\procexp.exe*" OR Image="*\\procmon64.exe*" OR Image="*\\procmon.exe*")))
```


### logpoint
    
```
((event_id="11" TargetFilename="*\\AppData\\Local\\Temp\*\\PROCEXP152.sys")  -(Image IN ["*\\procexp64.exe*", "*\\procexp.exe*", "*\\procmon64.exe*", "*\\procmon.exe*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*11)(?=.*.*\AppData\Local\Temp\.*\PROCEXP152\.sys)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\procexp64\.exe.*|.*.*\procexp\.exe.*|.*.*\procmon64\.exe.*|.*.*\procmon\.exe.*))))))'
```



