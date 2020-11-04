| Title                    | Alternate PowerShell Hosts Module Load       |
|:-------------------------|:------------------|
| **Description**          | Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Programs using PowerShell directly without invocation of a dedicated interpreter.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Alternate PowerShell Hosts Module Load
id: f67f6c57-257d-4919-a416-69cd31f9aac3
description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: sysmon
detection:
    selection: 
        EventID: 7
        Description: 'system.management.automation'
        ImageLoaded|contains: 'system.management.automation'
    filter:
        Image|endswith: '\powershell.exe'
    condition: selection and not filter
falsepositives:
    - Programs using PowerShell directly without invocation of a dedicated interpreter.
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7" -and $_.message -match "Description.*system.management.automation" -and $_.message -match "ImageLoaded.*.*system.management.automation.*") -and  -not ($_.message -match "Image.*.*\\powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"7" AND winlog.event_data.Description:"system.management.automation" AND winlog.event_data.ImageLoaded.keyword:*system.management.automation*) AND (NOT (winlog.event_data.Image.keyword:*\\powershell.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f67f6c57-257d-4919-a416-69cd31f9aac3 <<EOF
{
  "metadata": {
    "title": "Alternate PowerShell Hosts Module Load",
    "description": "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe",
    "tags": [
      "attack.execution",
      "attack.t1086"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"7\" AND winlog.event_data.Description:\"system.management.automation\" AND winlog.event_data.ImageLoaded.keyword:*system.management.automation*) AND (NOT (winlog.event_data.Image.keyword:*\\\\powershell.exe)))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"7\" AND winlog.event_data.Description:\"system.management.automation\" AND winlog.event_data.ImageLoaded.keyword:*system.management.automation*) AND (NOT (winlog.event_data.Image.keyword:*\\\\powershell.exe)))",
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
        "subject": "Sigma Rule 'Alternate PowerShell Hosts Module Load'",
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
((EventID:"7" AND Description:"system.management.automation" AND ImageLoaded.keyword:*system.management.automation*) AND (NOT (Image.keyword:*\\powershell.exe)))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="7" Description="system.management.automation" ImageLoaded="*system.management.automation*") NOT (Image="*\\powershell.exe"))
```


### logpoint
    
```
((event_id="7" Description="system.management.automation" ImageLoaded="*system.management.automation*")  -(Image="*\\powershell.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*7)(?=.*system\.management\.automation)(?=.*.*system\.management\.automation.*)))(?=.*(?!.*(?:.*(?=.*.*\powershell\.exe)))))'
```



