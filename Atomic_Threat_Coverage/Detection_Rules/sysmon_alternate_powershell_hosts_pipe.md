| Title                    | Alternate PowerShell Hosts Pipe       |
|:-------------------------|:------------------|
| **Description**          | Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Programs using PowerShell directly without invocation of a dedicated interpreter.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/alternate_signed_powershell_hosts.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Alternate PowerShell Hosts Pipe
id: 58cb02d5-78ce-4692-b3e1-dce850aae41a
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
        EventID: 17
        PipeName|startswith: '\PSHost'
    filter:
        Image|endswith: '\powershell.exe'
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - Image
    - PipeName
falsepositives:
    - Programs using PowerShell directly without invocation of a dedicated interpreter.
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -and $_.message -match "PipeName.*\\PSHost.*") -and  -not ($_.message -match "Image.*.*\\powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"17" AND winlog.event_data.PipeName.keyword:\\PSHost*) AND (NOT (winlog.event_data.Image.keyword:*\\powershell.exe)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/58cb02d5-78ce-4692-b3e1-dce850aae41a <<EOF
{
  "metadata": {
    "title": "Alternate PowerShell Hosts Pipe",
    "description": "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe",
    "tags": [
      "attack.execution",
      "attack.t1086"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"17\" AND winlog.event_data.PipeName.keyword:\\\\PSHost*) AND (NOT (winlog.event_data.Image.keyword:*\\\\powershell.exe)))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"17\" AND winlog.event_data.PipeName.keyword:\\\\PSHost*) AND (NOT (winlog.event_data.Image.keyword:*\\\\powershell.exe)))",
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
        "subject": "Sigma Rule 'Alternate PowerShell Hosts Pipe'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n       Image = {{_source.Image}}\n    PipeName = {{_source.PipeName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((EventID:"17" AND PipeName.keyword:\\PSHost*) AND (NOT (Image.keyword:*\\powershell.exe)))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="17" PipeName="\\PSHost*") NOT (Image="*\\powershell.exe")) | table ComputerName,User,Image,PipeName
```


### logpoint
    
```
((event_id="17" PipeName="\\PSHost*")  -(Image="*\\powershell.exe"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*17)(?=.*\PSHost.*)))(?=.*(?!.*(?:.*(?=.*.*\powershell\.exe)))))'
```



