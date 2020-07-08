| Title                    | CreateRemoteThread API and LoadLibrary       |
|:-------------------------|:------------------|
| **Description**          | Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1055_process_injection/dll_injection_createremotethread_loadlibrary.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1055_process_injection/dll_injection_createremotethread_loadlibrary.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: CreateRemoteThread API and LoadLibrary
id: 052ec6f6-1adc-41e6-907a-f1c813478bee
description: Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process
status: experimental
date: 2019/08/11
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/05_defense_evasion/T1055_process_injection/dll_injection_createremotethread_loadlibrary.md
tags:
    - attack.defense_evasion
    - attack.t1055
logsource:
    product: windows
    service: sysmon
detection:
    selection: 
        EventID: 8
        StartModule|endswith: '\kernel32.dll'
        StartFunction: 'LoadLibraryA'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "StartModule.*.*\\kernel32.dll" -and $_.message -match "StartFunction.*LoadLibraryA") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"8" AND winlog.event_data.StartModule.keyword:*\\kernel32.dll AND StartFunction:"LoadLibraryA")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/052ec6f6-1adc-41e6-907a-f1c813478bee <<EOF
{
  "metadata": {
    "title": "CreateRemoteThread API and LoadLibrary",
    "description": "Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process",
    "tags": [
      "attack.defense_evasion",
      "attack.t1055"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"8\" AND winlog.event_data.StartModule.keyword:*\\\\kernel32.dll AND StartFunction:\"LoadLibraryA\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"8\" AND winlog.event_data.StartModule.keyword:*\\\\kernel32.dll AND StartFunction:\"LoadLibraryA\")",
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
        "subject": "Sigma Rule 'CreateRemoteThread API and LoadLibrary'",
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
(EventID:"8" AND StartModule.keyword:*\\kernel32.dll AND StartFunction:"LoadLibraryA")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="8" StartModule="*\\kernel32.dll" StartFunction="LoadLibraryA")
```


### logpoint
    
```
(event_id="8" StartModule="*\\kernel32.dll" StartFunction="LoadLibraryA")
```


### grep
    
```
grep -P '^(?:.*(?=.*8)(?=.*.*\kernel32\.dll)(?=.*LoadLibraryA))'
```



