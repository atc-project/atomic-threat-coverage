| Title                    | Autorun Keys Modification       |
|:-------------------------|:------------------|
| **Description**          | Detects modification of autostart extensibility point (ASEP) in registry |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1060: Registry Run Keys / Startup Folder](../Triggers/T1060.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason</li><li>Legitimate administrator sets up autorun keys for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1060/T1060.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1060/T1060.yaml)</li></ul>  |
| **Author**               | Victor Sergeev, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Autorun Keys Modification
id: 17f878b8-9968-4578-b814-c4217fc5768c
description: Detects modification of autostart extensibility point (ASEP) in registry
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1060/T1060.yaml
tags:
    - attack.persistence
    - attack.t1060
date: 2019/10/21
modified: 2019/11/10
author: Victor Sergeev, Daniil Yugoslavskiy, oscd.community
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains:
            - '\software\Microsoft\Windows\CurrentVersion\Run'
            - '\software\Microsoft\Windows\CurrentVersion\RunOnce'
            - '\software\Microsoft\Windows\CurrentVersion\RunOnceEx'
            - '\software\Microsoft\Windows\CurrentVersion\RunServices'
            - '\software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
            - '\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit'
            - '\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell'
            - '\software\Microsoft\Windows NT\CurrentVersion\Windows'
            - '\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    condition: selection
falsepositives:
    - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason
    - Legitimate administrator sets up autorun keys for legitimate reason
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\Run.*" -or $_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnce.*" -or $_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx.*" -or $_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServices.*" -or $_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce.*" -or $_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit.*" -or $_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell.*" -or $_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows.*" -or $_.message -match "TargetObject.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*\\software\\Microsoft\\Windows\\CurrentVersion\\Run* OR *\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnce* OR *\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx* OR *\\software\\Microsoft\\Windows\\CurrentVersion\\RunServices* OR *\\software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce* OR *\\software\\Microsoft\\Windows\ NT\\CurrentVersion\\Winlogon\\Userinit* OR *\\software\\Microsoft\\Windows\ NT\\CurrentVersion\\Winlogon\\Shell* OR *\\software\\Microsoft\\Windows\ NT\\CurrentVersion\\Windows* OR *\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User\ Shell\ Folders*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/17f878b8-9968-4578-b814-c4217fc5768c <<EOF
{
  "metadata": {
    "title": "Autorun Keys Modification",
    "description": "Detects modification of autostart extensibility point (ASEP) in registry",
    "tags": [
      "attack.persistence",
      "attack.t1060"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User\\ Shell\\ Folders*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User\\ Shell\\ Folders*))",
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
        "subject": "Sigma Rule 'Autorun Keys Modification'",
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
(EventID:"13" AND TargetObject.keyword:(*\\software\\Microsoft\\Windows\\CurrentVersion\\Run* *\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnce* *\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx* *\\software\\Microsoft\\Windows\\CurrentVersion\\RunServices* *\\software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce* *\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit* *\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell* *\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows* *\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders*))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="*\\software\\Microsoft\\Windows\\CurrentVersion\\Run*" OR TargetObject="*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*" OR TargetObject="*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx*" OR TargetObject="*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServices*" OR TargetObject="*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce*" OR TargetObject="*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit*" OR TargetObject="*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell*" OR TargetObject="*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows*" OR TargetObject="*\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders*"))
```


### logpoint
    
```
(event_id="13" TargetObject IN ["*\\software\\Microsoft\\Windows\\CurrentVersion\\Run*", "*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*", "*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx*", "*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServices*", "*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce*", "*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit*", "*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell*", "*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows*", "*\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\software\Microsoft\Windows\CurrentVersion\Run.*|.*.*\software\Microsoft\Windows\CurrentVersion\RunOnce.*|.*.*\software\Microsoft\Windows\CurrentVersion\RunOnceEx.*|.*.*\software\Microsoft\Windows\CurrentVersion\RunServices.*|.*.*\software\Microsoft\Windows\CurrentVersion\RunServicesOnce.*|.*.*\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit.*|.*.*\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell.*|.*.*\software\Microsoft\Windows NT\CurrentVersion\Windows.*|.*.*\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders.*)))'
```



