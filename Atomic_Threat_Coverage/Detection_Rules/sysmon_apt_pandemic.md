| Title                    | Pandemic Registry Key       |
|:-------------------------|:------------------|
| **Description**          | Detects Pandemic Windows Implant |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://wikileaks.org/vault7/#Pandemic](https://wikileaks.org/vault7/#Pandemic)</li><li>[https://twitter.com/MalwareJake/status/870349480356454401](https://twitter.com/MalwareJake/status/870349480356454401)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
action: global
title: Pandemic Registry Key
id: 47e0852a-cf81-4494-a8e6-31864f8c86ed
status: experimental
description: Detects Pandemic Windows Implant
references:
    - https://wikileaks.org/vault7/#Pandemic
    - https://twitter.com/MalwareJake/status/870349480356454401
tags:
    - attack.lateral_movement
    - attack.t1105
author: Florian Roth
date: 2017/06/01
detection:
    condition: 1 of them
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - Image
    - User
    - TargetObject
falsepositives:
    - unknown
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 13
        TargetObject:
            - 'HKLM\SYSTEM\CurrentControlSet\services\null\Instance*'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection2:
        Command: 'loaddll -a *'

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*HKLM\\SYSTEM\\CurrentControlSet\\services\\null\\Instance.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {$_.message -match "Command.*loaddll -a .*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(HKLM\\SYSTEM\\CurrentControlSet\\services\\null\\Instance*))
Command.keyword:loaddll\ \-a\ *
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/47e0852a-cf81-4494-a8e6-31864f8c86ed <<EOF
{
  "metadata": {
    "title": "Pandemic Registry Key",
    "description": "Detects Pandemic Windows Implant",
    "tags": [
      "attack.lateral_movement",
      "attack.t1105"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\null\\\\Instance*))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\null\\\\Instance*))",
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
        "subject": "Sigma Rule 'Pandemic Registry Key'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n          EventID = {{_source.EventID}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n            Image = {{_source.Image}}\n             User = {{_source.User}}\n     TargetObject = {{_source.TargetObject}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/47e0852a-cf81-4494-a8e6-31864f8c86ed-2 <<EOF
{
  "metadata": {
    "title": "Pandemic Registry Key",
    "description": "Detects Pandemic Windows Implant",
    "tags": [
      "attack.lateral_movement",
      "attack.t1105"
    ],
    "query": "Command.keyword:loaddll\\ \\-a\\ *"
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
                    "query": "Command.keyword:loaddll\\ \\-a\\ *",
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
        "subject": "Sigma Rule 'Pandemic Registry Key'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n          EventID = {{_source.EventID}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n            Image = {{_source.Image}}\n             User = {{_source.User}}\n     TargetObject = {{_source.TargetObject}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"13" AND TargetObject.keyword:(HKLM\\SYSTEM\\CurrentControlSet\\services\\null\\Instance*))
Command.keyword:loaddll \-a *
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="HKLM\\SYSTEM\\CurrentControlSet\\services\\null\\Instance*")) | table EventCode,CommandLine,ParentCommandLine,Image,User,TargetObject
Command="loaddll -a *" | table EventCode,CommandLine,ParentCommandLine,Image,User,TargetObject
```


### logpoint
    
```
(event_id="13" TargetObject IN ["HKLM\\SYSTEM\\CurrentControlSet\\services\\null\\Instance*"])
Command="loaddll -a *"
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*HKLM\SYSTEM\CurrentControlSet\services\null\Instance.*)))'
grep -P '^loaddll -a .*'
```



