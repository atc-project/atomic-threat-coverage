| Title                    | Turla Group Lateral Movement       |
|:-------------------------|:------------------|
| **Description**          | Detects automated lateral movement by Turla group |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1083: File and Directory Discovery](https://attack.mitre.org/techniques/T1083)</li><li>[T1135: Network Share Discovery](https://attack.mitre.org/techniques/T1135)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0001_4688_windows_process_creation](../Data_Needed/DN0001_4688_windows_process_creation.md)</li><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1083: File and Directory Discovery](../Triggers/T1083.md)</li><li>[T1135: Network Share Discovery](../Triggers/T1135.md)</li></ul>  |
| **Severity Level**       |  Severity Level for this Detection Rule wasn't defined yet  |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securelist.com/the-epic-turla-operation/65545/](https://securelist.com/the-epic-turla-operation/65545/)</li></ul>  |
| **Author**               | Markus Neis |
| Other Tags           | <ul><li>attack.g0010</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: Turla Group Lateral Movement
id: c601f20d-570a-4cde-a7d6-e17f99cb8e7f
status: experimental
description: Detects automated lateral movement by Turla group
references:
    - https://securelist.com/the-epic-turla-operation/65545/
tags:
    - attack.g0010
    - attack.execution
    - attack.t1059
    - attack.lateral_movement
    - attack.t1077
    - attack.discovery
    - attack.t1083
    - attack.t1135
author: Markus Neis
date: 2017/11/07
logsource:
    category: process_creation
    product: windows
falsepositives:
   - Unknown
---
detection:
   selection:
      CommandLine:
         - 'net use \\%DomainController%\C$ "P@ssw0rd" *'
         - 'dir c:\\*.doc* /s'
         - 'dir %TEMP%\\*.exe'
   condition: selection
level: critical
---
detection:
   netCommand1:
      CommandLine: 'net view /DOMAIN'
   netCommand2:
      CommandLine: 'net session'
   netCommand3:
      CommandLine: 'net share'
   timeframe: 1m
   condition: netCommand1 | near netCommand2 and netCommand3
level: medium

```





### powershell
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_apt_turla_commands.yml): Only COUNT aggregation function is implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_apt_turla_commands.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c601f20d-570a-4cde-a7d6-e17f99cb8e7f <<EOF
{
  "metadata": {
    "title": "Turla Group Lateral Movement",
    "description": "Detects automated lateral movement by Turla group",
    "tags": [
      "attack.g0010",
      "attack.execution",
      "attack.t1059",
      "attack.lateral_movement",
      "attack.t1077",
      "attack.discovery",
      "attack.t1083",
      "attack.t1135"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(net\\ use\\ \\\\%DomainController%\\\\C$\\ \\\"P@ssw0rd\\\"\\ * OR dir\\ c\\:\\\\*.doc*\\ \\/s OR dir\\ %TEMP%\\\\*.exe)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(net\\ use\\ \\\\%DomainController%\\\\C$\\ \\\"P@ssw0rd\\\"\\ * OR dir\\ c\\:\\\\*.doc*\\ \\/s OR dir\\ %TEMP%\\\\*.exe)",
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
        "subject": "Sigma Rule 'Turla Group Lateral Movement'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c601f20d-570a-4cde-a7d6-e17f99cb8e7f-2 <<EOF
{
  "metadata": {
    "title": "Turla Group Lateral Movement",
    "description": "Detects automated lateral movement by Turla group",
    "tags": [
      "attack.g0010",
      "attack.execution",
      "attack.t1059",
      "attack.lateral_movement",
      "attack.t1077",
      "attack.discovery",
      "attack.t1083",
      "attack.t1135"
    ],
    "query": "winlog.event_data.CommandLine:\"net\\ view\\ \\/DOMAIN\""
  },
  "trigger": {
    "schedule": {
      "interval": "1m"
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
                    "query": "winlog.event_data.CommandLine:\"net\\ view\\ \\/DOMAIN\"",
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
        "subject": "Sigma Rule 'Turla Group Lateral Movement'",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_apt_turla_commands.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_apt_turla_commands.yml): The 'near' aggregation operator is not yet implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### logpoint
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_apt_turla_commands.yml): The 'near' aggregation operator is not yet implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### grep
    
```
grep -P '^(?:.*net use \\%DomainController%\C\$ "P@ssw0rd" .*|.*dir c:\\.*\.doc.* /s|.*dir %TEMP%\\.*\.exe)'
grep -P '^net view /DOMAIN'
```



