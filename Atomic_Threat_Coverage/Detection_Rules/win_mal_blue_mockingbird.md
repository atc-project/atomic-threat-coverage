| Title                    | Blue Mockingbird       |
|:-------------------------|:------------------|
| **Description**          | Attempts to detect system changes made by Blue Mockingbird |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://redcanary.com/blog/blue-mockingbird-cryptominer/](https://redcanary.com/blog/blue-mockingbird-cryptominer/)</li></ul>  |
| **Author**               | Trent Liffick (@tliffick) |


## Detection Rules

### Sigma rule

```
action: global
title: Blue Mockingbird
id: c3198a27-23a0-4c2c-af19-e5328d49680e
status: experimental
description: Attempts to detect system changes made by Blue Mockingbird
references:
    - https://redcanary.com/blog/blue-mockingbird-cryptominer/
tags:
    - attack.execution
    - attack.t1112
    - attack.t1047
author: Trent Liffick (@tliffick)
date: 2020/05/14
falsepositives:
    - unknown
level: high
detection:
    condition: 1 of them
---
logsource:
    category: process_creation
    product: windows
detection:
  exec_selection:
    Image|endswith: '\cmd.exe'
    CommandLine|contains|all:
      - 'sc config'
      - 'wercplsupporte.dll'
---
logsource:
  category: process_creation
  product: windows
detection:
  wmic_cmd:
    Image|endswith: '\wmic.exe'
    CommandLine|endswith: 'COR_PROFILER'
---
logsource:
  product: windows
  service: sysmon
detection:
  mod_reg:
    EventID: 13
    TargetObject|endswith:
      - '\CurrentControlSet\Services\wercplsupport\Parameters\ServiceDll'

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\cmd.exe" -and $_.message -match "CommandLine.*.*sc config.*" -and $_.message -match "CommandLine.*.*wercplsupporte.dll.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent | where {($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "CommandLine.*.*COR_PROFILER") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and ($_.message -match "TargetObject.*.*\\CurrentControlSet\\Services\\wercplsupport\\Parameters\\ServiceDll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\cmd.exe AND winlog.event_data.CommandLine.keyword:*sc\ config* AND winlog.event_data.CommandLine.keyword:*wercplsupporte.dll*)
(winlog.event_data.Image.keyword:*\\wmic.exe AND winlog.event_data.CommandLine.keyword:*COR_PROFILER)
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:(*\\CurrentControlSet\\Services\\wercplsupport\\Parameters\\ServiceDll))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c3198a27-23a0-4c2c-af19-e5328d49680e <<EOF
{
  "metadata": {
    "title": "Blue Mockingbird",
    "description": "Attempts to detect system changes made by Blue Mockingbird",
    "tags": [
      "attack.execution",
      "attack.t1112",
      "attack.t1047"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\cmd.exe AND winlog.event_data.CommandLine.keyword:*sc\\ config* AND winlog.event_data.CommandLine.keyword:*wercplsupporte.dll*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\cmd.exe AND winlog.event_data.CommandLine.keyword:*sc\\ config* AND winlog.event_data.CommandLine.keyword:*wercplsupporte.dll*)",
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
        "subject": "Sigma Rule 'Blue Mockingbird'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c3198a27-23a0-4c2c-af19-e5328d49680e-2 <<EOF
{
  "metadata": {
    "title": "Blue Mockingbird",
    "description": "Attempts to detect system changes made by Blue Mockingbird",
    "tags": [
      "attack.execution",
      "attack.t1112",
      "attack.t1047"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*COR_PROFILER)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*COR_PROFILER)",
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
        "subject": "Sigma Rule 'Blue Mockingbird'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c3198a27-23a0-4c2c-af19-e5328d49680e-3 <<EOF
{
  "metadata": {
    "title": "Blue Mockingbird",
    "description": "Attempts to detect system changes made by Blue Mockingbird",
    "tags": [
      "attack.execution",
      "attack.t1112",
      "attack.t1047"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\CurrentControlSet\\\\Services\\\\wercplsupport\\\\Parameters\\\\ServiceDll))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:(*\\\\CurrentControlSet\\\\Services\\\\wercplsupport\\\\Parameters\\\\ServiceDll))",
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
        "subject": "Sigma Rule 'Blue Mockingbird'",
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
(Image.keyword:*\\cmd.exe AND CommandLine.keyword:*sc config* AND CommandLine.keyword:*wercplsupporte.dll*)
(Image.keyword:*\\wmic.exe AND CommandLine.keyword:*COR_PROFILER)
(EventID:"13" AND TargetObject.keyword:(*\\CurrentControlSet\\Services\\wercplsupport\\Parameters\\ServiceDll))
```


### splunk
    
```
(Image="*\\cmd.exe" CommandLine="*sc config*" CommandLine="*wercplsupporte.dll*")
(Image="*\\wmic.exe" CommandLine="*COR_PROFILER")
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" (TargetObject="*\\CurrentControlSet\\Services\\wercplsupport\\Parameters\\ServiceDll"))
```


### logpoint
    
```
(Image="*\\cmd.exe" CommandLine="*sc config*" CommandLine="*wercplsupporte.dll*")
(Image="*\\wmic.exe" CommandLine="*COR_PROFILER")
(event_id="13" TargetObject IN ["*\\CurrentControlSet\\Services\\wercplsupport\\Parameters\\ServiceDll"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\cmd\.exe)(?=.*.*sc config.*)(?=.*.*wercplsupporte\.dll.*))'
grep -P '^(?:.*(?=.*.*\wmic\.exe)(?=.*.*COR_PROFILER))'
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\CurrentControlSet\Services\wercplsupport\Parameters\ServiceDll)))'
```



