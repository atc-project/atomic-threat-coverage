| Title                    | Usage of Sysinternals Tools       |
|:-------------------------|:------------------|
| **Description**          | Detects the usage of Sysinternals Tools due to accepteula key being added to Registry |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate use of SysInternals tools</li><li>Programs that use the same Registry Key</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/Moti_B/status/1008587936735035392](https://twitter.com/Moti_B/status/1008587936735035392)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
action: global
title: Usage of Sysinternals Tools
id: 25ffa65d-76d8-4da5-a832-3f2b0136e133
status: experimental
description: Detects the usage of Sysinternals Tools due to accepteula key being added to Registry
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
date: 2017/08/28
author: Markus Neis
detection:
    condition: 1 of them
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same Registry Key
level: low
---
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 13
        TargetObject: '*\EulaAccepted'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection2:
        CommandLine: '* -accepteula*'
```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and $_.message -match "TargetObject.*.*\\EulaAccepted") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {$_.message -match "CommandLine.*.* -accepteula.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:*\\EulaAccepted)
winlog.event_data.CommandLine.keyword:*\ \-accepteula*
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/25ffa65d-76d8-4da5-a832-3f2b0136e133 <<EOF
{
  "metadata": {
    "title": "Usage of Sysinternals Tools",
    "description": "Detects the usage of Sysinternals Tools due to accepteula key being added to Registry",
    "tags": "",
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:*\\\\EulaAccepted)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:*\\\\EulaAccepted)",
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
        "subject": "Sigma Rule 'Usage of Sysinternals Tools'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/25ffa65d-76d8-4da5-a832-3f2b0136e133-2 <<EOF
{
  "metadata": {
    "title": "Usage of Sysinternals Tools",
    "description": "Detects the usage of Sysinternals Tools due to accepteula key being added to Registry",
    "tags": "",
    "query": "winlog.event_data.CommandLine.keyword:*\\ \\-accepteula*"
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
                    "query": "winlog.event_data.CommandLine.keyword:*\\ \\-accepteula*",
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
        "subject": "Sigma Rule 'Usage of Sysinternals Tools'",
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
(EventID:"13" AND TargetObject.keyword:*\\EulaAccepted)
CommandLine.keyword:* \-accepteula*
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" TargetObject="*\\EulaAccepted")
CommandLine="* -accepteula*"
```


### logpoint
    
```
(event_id="13" TargetObject="*\\EulaAccepted")
CommandLine="* -accepteula*"
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*.*\EulaAccepted))'
grep -P '^.* -accepteula.*'
```



