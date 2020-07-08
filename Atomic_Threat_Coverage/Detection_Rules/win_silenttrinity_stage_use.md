| Title                    | SILENTTRINITY Stager Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects SILENTTRINITY stager use |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN0001_4688_windows_process_creation](../Data_Needed/DN0001_4688_windows_process_creation.md)</li><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/byt3bl33d3r/SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY)</li></ul>  |
| **Author**               | Aleksey Potapov, oscd.community |


## Detection Rules

### Sigma rule

```
action: global
title: SILENTTRINITY Stager Execution
id: 03552375-cc2c-4883-bbe4-7958d5a980be
status: experimental
description: Detects SILENTTRINITY stager use
references:
    - https://github.com/byt3bl33d3r/SILENTTRINITY
author: Aleksey Potapov, oscd.community
date: 2019/10/22
modified: 2019/11/04
tags:
    - attack.execution
detection:
    selection:
        Description|contains: 'st2stager'
    condition: selection
falsepositives:
    - unknown
level: high
---
logsource:
    category: process_creation
    product: windows
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Description.*.*st2stager.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Description.*.*st2stager.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Description.keyword:*st2stager*
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"7" AND winlog.event_data.Description.keyword:*st2stager*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/03552375-cc2c-4883-bbe4-7958d5a980be <<EOF
{
  "metadata": {
    "title": "SILENTTRINITY Stager Execution",
    "description": "Detects SILENTTRINITY stager use",
    "tags": [
      "attack.execution"
    ],
    "query": "winlog.event_data.Description.keyword:*st2stager*"
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
                    "query": "winlog.event_data.Description.keyword:*st2stager*",
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
        "subject": "Sigma Rule 'SILENTTRINITY Stager Execution'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/03552375-cc2c-4883-bbe4-7958d5a980be-2 <<EOF
{
  "metadata": {
    "title": "SILENTTRINITY Stager Execution",
    "description": "Detects SILENTTRINITY stager use",
    "tags": [
      "attack.execution"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Description.keyword:*st2stager*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Description.keyword:*st2stager*)",
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
        "subject": "Sigma Rule 'SILENTTRINITY Stager Execution'",
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
Description.keyword:*st2stager*
(EventID:"7" AND Description.keyword:*st2stager*)
```


### splunk
    
```
Description="*st2stager*"
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="7" Description="*st2stager*")
```


### logpoint
    
```
(event_id="1" Description="*st2stager*")
(event_id="7" Description="*st2stager*")
```


### grep
    
```
grep -P '^.*st2stager.*'
grep -P '^(?:.*(?=.*7)(?=.*.*st2stager.*))'
```



