| Title                    | PsExec Tool Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects PsExec service installation and execution events (service and Sysmon) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0031_7036_service_started_stopped](../Data_Needed/DN_0031_7036_service_started_stopped.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0029</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: PsExec Tool Execution
id: 42c575ea-e41e-41f1-b248-8093c3e82a28
status: experimental
description: Detects PsExec service installation and execution events (service and Sysmon)
author: Thomas Patzke
date: 2017/06/12
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.execution
    - attack.t1035
    - attack.s0029
detection:
    condition: 1 of them
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - ServiceName
    - ServiceFileName
falsepositives:
    - unknown
level: low
---
logsource:
    product: windows
    service: system
detection:
    service_installation:
        EventID: 7045
        ServiceName: 'PSEXESVC'
        ServiceFileName: '*\PSEXESVC.exe'
    service_execution:
        EventID: 7036
        ServiceName: 'PSEXESVC'
---
logsource:
    category: process_creation
    product: windows
detection:
    sysmon_processcreation:
        Image: '*\PSEXESVC.exe'
        User: 'NT AUTHORITY\SYSTEM'

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.message -match "ServiceName.*PSEXESVC" -and (($_.ID -eq "7045" -and $_.message -match "ServiceFileName.*.*\\PSEXESVC.exe") -or $_.ID -eq "7036")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName System | where {($_.message -match "Image.*.*\\PSEXESVC.exe" -and $_.message -match "User.*NT AUTHORITY\\SYSTEM") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ServiceName:"PSEXESVC" AND ((winlog.event_id:"7045" AND winlog.event_data.ServiceFileName.keyword:*\\PSEXESVC.exe) OR winlog.event_id:"7036"))
(winlog.event_data.Image.keyword:*\\PSEXESVC.exe AND winlog.event_data.User:"NT\ AUTHORITY\\SYSTEM")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/42c575ea-e41e-41f1-b248-8093c3e82a28 <<EOF
{
  "metadata": {
    "title": "PsExec Tool Execution",
    "description": "Detects PsExec service installation and execution events (service and Sysmon)",
    "tags": [
      "attack.execution",
      "attack.t1035",
      "attack.s0029"
    ],
    "query": "(winlog.event_data.ServiceName:\"PSEXESVC\" AND ((winlog.event_id:\"7045\" AND winlog.event_data.ServiceFileName.keyword:*\\\\PSEXESVC.exe) OR winlog.event_id:\"7036\"))"
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
                    "query": "(winlog.event_data.ServiceName:\"PSEXESVC\" AND ((winlog.event_id:\"7045\" AND winlog.event_data.ServiceFileName.keyword:*\\\\PSEXESVC.exe) OR winlog.event_id:\"7036\"))",
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
        "subject": "Sigma Rule 'PsExec Tool Execution'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n          EventID = {{_source.EventID}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n      ServiceName = {{_source.ServiceName}}\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/42c575ea-e41e-41f1-b248-8093c3e82a28-2 <<EOF
{
  "metadata": {
    "title": "PsExec Tool Execution",
    "description": "Detects PsExec service installation and execution events (service and Sysmon)",
    "tags": [
      "attack.execution",
      "attack.t1035",
      "attack.s0029"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\PSEXESVC.exe AND winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\")"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\PSEXESVC.exe AND winlog.event_data.User:\"NT\\ AUTHORITY\\\\SYSTEM\")",
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
        "subject": "Sigma Rule 'PsExec Tool Execution'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n          EventID = {{_source.EventID}}\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n      ServiceName = {{_source.ServiceName}}\n  ServiceFileName = {{_source.ServiceFileName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(ServiceName:"PSEXESVC" AND ((EventID:"7045" AND ServiceFileName.keyword:*\\PSEXESVC.exe) OR EventID:"7036"))
(Image.keyword:*\\PSEXESVC.exe AND User:"NT AUTHORITY\\SYSTEM")
```


### splunk
    
```
(source="WinEventLog:System" ServiceName="PSEXESVC" ((EventCode="7045" ServiceFileName="*\\PSEXESVC.exe") OR EventCode="7036")) | table EventCode,CommandLine,ParentCommandLine,ServiceName,ServiceFileName
(Image="*\\PSEXESVC.exe" User="NT AUTHORITY\\SYSTEM") | table EventCode,CommandLine,ParentCommandLine,ServiceName,ServiceFileName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" service="PSEXESVC" ((event_id="7045" ServiceFileName="*\\PSEXESVC.exe") OR event_id="7036"))
(Image="*\\PSEXESVC.exe" User="NT AUTHORITY\\SYSTEM")
```


### grep
    
```
grep -P '^(?:.*(?=.*PSEXESVC)(?=.*(?:.*(?:.*(?:.*(?=.*7045)(?=.*.*\PSEXESVC\.exe))|.*7036))))'
grep -P '^(?:.*(?=.*.*\PSEXESVC\.exe)(?=.*NT AUTHORITY\SYSTEM))'
```



