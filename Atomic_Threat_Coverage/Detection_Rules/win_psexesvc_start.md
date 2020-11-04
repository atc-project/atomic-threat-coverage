| Title                    | PsExec Service Start       |
|:-------------------------|:------------------|
| **Description**          | Detects a PsExec service start |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Administrative activity</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0029</li></ul> | 

## Detection Rules

### Sigma rule

```
title: PsExec Service Start
id: 3ede524d-21cc-472d-a3ce-d21b568d8db7
description: Detects a PsExec service start
author: Florian Roth
date: 2018/03/13
modified: 2012/12/11
tags:
    - attack.execution
    - attack.t1035
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ProcessCommandLine: C:\Windows\PSEXESVC.exe
    condition: selection
falsepositives:
    - Administrative activity
level: low

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "ProcessCommandLine.*C:\\Windows\\PSEXESVC.exe" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.ProcessCommandLine:"C\:\\Windows\\PSEXESVC.exe"
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3ede524d-21cc-472d-a3ce-d21b568d8db7 <<EOF
{
  "metadata": {
    "title": "PsExec Service Start",
    "description": "Detects a PsExec service start",
    "tags": [
      "attack.execution",
      "attack.t1035",
      "attack.s0029"
    ],
    "query": "winlog.event_data.ProcessCommandLine:\"C\\:\\\\Windows\\\\PSEXESVC.exe\""
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
                    "query": "winlog.event_data.ProcessCommandLine:\"C\\:\\\\Windows\\\\PSEXESVC.exe\"",
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
        "subject": "Sigma Rule 'PsExec Service Start'",
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
ProcessCommandLine:"C\:\\Windows\\PSEXESVC.exe"
```


### splunk
    
```
ProcessCommandLine="C:\\Windows\\PSEXESVC.exe"
```


### logpoint
    
```
ProcessCommandLine="C:\\Windows\\PSEXESVC.exe"
```


### grep
    
```
grep -P '^C:\Windows\PSEXESVC\.exe'
```



