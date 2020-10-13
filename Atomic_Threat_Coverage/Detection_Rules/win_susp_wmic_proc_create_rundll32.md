| Title                    | Suspicious WMI Execution Using Rundll32       |
|:-------------------------|:------------------|
| **Description**          | Detects WMI executing rundll32 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://thedfirreport.com/2020/10/08/ryuks-return/](https://thedfirreport.com/2020/10/08/ryuks-return/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious WMI Execution Using Rundll32
id: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
status: experimental
description: Detects WMI executing rundll32
references:
    - https://thedfirreport.com/2020/10/08/ryuks-return/
author: Florian Roth
date: 2020/10/12
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'process call create'
            - 'rundll32'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.t1047
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*process call create.*" -and $_.message -match "CommandLine.*.*rundll32.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*process\ call\ create* AND winlog.event_data.CommandLine.keyword:*rundll32*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3c89a1e8-0fba-449e-8f1b-8409d6267ec8 <<EOF
{
  "metadata": {
    "title": "Suspicious WMI Execution Using Rundll32",
    "description": "Detects WMI executing rundll32",
    "tags": [
      "attack.execution",
      "attack.t1047"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*process\\ call\\ create* AND winlog.event_data.CommandLine.keyword:*rundll32*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*process\\ call\\ create* AND winlog.event_data.CommandLine.keyword:*rundll32*)",
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
        "subject": "Sigma Rule 'Suspicious WMI Execution Using Rundll32'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(CommandLine.keyword:*process call create* AND CommandLine.keyword:*rundll32*)
```


### splunk
    
```
(CommandLine="*process call create*" CommandLine="*rundll32*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(CommandLine="*process call create*" CommandLine="*rundll32*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*process call create.*)(?=.*.*rundll32.*))'
```



