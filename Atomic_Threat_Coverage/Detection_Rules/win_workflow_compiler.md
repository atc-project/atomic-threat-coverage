| Title                    | Microsoft Workflow Compiler       |
|:-------------------------|:------------------|
| **Description**          | Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1127: Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate MWC use (unlikely in modern enterprise environments)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb](https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb)</li></ul>  |
| **Author**               | Nik Seetharaman |


## Detection Rules

### Sigma rule

```
title: Microsoft Workflow Compiler
id: 419dbf2b-8a9b-4bea-bf99-7544b050ec8d
status: experimental
description: Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1127
author: Nik Seetharaman
date: 2019/01/16
references:
    - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\Microsoft.Workflow.Compiler.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate MWC use (unlikely in modern enterprise environments)
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "Image.*.*\\Microsoft.Workflow.Compiler.exe" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:*\\Microsoft.Workflow.Compiler.exe
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/419dbf2b-8a9b-4bea-bf99-7544b050ec8d <<EOF
{
  "metadata": {
    "title": "Microsoft Workflow Compiler",
    "description": "Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1127"
    ],
    "query": "winlog.event_data.Image.keyword:*\\\\Microsoft.Workflow.Compiler.exe"
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
                    "query": "winlog.event_data.Image.keyword:*\\\\Microsoft.Workflow.Compiler.exe",
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
        "subject": "Sigma Rule 'Microsoft Workflow Compiler'",
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
Image.keyword:*\\Microsoft.Workflow.Compiler.exe
```


### splunk
    
```
Image="*\\Microsoft.Workflow.Compiler.exe" | table CommandLine,ParentCommandLine
```


### logpoint
    
```
Image="*\\Microsoft.Workflow.Compiler.exe"
```


### grep
    
```
grep -P '^.*\Microsoft\.Workflow\.Compiler\.exe'
```



