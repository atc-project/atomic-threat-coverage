| Title                    | Suspicious Execution from Outlook       |
|:-------------------------|:------------------|
| **Description**          | Detects EnableUnsafeClientMailRules used for Script Execution from Outlook |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1202: Indirect Command Execution](https://attack.mitre.org/techniques/T1202)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059: Command and Scripting Interpreter](../Triggers/T1059.md)</li><li>[T1202: Indirect Command Execution](../Triggers/T1202.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/sensepost/ruler](https://github.com/sensepost/ruler)</li><li>[https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html](https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious Execution from Outlook
id: e212d415-0e93-435f-9e1a-f29005bb4723
status: experimental
description: Detects EnableUnsafeClientMailRules used for Script Execution from Outlook
references:
    - https://github.com/sensepost/ruler
    - https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html
tags:
    - attack.execution
    - attack.t1059
    - attack.t1202
author: Markus Neis
date: 2018/12/27
logsource:
    category: process_creation
    product: windows
detection:
    clientMailRules:
        CommandLine: '*EnableUnsafeClientMailRules*'
    outlookExec:
        ParentImage: '*\outlook.exe'
        CommandLine: \\\\*\\*.exe
    condition: clientMailRules or outlookExec
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*EnableUnsafeClientMailRules.*" -or ($_.message -match "ParentImage.*.*\\outlook.exe" -and $_.message -match "CommandLine.*\\\\.*\\.*.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*EnableUnsafeClientMailRules* OR (winlog.event_data.ParentImage.keyword:*\\outlook.exe AND winlog.event_data.CommandLine.keyword:\\\\*\\*.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e212d415-0e93-435f-9e1a-f29005bb4723 <<EOF
{
  "metadata": {
    "title": "Suspicious Execution from Outlook",
    "description": "Detects EnableUnsafeClientMailRules used for Script Execution from Outlook",
    "tags": [
      "attack.execution",
      "attack.t1059",
      "attack.t1202"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*EnableUnsafeClientMailRules* OR (winlog.event_data.ParentImage.keyword:*\\\\outlook.exe AND winlog.event_data.CommandLine.keyword:\\\\\\\\*\\\\*.exe))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*EnableUnsafeClientMailRules* OR (winlog.event_data.ParentImage.keyword:*\\\\outlook.exe AND winlog.event_data.CommandLine.keyword:\\\\\\\\*\\\\*.exe))",
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
        "subject": "Sigma Rule 'Suspicious Execution from Outlook'",
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
(CommandLine.keyword:*EnableUnsafeClientMailRules* OR (ParentImage.keyword:*\\outlook.exe AND CommandLine.keyword:\\\\*\\*.exe))
```


### splunk
    
```
(CommandLine="*EnableUnsafeClientMailRules*" OR (ParentImage="*\\outlook.exe" CommandLine="\\\\*\\*.exe"))
```


### logpoint
    
```
(CommandLine="*EnableUnsafeClientMailRules*" OR (ParentImage="*\\outlook.exe" CommandLine="\\\\*\\*.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*EnableUnsafeClientMailRules.*|.*(?:.*(?=.*.*\outlook\.exe)(?=.*\\\\.*\\.*\.exe))))'
```



