| Title                    | Suspicious XOR Encoded PowerShell Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious powershell process which includes bxor command, alternatvide obfuscation method to b64 encoded commands. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Sami Ruohonen |


## Detection Rules

### Sigma rule

```
title: Suspicious XOR Encoded PowerShell Command Line
id: bb780e0c-16cf-4383-8383-1e5471db6cf9
description: Detects suspicious powershell process which includes bxor command, alternatvide obfuscation method to b64 encoded commands.
status: experimental
author: Sami Ruohonen
date: 2018/09/05
tags:
    - attack.execution
    - attack.t1086
detection:
    selection:
        CommandLine:
            - '* -bxor*'
    condition: selection
falsepositives:
    - unknown
level: medium
logsource:
    category: process_creation
    product: windows

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* -bxor.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ \-bxor*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/bb780e0c-16cf-4383-8383-1e5471db6cf9 <<EOF
{
  "metadata": {
    "title": "Suspicious XOR Encoded PowerShell Command Line",
    "description": "Detects suspicious powershell process which includes bxor command, alternatvide obfuscation method to b64 encoded commands.",
    "tags": [
      "attack.execution",
      "attack.t1086"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\-bxor*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\-bxor*)",
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
        "subject": "Sigma Rule 'Suspicious XOR Encoded PowerShell Command Line'",
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
CommandLine.keyword:(* \-bxor*)
```


### splunk
    
```
(CommandLine="* -bxor*")
```


### logpoint
    
```
CommandLine IN ["* -bxor*"]
```


### grep
    
```
grep -P '^(?:.*.* -bxor.*)'
```



