| Title                    | PowerShell Base64 Encoded Shellcode       |
|:-------------------------|:------------------|
| **Description**          | Detects Base64 encoded Shellcode |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/cyb3rops/status/1063072865992523776](https://twitter.com/cyb3rops/status/1063072865992523776)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell Base64 Encoded Shellcode
id: 2d117e49-e626-4c7c-bd1f-c3c0147774c8
description: Detects Base64 encoded Shellcode
status: experimental
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
author: Florian Roth
date: 2018/11/17
modified: 2020/09/01
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*AAAAYInlM*'
    selection2:
        CommandLine:
            - '*OiCAAAAYInlM*'
            - '*OiJAAAAYInlM*'
    condition: selection1 and selection2
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*AAAAYInlM.*" -and ($_.message -match "CommandLine.*.*OiCAAAAYInlM.*" -or $_.message -match "CommandLine.*.*OiJAAAAYInlM.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*AAAAYInlM* AND winlog.event_data.CommandLine.keyword:(*OiCAAAAYInlM* OR *OiJAAAAYInlM*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/2d117e49-e626-4c7c-bd1f-c3c0147774c8 <<EOF
{
  "metadata": {
    "title": "PowerShell Base64 Encoded Shellcode",
    "description": "Detects Base64 encoded Shellcode",
    "tags": [
      "attack.defense_evasion",
      "attack.t1027"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*AAAAYInlM* AND winlog.event_data.CommandLine.keyword:(*OiCAAAAYInlM* OR *OiJAAAAYInlM*))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*AAAAYInlM* AND winlog.event_data.CommandLine.keyword:(*OiCAAAAYInlM* OR *OiJAAAAYInlM*))",
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
        "subject": "Sigma Rule 'PowerShell Base64 Encoded Shellcode'",
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
(CommandLine.keyword:*AAAAYInlM* AND CommandLine.keyword:(*OiCAAAAYInlM* *OiJAAAAYInlM*))
```


### splunk
    
```
(CommandLine="*AAAAYInlM*" (CommandLine="*OiCAAAAYInlM*" OR CommandLine="*OiJAAAAYInlM*"))
```


### logpoint
    
```
(CommandLine="*AAAAYInlM*" CommandLine IN ["*OiCAAAAYInlM*", "*OiJAAAAYInlM*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*AAAAYInlM.*)(?=.*(?:.*.*OiCAAAAYInlM.*|.*.*OiJAAAAYInlM.*)))'
```



