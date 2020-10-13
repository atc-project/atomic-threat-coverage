| Title                    | Suspicious XOR Encoded PowerShell Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Sami Ruohonen, Harish Segar (improvement) |


## Detection Rules

### Sigma rule

```
title: Suspicious XOR Encoded PowerShell Command Line
id: bb780e0c-16cf-4383-8383-1e5471db6cf9
description: Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.
status: experimental
author: Sami Ruohonen, Harish Segar (improvement)
date: 2018/09/05
modified: 2020/09/06
tags:
    - attack.defense_evasion
    - attack.t1086 # an old one
    - attack.t1059.001
    - attack.t1140
    - attack.t1027    
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: "Windows PowerShell"
        - Product: "PowerShell Core 6"
    filter:
        CommandLine|contains:
            - "bxor"
            - "join"
            - "char"
    condition: selection and filter
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Description.*Windows PowerShell" -or $_.message -match "Product.*PowerShell Core 6") -and ($_.message -match "CommandLine.*.*bxor.*" -or $_.message -match "CommandLine.*.*join.*" -or $_.message -match "CommandLine.*.*char.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Description:"Windows\ PowerShell" OR Product:"PowerShell\ Core\ 6") AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/bb780e0c-16cf-4383-8383-1e5471db6cf9 <<EOF
{
  "metadata": {
    "title": "Suspicious XOR Encoded PowerShell Command Line",
    "description": "Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.",
    "tags": [
      "attack.defense_evasion",
      "attack.t1086",
      "attack.t1059.001",
      "attack.t1140",
      "attack.t1027"
    ],
    "query": "((winlog.event_data.Description:\"Windows\\ PowerShell\" OR Product:\"PowerShell\\ Core\\ 6\") AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))"
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
                    "query": "((winlog.event_data.Description:\"Windows\\ PowerShell\" OR Product:\"PowerShell\\ Core\\ 6\") AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))",
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
((Description:"Windows PowerShell" OR Product:"PowerShell Core 6") AND CommandLine.keyword:(*bxor* *join* *char*))
```


### splunk
    
```
((Description="Windows PowerShell" OR Product="PowerShell Core 6") (CommandLine="*bxor*" OR CommandLine="*join*" OR CommandLine="*char*"))
```


### logpoint
    
```
((Description="Windows PowerShell" OR Product="PowerShell Core 6") CommandLine IN ["*bxor*", "*join*", "*char*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*Windows PowerShell|.*PowerShell Core 6)))(?=.*(?:.*.*bxor.*|.*.*join.*|.*.*char.*)))'
```



