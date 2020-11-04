| Title                    | Control Panel Items       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of a control panel item (.cpl) outside of the System32 folder |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1196: Control Panel Items](https://attack.mitre.org/techniques/T1196)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1196: Control Panel Items](../Triggers/T1196.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Kyaw Min Thein |


## Detection Rules

### Sigma rule

```
title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: experimental
description: Detects the use of a control panel item (.cpl) outside of the System32 folder
reference:
    - https://attack.mitre.org/techniques/T1196/
tags:
    - attack.execution
    - attack.t1196
    - attack.defense_evasion
author: Kyaw Min Thein
date: 2019/08/27
level: critical
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: '*.cpl'
    filter:
        CommandLine:
            - '*\System32\\*'
            - '*%System%*'
    condition: selection and not filter
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*.cpl" -and  -not (($_.message -match "CommandLine.*.*\\System32\\.*" -or $_.message -match "CommandLine.*.*%System%.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\System32\\* OR *%System%*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/0ba863e6-def5-4e50-9cea-4dd8c7dc46a4 <<EOF
{
  "metadata": {
    "title": "Control Panel Items",
    "description": "Detects the use of a control panel item (.cpl) outside of the System32 folder",
    "tags": [
      "attack.execution",
      "attack.t1196",
      "attack.defense_evasion"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\System32\\\\* OR *%System%*))))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\System32\\\\* OR *%System%*))))",
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
        "subject": "Sigma Rule 'Control Panel Items'",
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
(CommandLine.keyword:*.cpl AND (NOT (CommandLine.keyword:(*\\System32\\* *%System%*))))
```


### splunk
    
```
(CommandLine="*.cpl" NOT ((CommandLine="*\\System32\\*" OR CommandLine="*%System%*")))
```


### logpoint
    
```
(CommandLine="*.cpl"  -(CommandLine IN ["*\\System32\\*", "*%System%*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\.cpl)(?=.*(?!.*(?:.*(?=.*(?:.*.*\System32\\.*|.*.*%System%.*))))))'
```



