| Title                    | Control Panel Items       |
|:-------------------------|:------------------|
| **Description**          | Detects the malicious use of a control panel item |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1196: Control Panel Items](https://attack.mitre.org/techniques/T1196)</li><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_) |


## Detection Rules

### Sigma rule

```
title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: experimental
description: Detects the malicious use of a control panel item
reference:
    - https://attack.mitre.org/techniques/T1196/
    - https://ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins
tags:
    - attack.execution
    - attack.t1196
    - attack.defense_evasion
    - attack.t1218
author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
date: 2020/06/22
level: critical
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        CommandLine: '*.cpl'
    filter:
        CommandLine:
            - '*\System32\\*'
            - '*%System%*'
    selection2:
        CommandLine:
            - '*reg add*'
    selection3:
        CommandLine:
            - '*CurrentVersion\\Control Panel\\CPLs*'
    condition: (selection1 and not filter) or (selection2 and selection3)
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and (($_.message -match "CommandLine.*.*.cpl" -and  -not (($_.message -match "CommandLine.*.*\\System32\\.*" -or $_.message -match "CommandLine.*.*%System%.*"))) -or (($_.message -match "CommandLine.*.*reg add.*") -and ($_.message -match "CommandLine.*.*CurrentVersion\\Control Panel\\CPLs.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\System32\\* OR *%System%*)))) OR (winlog.event_data.CommandLine.keyword:(*reg\ add*) AND winlog.event_data.CommandLine.keyword:(*CurrentVersion\\Control\ Panel\\CPLs*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/0ba863e6-def5-4e50-9cea-4dd8c7dc46a4 <<EOF
{
  "metadata": {
    "title": "Control Panel Items",
    "description": "Detects the malicious use of a control panel item",
    "tags": [
      "attack.execution",
      "attack.t1196",
      "attack.defense_evasion",
      "attack.t1218"
    ],
    "query": "((winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\System32\\\\* OR *%System%*)))) OR (winlog.event_data.CommandLine.keyword:(*reg\\ add*) AND winlog.event_data.CommandLine.keyword:(*CurrentVersion\\\\Control\\ Panel\\\\CPLs*)))"
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
                    "query": "((winlog.event_data.CommandLine.keyword:*.cpl AND (NOT (winlog.event_data.CommandLine.keyword:(*\\\\System32\\\\* OR *%System%*)))) OR (winlog.event_data.CommandLine.keyword:(*reg\\ add*) AND winlog.event_data.CommandLine.keyword:(*CurrentVersion\\\\Control\\ Panel\\\\CPLs*)))",
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
((CommandLine.keyword:*.cpl AND (NOT (CommandLine.keyword:(*\\System32\\* *%System%*)))) OR (CommandLine.keyword:(*reg add*) AND CommandLine.keyword:(*CurrentVersion\\Control Panel\\CPLs*)))
```


### splunk
    
```
((CommandLine="*.cpl" NOT ((CommandLine="*\\System32\\*" OR CommandLine="*%System%*"))) OR ((CommandLine="*reg add*") (CommandLine="*CurrentVersion\\Control Panel\\CPLs*")))
```


### logpoint
    
```
(event_id="1" ((CommandLine="*.cpl"  -(CommandLine IN ["*\\System32\\*", "*%System%*"])) OR (CommandLine IN ["*reg add*"] CommandLine IN ["*CurrentVersion\\Control Panel\\CPLs*"])))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\.cpl)(?=.*(?!.*(?:.*(?=.*(?:.*.*\System32\\.*|.*.*%System%.*))))))|.*(?:.*(?=.*(?:.*.*reg add.*))(?=.*(?:.*.*CurrentVersion\\Control Panel\\CPLs.*)))))'
```



