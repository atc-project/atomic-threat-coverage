| Title                    | Copy from Admin Share       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious copy command from a remote C$ or ADMIN$ share |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrative scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1211636381086339073](https://twitter.com/SBousseaden/status/1211636381086339073)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Copy from Admin Share
id: 855bc8b5-2ae8-402e-a9ed-b889e6df1900
status: experimental
description: Detects a suspicious copy command from a remote C$ or ADMIN$ share
references: 
  - https://twitter.com/SBousseaden/status/1211636381086339073
author: Florian Roth
date: 2019/12/30
tags:
    - attack.lateral_movement
    - attack.t1077
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 
          - 'copy *\c$'
          - 'copy *\ADMIN$'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*copy .*\\c$.*" -or $_.message -match "CommandLine.*.*copy .*\\ADMIN$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*copy\ *\\c$* OR *copy\ *\\ADMIN$*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/855bc8b5-2ae8-402e-a9ed-b889e6df1900 <<EOF
{
  "metadata": {
    "title": "Copy from Admin Share",
    "description": "Detects a suspicious copy command from a remote C$ or ADMIN$ share",
    "tags": [
      "attack.lateral_movement",
      "attack.t1077",
      "attack.t1105"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*copy\\ *\\\\c$* OR *copy\\ *\\\\ADMIN$*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*copy\\ *\\\\c$* OR *copy\\ *\\\\ADMIN$*)",
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
        "subject": "Sigma Rule 'Copy from Admin Share'",
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
CommandLine.keyword:(*copy *\\c$* *copy *\\ADMIN$*)
```


### splunk
    
```
(CommandLine="*copy *\\c$*" OR CommandLine="*copy *\\ADMIN$*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["*copy *\\c$*", "*copy *\\ADMIN$*"]
```


### grep
    
```
grep -P '^(?:.*.*copy .*\c\$.*|.*.*copy .*\ADMIN\$.*)'
```



