| Title                    | Ryuk Ransomware       |
|:-------------------------|:------------------|
| **Description**          | Detects Ryuk Ransomware command lines |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/](https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/)</li></ul>  |
| **Author**               | Vasiliy Burov |


## Detection Rules

### Sigma rule

```
title: Ryuk Ransomware
id: 0acaad27-9f02-4136-a243-c357202edd74
description: Detects Ryuk Ransomware command lines
status: experimental
references:
    - https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/
author: Vasiliy Burov
date: 2019/08/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\net.exe stop "samss" *'
            - '*\net.exe stop "audioendpointbuilder" *'
            - '*\net.exe stop "unistoresvc_?????" *'
    condition: selection
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*\\net.exe stop \"samss\" .*" -or $_.message -match "CommandLine.*.*\\net.exe stop \"audioendpointbuilder\" .*" -or $_.message -match "CommandLine.*.*\\net.exe stop \"unistoresvc_?????\" .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\net.exe\ stop\ \"samss\"\ * OR *\\net.exe\ stop\ \"audioendpointbuilder\"\ * OR *\\net.exe\ stop\ \"unistoresvc_?????\"\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/0acaad27-9f02-4136-a243-c357202edd74 <<EOF
{
  "metadata": {
    "title": "Ryuk Ransomware",
    "description": "Detects Ryuk Ransomware command lines",
    "tags": "",
    "query": "winlog.event_data.CommandLine.keyword:(*\\\\net.exe\\ stop\\ \\\"samss\\\"\\ * OR *\\\\net.exe\\ stop\\ \\\"audioendpointbuilder\\\"\\ * OR *\\\\net.exe\\ stop\\ \\\"unistoresvc_?????\\\"\\ *)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\net.exe\\ stop\\ \\\"samss\\\"\\ * OR *\\\\net.exe\\ stop\\ \\\"audioendpointbuilder\\\"\\ * OR *\\\\net.exe\\ stop\\ \\\"unistoresvc_?????\\\"\\ *)",
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
        "subject": "Sigma Rule 'Ryuk Ransomware'",
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
CommandLine.keyword:(*\\net.exe stop \"samss\" * *\\net.exe stop \"audioendpointbuilder\" * *\\net.exe stop \"unistoresvc_?????\" *)
```


### splunk
    
```
(CommandLine="*\\net.exe stop \"samss\" *" OR CommandLine="*\\net.exe stop \"audioendpointbuilder\" *" OR CommandLine="*\\net.exe stop \"unistoresvc_?????\" *")
```


### logpoint
    
```
CommandLine IN ["*\\net.exe stop \"samss\" *", "*\\net.exe stop \"audioendpointbuilder\" *", "*\\net.exe stop \"unistoresvc_?????\" *"]
```


### grep
    
```
grep -P '^(?:.*.*\net\.exe stop "samss" .*|.*.*\net\.exe stop "audioendpointbuilder" .*|.*.*\net\.exe stop "unistoresvc_?????" .*)'
```



