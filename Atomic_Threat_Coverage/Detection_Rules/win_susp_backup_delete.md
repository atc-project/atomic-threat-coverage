| Title                    | Backup Catalog Deleted       |
|:-------------------------|:------------------|
| **Description**          | Detects backup catalog deletions |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1107: File Deletion](https://attack.mitre.org/techniques/T1107)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx](https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx)</li><li>[https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100](https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100)</li></ul>  |
| **Author**               | Florian Roth (rule), Tom U. @c_APT_ure (collection) |
| Other Tags           | <ul><li>attack.t1551.004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Backup Catalog Deleted
id: 9703792d-fd9a-456d-a672-ff92efe4806a
status: experimental
description: Detects backup catalog deletions
references:
    - https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
author: Florian Roth (rule), Tom U. @c_APT_ure (collection)
date: 2017/05/12
tags:
    - attack.defense_evasion
    - attack.t1107
    - attack.t1551.004
logsource:
    product: windows
    service: application
detection:
    selection:
        EventID: 524
        Source: Microsoft-Windows-Backup
    condition: selection
falsepositives:
    - Unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Application | where {($_.ID -eq "524" -and $_.message -match "Source.*Microsoft-Windows-Backup") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Application" AND winlog.event_id:"524" AND winlog.event_data.Source:"Microsoft\-Windows\-Backup")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9703792d-fd9a-456d-a672-ff92efe4806a <<EOF
{
  "metadata": {
    "title": "Backup Catalog Deleted",
    "description": "Detects backup catalog deletions",
    "tags": [
      "attack.defense_evasion",
      "attack.t1107",
      "attack.t1551.004"
    ],
    "query": "(winlog.channel:\"Application\" AND winlog.event_id:\"524\" AND winlog.event_data.Source:\"Microsoft\\-Windows\\-Backup\")"
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
                    "query": "(winlog.channel:\"Application\" AND winlog.event_id:\"524\" AND winlog.event_data.Source:\"Microsoft\\-Windows\\-Backup\")",
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
        "subject": "Sigma Rule 'Backup Catalog Deleted'",
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
(EventID:"524" AND Source:"Microsoft\-Windows\-Backup")
```


### splunk
    
```
(source="WinEventLog:Application" EventCode="524" Source="Microsoft-Windows-Backup")
```


### logpoint
    
```
(event_id="524" Source="Microsoft-Windows-Backup")
```


### grep
    
```
grep -P '^(?:.*(?=.*524)(?=.*Microsoft-Windows-Backup))'
```



