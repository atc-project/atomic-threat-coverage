| Title                    | Rare Scheduled Task Creations       |
|:-------------------------|:------------------|
| **Description**          | This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0035_106_task_scheduler_task_registered](../Data_Needed/DN_0035_106_task_scheduler_task_registered.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053: Scheduled Task/Job](../Triggers/T1053.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Software installation</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0111</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rare Scheduled Task Creations
id: b20f6158-9438-41be-83da-a5a16ac90c2b
status: experimental
description: This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count
    function selects tasks with rare names.
tags:
    - attack.persistence
    - attack.t1053
    - attack.s0111
author: Florian Roth
date: 2017/03/17
logsource:
    product: windows
    service: taskscheduler
detection:
    selection:
        EventID: 106
    timeframe: 7d
    condition: selection | count() by TaskName < 5
falsepositives:
    - Software installation
level: low

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | where {($_.ID -eq "106") }  | group-object TaskName | where { $_.count -lt 5 } | select name,count | sort -desc
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/other/win_rare_schtask_creation.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b20f6158-9438-41be-83da-a5a16ac90c2b <<EOF
{
  "metadata": {
    "title": "Rare Scheduled Task Creations",
    "description": "This rule detects rare scheduled task creations. Typically software gets installed on multiple systems and not only on a few. The aggregation and count function selects tasks with rare names.",
    "tags": [
      "attack.persistence",
      "attack.t1053",
      "attack.s0111"
    ],
    "query": "winlog.event_id:\"106\""
  },
  "trigger": {
    "schedule": {
      "interval": "7d"
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
                    "query": "winlog.event_id:\"106\"",
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
          },
          "aggs": {
            "by": {
              "terms": {
                "field": "TaskName",
                "size": 10,
                "order": {
                  "_count": "asc"
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
      "ctx.payload.aggregations.by.buckets.0.doc_count": {
        "lt": 5
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Rare Scheduled Task Creations'",
        "body": "Hits:\n{{#aggregations.by.buckets}}\n {{key}} {{doc_count}}\n{{/aggregations.by.buckets}}\n",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/other/win_rare_schtask_creation.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode="106") | eventstats count as val by TaskName| search val < 5
```


### logpoint
    
```
event_id="106" | chart count() as val by TaskName | search val < 5
```


### grep
    
```
grep -P '^106'
```



