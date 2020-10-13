| Title                    | Access to ADMIN$ Share       |
|:-------------------------|:------------------|
| **Description**          | Detects access to $ADMIN share |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0033_5140_network_share_object_was_accessed](../Data_Needed/DN_0033_5140_network_share_object_was_accessed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate administrative activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Access to ADMIN$ Share
id: 098d7118-55bc-4912-a836-dc6483a8d150
description: Detects access to $ADMIN share
tags:
    - attack.lateral_movement
    - attack.t1077          # an old one
    - attack.t1021.002
status: experimental
author: Florian Roth
date: 2017/03/04
modified: 2020/08/23
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5140
        ShareName: Admin$
    filter:
        SubjectUserName: '*$'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative activity
level: low

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5140" -and $_.message -match "ShareName.*Admin$") -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"5140" AND winlog.event_data.ShareName:"Admin$") AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/098d7118-55bc-4912-a836-dc6483a8d150 <<EOF
{
  "metadata": {
    "title": "Access to ADMIN$ Share",
    "description": "Detects access to $ADMIN share",
    "tags": [
      "attack.lateral_movement",
      "attack.t1077",
      "attack.t1021.002"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"5140\" AND winlog.event_data.ShareName:\"Admin$\") AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"5140\" AND winlog.event_data.ShareName:\"Admin$\") AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))",
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
        "subject": "Sigma Rule 'Access to ADMIN$ Share'",
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
((EventID:"5140" AND ShareName:"Admin$") AND (NOT (SubjectUserName.keyword:*$)))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5140" ShareName="Admin$") NOT (SubjectUserName="*$"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="5140" ShareName="Admin$")  -(SubjectUserName="*$"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5140)(?=.*Admin\$)))(?=.*(?!.*(?:.*(?=.*.*\$)))))'
```



