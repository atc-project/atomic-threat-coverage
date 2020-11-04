| Title                    | Reconnaissance Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects activity as "net user administrator /domain" and "net group domain admins /domain" |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1069: Permission Groups Discovery](https://attack.mitre.org/techniques/T1069)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0029_4661_handle_to_an_object_was_requested](../Data_Needed/DN_0029_4661_handle_to_an_object_was_requested.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li><li>[T1069: Permission Groups Discovery](../Triggers/T1069.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrator activity</li><li>Penetration tests</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html](https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html)</li></ul>  |
| **Author**               | Florian Roth (rule), Jack Croock (method) |
| Other Tags           | <ul><li>attack.s0039</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Reconnaissance Activity
id: 968eef52-9cff-4454-8992-1e74b9cbad6c
status: experimental
description: Detects activity as "net user administrator /domain" and "net group domain admins /domain"
references:
    - https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html
author: Florian Roth (rule), Jack Croock (method)
date: 2017/03/07
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1069
    - attack.s0039
logsource:
    product: windows
    service: security
    definition: The volume of Event ID 4661 is high on Domain Controllers and therefore "Audit SAM" and "Audit Kernel Object" advanced audit policy settings are not configured in the recommendations for server systems
detection:
    selection:
        - EventID: 4661
          ObjectType: 'SAM_USER'
          ObjectName: 'S-1-5-21-*-500'
          AccessMask: '0x2d'
        - EventID: 4661
          ObjectType: 'SAM_GROUP'
          ObjectName: 'S-1-5-21-*-512'
          AccessMask: '0x2d'
    condition: selection
falsepositives:
    - Administrator activity
    - Penetration tests
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4661" -and $_.message -match "AccessMask.*0x2d" -and (($_.message -match "ObjectType.*SAM_USER" -and $_.message -match "ObjectName.*S-1-5-21-.*-500") -or ($_.message -match "ObjectType.*SAM_GROUP" -and $_.message -match "ObjectName.*S-1-5-21-.*-512"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4661" AND winlog.event_data.AccessMask:"0x2d" AND ((winlog.event_data.ObjectType:"SAM_USER" AND winlog.event_data.ObjectName.keyword:S\-1\-5\-21\-*\-500) OR (winlog.event_data.ObjectType:"SAM_GROUP" AND winlog.event_data.ObjectName.keyword:S\-1\-5\-21\-*\-512)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/968eef52-9cff-4454-8992-1e74b9cbad6c <<EOF
{
  "metadata": {
    "title": "Reconnaissance Activity",
    "description": "Detects activity as \"net user administrator /domain\" and \"net group domain admins /domain\"",
    "tags": [
      "attack.discovery",
      "attack.t1087",
      "attack.t1069",
      "attack.s0039"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4661\" AND winlog.event_data.AccessMask:\"0x2d\" AND ((winlog.event_data.ObjectType:\"SAM_USER\" AND winlog.event_data.ObjectName.keyword:S\\-1\\-5\\-21\\-*\\-500) OR (winlog.event_data.ObjectType:\"SAM_GROUP\" AND winlog.event_data.ObjectName.keyword:S\\-1\\-5\\-21\\-*\\-512)))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4661\" AND winlog.event_data.AccessMask:\"0x2d\" AND ((winlog.event_data.ObjectType:\"SAM_USER\" AND winlog.event_data.ObjectName.keyword:S\\-1\\-5\\-21\\-*\\-500) OR (winlog.event_data.ObjectType:\"SAM_GROUP\" AND winlog.event_data.ObjectName.keyword:S\\-1\\-5\\-21\\-*\\-512)))",
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
        "subject": "Sigma Rule 'Reconnaissance Activity'",
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
(EventID:"4661" AND AccessMask:"0x2d" AND ((ObjectType:"SAM_USER" AND ObjectName.keyword:S\-1\-5\-21\-*\-500) OR (ObjectType:"SAM_GROUP" AND ObjectName.keyword:S\-1\-5\-21\-*\-512)))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4661" AccessMask="0x2d" ((ObjectType="SAM_USER" ObjectName="S-1-5-21-*-500") OR (ObjectType="SAM_GROUP" ObjectName="S-1-5-21-*-512")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4661" AccessMask="0x2d" ((ObjectType="SAM_USER" ObjectName="S-1-5-21-*-500") OR (ObjectType="SAM_GROUP" ObjectName="S-1-5-21-*-512")))
```


### grep
    
```
grep -P '^(?:.*(?=.*4661)(?=.*0x2d)(?=.*(?:.*(?:.*(?:.*(?=.*SAM_USER)(?=.*S-1-5-21-.*-500))|.*(?:.*(?=.*SAM_GROUP)(?=.*S-1-5-21-.*-512))))))'
```



