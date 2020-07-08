| Title                    | SAM Dump to AppData       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration testing</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1003.002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: SAM Dump to AppData
id: 839dd1e8-eda8-4834-8145-01beeee33acd
status: experimental
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.002
author: Florian Roth
date: 2018/01/27
logsource:
    product: windows
    service: system
    definition: The source of this type of event is Kernel-General
detection:
    selection:
        EventID: 16
        Message:
            - '*\AppData\Local\Temp\SAM-*.dmp *'
    condition: selection
falsepositives:
    - Penetration testing
level: high

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "16" -and ($_.message -match "Message.*.*\\AppData\\Local\\Temp\\SAM-.*.dmp .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"16" AND Message.keyword:(*\\AppData\\Local\\Temp\\SAM\-*.dmp\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/839dd1e8-eda8-4834-8145-01beeee33acd <<EOF
{
  "metadata": {
    "title": "SAM Dump to AppData",
    "description": "Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.002"
    ],
    "query": "(winlog.event_id:\"16\" AND Message.keyword:(*\\\\AppData\\\\Local\\\\Temp\\\\SAM\\-*.dmp\\ *))"
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
                    "query": "(winlog.event_id:\"16\" AND Message.keyword:(*\\\\AppData\\\\Local\\\\Temp\\\\SAM\\-*.dmp\\ *))",
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
        "subject": "Sigma Rule 'SAM Dump to AppData'",
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
(EventID:"16" AND Message.keyword:(*\\AppData\\Local\\Temp\\SAM\-*.dmp *))
```


### splunk
    
```
(source="WinEventLog:System" EventCode="16" (Message="*\\AppData\\Local\\Temp\\SAM-*.dmp *"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="16" Message IN ["*\\AppData\\Local\\Temp\\SAM-*.dmp *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*16)(?=.*(?:.*.*\AppData\Local\Temp\SAM-.*\.dmp .*)))'
```



