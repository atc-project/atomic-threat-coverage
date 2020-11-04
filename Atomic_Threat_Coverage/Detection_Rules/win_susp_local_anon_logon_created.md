| Title                    | Suspicious Windows ANONYMOUS LOGON Local Account Created       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of suspicious accounts simliar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0086_4720_user_account_was_created](../Data_Needed/DN_0086_4720_user_account_was_created.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1136: Create Account](../Triggers/T1136.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1189469425482829824](https://twitter.com/SBousseaden/status/1189469425482829824)</li></ul>  |
| **Author**               | James Pemberton / @4A616D6573 |


## Detection Rules

### Sigma rule

```
title: Suspicious Windows ANONYMOUS LOGON Local Account Created
id: 1bbf25b9-8038-4154-a50b-118f2a32be27
status: experimental
description: Detects the creation of suspicious accounts simliar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.
references:
    - https://twitter.com/SBousseaden/status/1189469425482829824
author: James Pemberton / @4A616D6573
date: 2019/10/31
tags:
    - attack.persistence
    - attack.t1136
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        SAMAccountName: '*ANONYMOUS*LOGON*'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4720" -and $_.message -match "SAMAccountName.*.*ANONYMOUS.*LOGON.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4720" AND SAMAccountName.keyword:*ANONYMOUS*LOGON*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1bbf25b9-8038-4154-a50b-118f2a32be27 <<EOF
{
  "metadata": {
    "title": "Suspicious Windows ANONYMOUS LOGON Local Account Created",
    "description": "Detects the creation of suspicious accounts simliar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.",
    "tags": [
      "attack.persistence",
      "attack.t1136"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4720\" AND SAMAccountName.keyword:*ANONYMOUS*LOGON*)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4720\" AND SAMAccountName.keyword:*ANONYMOUS*LOGON*)",
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
        "subject": "Sigma Rule 'Suspicious Windows ANONYMOUS LOGON Local Account Created'",
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
(EventID:"4720" AND SAMAccountName.keyword:*ANONYMOUS*LOGON*)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4720" SAMAccountName="*ANONYMOUS*LOGON*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4720" SAMAccountName="*ANONYMOUS*LOGON*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4720)(?=.*.*ANONYMOUS.*LOGON.*))'
```



