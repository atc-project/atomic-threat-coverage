| Title                    | Enabled User Right in AD to Control User Objects       |
|:-------------------------|:------------------|
| **Description**          | Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0066_4704_user_right_was_assigned](../Data_Needed/DN_0066_4704_user_right_was_assigned.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1098: Account Manipulation](../Triggers/T1098.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)</li></ul>  |
| **Author**               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Enabled User Right in AD to Control User Objects
id: 311b6ce2-7890-4383-a8c2-663a9f6b43cd
description: Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.
tags:
    - attack.persistence
    - attack.t1098
references:
    - https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
author: '@neu5ron'
date: 2017/07/30
modified: 2020/08/23
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Policy Change > Audit Authorization Policy Change, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authorization Policy Change'
detection:
    selection:
        EventID: 4704
    keywords:
        Message:
            - '*SeEnableDelegationPrivilege*'
    condition: all of them
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4704" -and ($_.message -match ".*SeEnableDelegationPrivilege.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4704" AND Message.keyword:(*SeEnableDelegationPrivilege*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/311b6ce2-7890-4383-a8c2-663a9f6b43cd <<EOF
{
  "metadata": {
    "title": "Enabled User Right in AD to Control User Objects",
    "description": "Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.",
    "tags": [
      "attack.persistence",
      "attack.t1098"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4704\" AND Message.keyword:(*SeEnableDelegationPrivilege*))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4704\" AND Message.keyword:(*SeEnableDelegationPrivilege*))",
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
        "subject": "Sigma Rule 'Enabled User Right in AD to Control User Objects'",
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
(EventID:"4704" AND Message.keyword:(*SeEnableDelegationPrivilege*))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4704" (Message="*SeEnableDelegationPrivilege*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4704" Message IN ["*SeEnableDelegationPrivilege*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4704)(?=.*(?:.*.*SeEnableDelegationPrivilege.*)))'
```



