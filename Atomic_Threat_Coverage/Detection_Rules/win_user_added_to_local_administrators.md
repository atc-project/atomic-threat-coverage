| Title                    | User Added to Local Administrators       |
|:-------------------------|:------------------|
| **Description**          | This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0069_4732_member_was_added_to_security_enabled_local_group](../Data_Needed/DN_0069_4732_member_was_added_to_security_enabled_local_group.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administrative activity</li></ul>  |
| **Development Status**   | stable |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: User Added to Local Administrators
id: c265cf08-3f99-46c1-8d59-328247057d57
description: This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation
    activity
status: stable
author: Florian Roth
date: 2017/03/14
tags:
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4732
    selection_group1:
        GroupName: 'Administrators'
    selection_group2:
        GroupSid: 'S-1-5-32-544'
    filter:
        SubjectUserName: '*$'
    condition: selection and (1 of selection_group*) and not filter
falsepositives:
    - Legitimate administrative activity
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4732" -and ($_.message -match "GroupName.*Administrators" -or $_.message -match "GroupSid.*S-1-5-32-544")) -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"4732" AND winlog.channel:"Security" AND (winlog.event_data.GroupName:"Administrators" OR winlog.event_data.GroupSid:"S\-1\-5\-32\-544")) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c265cf08-3f99-46c1-8d59-328247057d57 <<EOF
{
  "metadata": {
    "title": "User Added to Local Administrators",
    "description": "This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1078"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4732\" AND winlog.channel:\"Security\" AND (winlog.event_data.GroupName:\"Administrators\" OR winlog.event_data.GroupSid:\"S\\-1\\-5\\-32\\-544\")) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4732\" AND winlog.channel:\"Security\" AND (winlog.event_data.GroupName:\"Administrators\" OR winlog.event_data.GroupSid:\"S\\-1\\-5\\-32\\-544\")) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))",
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
        "subject": "Sigma Rule 'User Added to Local Administrators'",
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
((EventID:"4732" AND (GroupName:"Administrators" OR GroupSid:"S\-1\-5\-32\-544")) AND (NOT (SubjectUserName.keyword:*$)))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4732" source="WinEventLog:Security" (GroupName="Administrators" OR GroupSid="S-1-5-32-544")) NOT (SubjectUserName="*$"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4732" event_source="Microsoft-Windows-Security-Auditing" (group_name="Administrators" OR group_sid="S-1-5-32-544"))  -(SubjectUserName="*$"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4732)(?=.*(?:.*(?:.*Administrators|.*S-1-5-32-544)))))(?=.*(?!.*(?:.*(?=.*.*\$)))))'
```



