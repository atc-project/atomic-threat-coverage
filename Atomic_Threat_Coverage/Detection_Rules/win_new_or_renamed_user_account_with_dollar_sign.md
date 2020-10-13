| Title                    | New or Renamed User Account with '$' in Attribute 'SamAccountName'.       |
|:-------------------------|:------------------|
| **Description**          | Detects possible bypass EDR and SIEM via abnormal user account name. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0086_4720_user_account_was_created](../Data_Needed/DN_0086_4720_user_account_was_created.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: New or Renamed User Account with '$' in Attribute 'SamAccountName'.
id: cfeed607-6aa4-4bbd-9627-b637deb723c8
status: experimental
description: Detects possible bypass EDR and SIEM via abnormal user account name.
tags:
    - attack.defense_evasion
    - attack.t1036
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2019/11/13
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 
            - 4720 # create user
            - 4781 # rename user
        UserName|contains: '$'    #SamAccountName
    condition: selection
fields:
    - EventID
    - UserName
    - SubjectAccountName
falsepositives:
    - Unkown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4720" -or $_.ID -eq "4781") -and $_.message -match "UserName.*.*$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("4720" OR "4781") AND UserName.keyword:*$*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/cfeed607-6aa4-4bbd-9627-b637deb723c8 <<EOF
{
  "metadata": {
    "title": "New or Renamed User Account with '$' in Attribute 'SamAccountName'.",
    "description": "Detects possible bypass EDR and SIEM via abnormal user account name.",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4720\" OR \"4781\") AND UserName.keyword:*$*)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4720\" OR \"4781\") AND UserName.keyword:*$*)",
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
        "subject": "Sigma Rule 'New or Renamed User Account with '$' in Attribute 'SamAccountName'.'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n           EventID = {{_source.EventID}}\n          UserName = {{_source.UserName}}\nSubjectAccountName = {{_source.SubjectAccountName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:("4720" "4781") AND UserName.keyword:*$*)
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4720" OR EventCode="4781") UserName="*$*") | table EventCode,UserName,SubjectAccountName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4720", "4781"] (caller_user="*$*" OR target_user="*$*" OR user="*$*" OR member="*$*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4720|.*4781))(?=.*.*\$.*))'
```



