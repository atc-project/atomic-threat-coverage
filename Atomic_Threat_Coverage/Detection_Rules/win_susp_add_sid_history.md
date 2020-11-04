| Title                    | Addition of SID History to Active Directory Object       |
|:-------------------------|:------------------|
| **Description**          | An attacker can use the SID history attribute to gain additional privileges. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1178: SID-History Injection](https://attack.mitre.org/techniques/T1178)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li><li>[DN_0074_4765_sid_history_was_added_to_an_account](../Data_Needed/DN_0074_4765_sid_history_was_added_to_an_account.md)</li><li>[DN_0075_4766_attempt_to_add_sid_history_to_an_account_failed](../Data_Needed/DN_0075_4766_attempt_to_add_sid_history_to_an_account_failed.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Migration of an account into a new domain</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)</li></ul>  |
| **Author**               | Thomas Patzke, @atc_project (improvements) |


## Detection Rules

### Sigma rule

```
title: Addition of SID History to Active Directory Object
id: 2632954e-db1c-49cb-9936-67d1ef1d17d2
status: stable
description: An attacker can use the SID history attribute to gain additional privileges.
references:
    - https://adsecurity.org/?p=1772
author: Thomas Patzke, @atc_project (improvements)
date: 2017/02/19
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1178
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 4765
            - 4766
    selection2:
        EventID: 4738
    selection3:
        SidHistory:
            - '-'
            - '%%1793'
    condition: selection1 or (selection2 and not selection3)
falsepositives:
    - Migration of an account into a new domain
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {((($_.ID -eq "4765" -or $_.ID -eq "4766") -or ($_.ID -eq "4738" -and  -not (($_.message -match "-" -or $_.message -match "%%1793"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:("4765" OR "4766") OR (winlog.channel:"Security" AND winlog.event_id:"4738" AND (NOT (SidHistory:("\-" OR "%%1793"))))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/2632954e-db1c-49cb-9936-67d1ef1d17d2 <<EOF
{
  "metadata": {
    "title": "Addition of SID History to Active Directory Object",
    "description": "An attacker can use the SID history attribute to gain additional privileges.",
    "tags": [
      "attack.persistence",
      "attack.privilege_escalation",
      "attack.t1178"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:(\"4765\" OR \"4766\") OR (winlog.channel:\"Security\" AND winlog.event_id:\"4738\" AND (NOT (SidHistory:(\"\\-\" OR \"%%1793\"))))))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:(\"4765\" OR \"4766\") OR (winlog.channel:\"Security\" AND winlog.event_id:\"4738\" AND (NOT (SidHistory:(\"\\-\" OR \"%%1793\"))))))",
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
        "subject": "Sigma Rule 'Addition of SID History to Active Directory Object'",
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
(EventID:("4765" "4766") OR (EventID:"4738" AND (NOT (SidHistory:("\-" "%%1793")))))
```


### splunk
    
```
(source="WinEventLog:Security" ((EventCode="4765" OR EventCode="4766") OR (source="WinEventLog:Security" EventCode="4738" NOT ((SidHistory="-" OR SidHistory="%%1793")))))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id IN ["4765", "4766"] OR (event_source="Microsoft-Windows-Security-Auditing" event_id="4738"  -(SidHistory IN ["-", "%%1793"]))))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*4765|.*4766)|.*(?:.*(?=.*4738)(?=.*(?!.*(?:.*(?=.*(?:.*-|.*%%1793))))))))'
```



