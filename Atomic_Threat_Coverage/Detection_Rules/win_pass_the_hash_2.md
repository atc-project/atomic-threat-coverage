| Title                    | Pass the Hash Activity 2       |
|:-------------------------|:------------------|
| **Description**          | Detects the attack technique pass the hash which is used to move laterally inside the network |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrator activity</li><li>Penetration tests</li></ul>  |
| **Development Status**   | production |
| **References**           | <ul><li>[https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events](https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events)</li><li>[https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis](https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis)</li><li>[https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/](https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/)</li></ul>  |
| **Author**               | Dave Kennedy, Jeff Warren (method) / David Vassallo (rule) |


## Detection Rules

### Sigma rule

```
title: Pass the Hash Activity 2
id: 8eef149c-bd26-49f2-9e5a-9b00e3af499b
status: production
description: Detects the attack technique pass the hash which is used to move laterally inside the network
references:
    - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
    - https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis
    - https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/
author: Dave Kennedy, Jeff Warren (method) / David Vassallo (rule)
date: 2019/06/14
tags:
    - attack.lateral_movement
    - attack.t1075
logsource:
    product: windows
    service: security
    definition: The successful use of PtH for lateral movement between workstations would trigger event ID 4624
detection:
    selection:
        - EventID: 4624
          SubjectUserSid: 'S-1-0-0'
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          KeyLength: '0'
        - EventID: 4624
          LogonType: '9'
          LogonProcessName: 'seclogo'
    filter:
        AccountName: 'ANONYMOUS LOGON'
    condition: selection and not filter
falsepositives:
    - Administrator activity
    - Penetration tests
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4624" -and (($_.message -match "SubjectUserSid.*S-1-0-0" -and $_.message -match "LogonType.*3" -and $_.message -match "LogonProcessName.*NtLmSsp" -and $_.message -match "KeyLength.*0") -or ($_.message -match "LogonType.*9" -and $_.message -match "LogonProcessName.*seclogo"))) -and  -not ($_.message -match "AccountName.*ANONYMOUS LOGON")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"4624" AND ((winlog.event_data.SubjectUserSid:"S\-1\-0\-0" AND winlog.event_data.LogonType:"3" AND winlog.event_data.LogonProcessName:"NtLmSsp" AND winlog.event_data.KeyLength:"0") OR (winlog.event_data.LogonType:"9" AND winlog.event_data.LogonProcessName:"seclogo"))) AND (NOT (winlog.event_data.AccountName:"ANONYMOUS\ LOGON")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8eef149c-bd26-49f2-9e5a-9b00e3af499b <<EOF
{
  "metadata": {
    "title": "Pass the Hash Activity 2",
    "description": "Detects the attack technique pass the hash which is used to move laterally inside the network",
    "tags": [
      "attack.lateral_movement",
      "attack.t1075"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4624\" AND ((winlog.event_data.SubjectUserSid:\"S\\-1\\-0\\-0\" AND winlog.event_data.LogonType:\"3\" AND winlog.event_data.LogonProcessName:\"NtLmSsp\" AND winlog.event_data.KeyLength:\"0\") OR (winlog.event_data.LogonType:\"9\" AND winlog.event_data.LogonProcessName:\"seclogo\"))) AND (NOT (winlog.event_data.AccountName:\"ANONYMOUS\\ LOGON\")))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4624\" AND ((winlog.event_data.SubjectUserSid:\"S\\-1\\-0\\-0\" AND winlog.event_data.LogonType:\"3\" AND winlog.event_data.LogonProcessName:\"NtLmSsp\" AND winlog.event_data.KeyLength:\"0\") OR (winlog.event_data.LogonType:\"9\" AND winlog.event_data.LogonProcessName:\"seclogo\"))) AND (NOT (winlog.event_data.AccountName:\"ANONYMOUS\\ LOGON\")))",
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
        "subject": "Sigma Rule 'Pass the Hash Activity 2'",
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
((EventID:"4624" AND ((SubjectUserSid:"S\-1\-0\-0" AND LogonType:"3" AND LogonProcessName:"NtLmSsp" AND KeyLength:"0") OR (LogonType:"9" AND LogonProcessName:"seclogo"))) AND (NOT (AccountName:"ANONYMOUS LOGON")))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4624" ((SubjectUserSid="S-1-0-0" LogonType="3" LogonProcessName="NtLmSsp" KeyLength="0") OR (LogonType="9" LogonProcessName="seclogo"))) NOT (AccountName="ANONYMOUS LOGON"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4624" ((SubjectUserSid="S-1-0-0" logon_type="3" logon_process="NtLmSsp" key_length="0") OR (logon_type="9" logon_process="seclogo")))  -(AccountName="ANONYMOUS LOGON"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4624)(?=.*(?:.*(?:.*(?:.*(?=.*S-1-0-0)(?=.*3)(?=.*NtLmSsp)(?=.*0))|.*(?:.*(?=.*9)(?=.*seclogo)))))))(?=.*(?!.*(?:.*(?=.*ANONYMOUS LOGON)))))'
```



