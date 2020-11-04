| Title                    | Register new Logon Process by Rubeus       |
|:-------------------------|:------------------|
| **Description**          | Detects potential use of Rubeus via registered new trusted logon process |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)</li></ul>  |
| **Author**               | Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community |


## Detection Rules

### Sigma rule

```
title: Register new Logon Process by Rubeus
id: 12e6d621-194f-4f59-90cc-1959e21e69f7
description: Detects potential use of Rubeus via registered new trusted logon process
status: experimental
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.t1208
author: Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
date: 2019/10/24
logsource:
    product: windows
    service: security
detection:
    selection:
        - EventID: 4611
          LogonProcessName: 'User32LogonProcesss'
    condition: selection
falsepositives:
    - Unkown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4611" -and $_.message -match "LogonProcessName.*User32LogonProcesss") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4611" AND winlog.event_data.LogonProcessName:"User32LogonProcesss")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/12e6d621-194f-4f59-90cc-1959e21e69f7 <<EOF
{
  "metadata": {
    "title": "Register new Logon Process by Rubeus",
    "description": "Detects potential use of Rubeus via registered new trusted logon process",
    "tags": [
      "attack.lateral_movement",
      "attack.privilege_escalation",
      "attack.t1208"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4611\" AND winlog.event_data.LogonProcessName:\"User32LogonProcesss\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4611\" AND winlog.event_data.LogonProcessName:\"User32LogonProcesss\")",
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
        "subject": "Sigma Rule 'Register new Logon Process by Rubeus'",
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
(EventID:"4611" AND LogonProcessName:"User32LogonProcesss")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4611" LogonProcessName="User32LogonProcesss")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4611" logon_process="User32LogonProcesss")
```


### grep
    
```
grep -P '^(?:.*(?=.*4611)(?=.*User32LogonProcesss))'
```



