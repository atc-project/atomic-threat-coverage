| Title                    | User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'       |
|:-------------------------|:------------------|
| **Description**          | The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)</li></ul>  |
| **Author**               | Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community |
| Other Tags           | <ul><li>attack.t1558.003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'
id: 6daac7fc-77d1-449a-a71a-e6b4d59a0e54
description: The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.
status: experimental
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.t1208
    - attack.t1558.003
author: Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
date: 2019/10/24
logsource:
    product: windows
    service: security
detection:
    selection:
        - EventID: 4673
          Service: 'LsaRegisterLogonProcess()'
          Keywords: '0x8010000000000000'     #failure
    condition: selection
falsepositives:
    - Unkown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4673" -and $_.message -match "Service.*LsaRegisterLogonProcess()" -and $_.message -match "Keywords.*0x8010000000000000") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4673" AND Service:"LsaRegisterLogonProcess\(\)" AND Keywords:"0x8010000000000000")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/6daac7fc-77d1-449a-a71a-e6b4d59a0e54 <<EOF
{
  "metadata": {
    "title": "User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'",
    "description": "The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.",
    "tags": [
      "attack.lateral_movement",
      "attack.privilege_escalation",
      "attack.t1208",
      "attack.t1558.003"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4673\" AND Service:\"LsaRegisterLogonProcess\\(\\)\" AND Keywords:\"0x8010000000000000\")"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4673\" AND Service:\"LsaRegisterLogonProcess\\(\\)\" AND Keywords:\"0x8010000000000000\")",
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
        "subject": "Sigma Rule 'User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess''",
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
(EventID:"4673" AND Service:"LsaRegisterLogonProcess\(\)" AND Keywords:"0x8010000000000000")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4673" Service="LsaRegisterLogonProcess()" Keywords="0x8010000000000000")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4673" Service="LsaRegisterLogonProcess()" Keywords="0x8010000000000000")
```


### grep
    
```
grep -P '^(?:.*(?=.*4673)(?=.*LsaRegisterLogonProcess\(\))(?=.*0x8010000000000000))'
```



