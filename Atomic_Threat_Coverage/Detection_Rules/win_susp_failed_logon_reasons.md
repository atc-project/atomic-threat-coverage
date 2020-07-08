| Title                    | Account Tampering - Suspicious Failed Logon Reasons       |
|:-------------------------|:------------------|
| **Description**          | This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>User using a disabled account</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1101431884540710913](https://twitter.com/SBousseaden/status/1101431884540710913)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Account Tampering - Suspicious Failed Logon Reasons
id: 9eb99343-d336-4020-a3cd-67f3819e68ee
description: This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow
    restricted.
author: Florian Roth
date: 2017/02/19
modified: 2019/03/01
references:
    - https://twitter.com/SBousseaden/status/1101431884540710913
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4625
            - 4776
        Status:
            - '0xC0000072'  # User logon to account disabled by administrator
            - '0xC000006F'  # User logon outside authorized hours
            - '0xC0000070'  # User logon from unauthorized workstation
            - '0xC0000413'  # Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine
            - '0xC000018C'  # The logon request failed because the trust relationship between the primary domain and the trusted domain failed
            - '0xC000015B'  # The user has not been granted the requested logon type (aka logon right) at this machine
    condition: selection
falsepositives:
    - User using a disabled account
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4625" -or $_.ID -eq "4776") -and ($_.message -match "0xC0000072" -or $_.message -match "0xC000006F" -or $_.message -match "0xC0000070" -or $_.message -match "0xC0000413" -or $_.message -match "0xC000018C" -or $_.message -match "0xC000015B")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("4625" OR "4776") AND winlog.event_data.Status:("0xC0000072" OR "0xC000006F" OR "0xC0000070" OR "0xC0000413" OR "0xC000018C" OR "0xC000015B"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9eb99343-d336-4020-a3cd-67f3819e68ee <<EOF
{
  "metadata": {
    "title": "Account Tampering - Suspicious Failed Logon Reasons",
    "description": "This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.",
    "tags": [
      "attack.persistence",
      "attack.privilege_escalation",
      "attack.t1078"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4625\" OR \"4776\") AND winlog.event_data.Status:(\"0xC0000072\" OR \"0xC000006F\" OR \"0xC0000070\" OR \"0xC0000413\" OR \"0xC000018C\" OR \"0xC000015B\"))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:(\"4625\" OR \"4776\") AND winlog.event_data.Status:(\"0xC0000072\" OR \"0xC000006F\" OR \"0xC0000070\" OR \"0xC0000413\" OR \"0xC000018C\" OR \"0xC000015B\"))",
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
        "subject": "Sigma Rule 'Account Tampering - Suspicious Failed Logon Reasons'",
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
(EventID:("4625" "4776") AND Status:("0xC0000072" "0xC000006F" "0xC0000070" "0xC0000413" "0xC000018C" "0xC000015B"))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4625" OR EventCode="4776") (Status="0xC0000072" OR Status="0xC000006F" OR Status="0xC0000070" OR Status="0xC0000413" OR Status="0xC000018C" OR Status="0xC000015B"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4625", "4776"] Status IN ["0xC0000072", "0xC000006F", "0xC0000070", "0xC0000413", "0xC000018C", "0xC000015B"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4625|.*4776))(?=.*(?:.*0xC0000072|.*0xC000006F|.*0xC0000070|.*0xC0000413|.*0xC000018C|.*0xC000015B)))'
```



