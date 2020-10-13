| Title                    | Vulnerable Netlogon Secure Channel Connection Allowed       |
|:-------------------------|:------------------|
| **Description**          | Detects that a vulnerable Netlogon secure channel connection was allowed, which could be an indicator of CVE-2020-1472. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc](https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc)</li></ul>  |
| **Author**               | NVISO |


## Detection Rules

### Sigma rule

```
title: Vulnerable Netlogon Secure Channel Connection Allowed
id: a0cb7110-edf0-47a4-9177-541a4083128a
status: experimental
description: Detects that a vulnerable Netlogon secure channel connection was allowed, which could be an indicator of CVE-2020-1472.
references:
    - https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc
author: NVISO
date: 2020/09/15
tags:
    - attack.privilege_escalation
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID:
            - 5829
    condition: selection
fields:
    - SAMAccountName
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName System | where {(($_.ID -eq "5829")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_id:("5829")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/a0cb7110-edf0-47a4-9177-541a4083128a <<EOF
{
  "metadata": {
    "title": "Vulnerable Netlogon Secure Channel Connection Allowed",
    "description": "Detects that a vulnerable Netlogon secure channel connection was allowed, which could be an indicator of CVE-2020-1472.",
    "tags": [
      "attack.privilege_escalation"
    ],
    "query": "winlog.event_id:(\"5829\")"
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
                    "query": "winlog.event_id:(\"5829\")",
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
        "subject": "Sigma Rule 'Vulnerable Netlogon Secure Channel Connection Allowed'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nSAMAccountName = {{_source.SAMAccountName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
EventID:("5829")
```


### splunk
    
```
(source="WinEventLog:System" (EventCode="5829")) | table SAMAccountName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["5829"])
```


### grep
    
```
grep -P '^(?:.*5829)'
```



