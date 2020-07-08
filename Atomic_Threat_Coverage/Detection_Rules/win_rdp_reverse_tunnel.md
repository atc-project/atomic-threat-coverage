| Title                    | RDP over Reverse SSH Tunnel WFP       |
|:-------------------------|:------------------|
| **Description**          | Detects svchost hosting RDP termsvcs communicating with the loopback address |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li><li>[T1090: Proxy](https://attack.mitre.org/techniques/T1090)</li><li>[T1021: Remote Services](https://attack.mitre.org/techniques/T1021)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1096148422984384514](https://twitter.com/SBousseaden/status/1096148422984384514)</li><li>[https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Command%20and%20Control/DE_RDP_Tunnel_5156.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Command%20and%20Control/DE_RDP_Tunnel_5156.evtx)</li></ul>  |
| **Author**               | Samir Bousseaden |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: RDP over Reverse SSH Tunnel WFP
id: 5bed80b6-b3e8-428e-a3ae-d3c757589e41
status: experimental
description: Detects svchost hosting RDP termsvcs communicating with the loopback address
references:
    - https://twitter.com/SBousseaden/status/1096148422984384514
    - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Command%20and%20Control/DE_RDP_Tunnel_5156.evtx
author: Samir Bousseaden
date: 2019/02/16
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.lateral_movement
    - attack.t1076
    - attack.t1090
    - car.2013-07-002
    - attack.t1021
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
    sourceRDP:
        SourcePort: 3389
        DestinationAddress:
            - '127.*'
            - '::1'
    destinationRDP:
        DestinationPort: 3389
        SourceAddress:
            - '127.*'
            - '::1'
    condition: selection and ( sourceRDP or destinationRDP )
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5156" -and (($_.message -match "SourcePort.*3389" -and ($_.message -match "DestinationAddress.*127..*" -or $_.message -match "::1")) -or ($_.message -match "DestinationPort.*3389" -and ($_.message -match "SourceAddress.*127..*" -or $_.message -match "::1")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5156" AND ((winlog.event_data.SourcePort:"3389" AND DestinationAddress.keyword:(127.* OR \:\:1)) OR (winlog.event_data.DestinationPort:"3389" AND SourceAddress.keyword:(127.* OR \:\:1))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/5bed80b6-b3e8-428e-a3ae-d3c757589e41 <<EOF
{
  "metadata": {
    "title": "RDP over Reverse SSH Tunnel WFP",
    "description": "Detects svchost hosting RDP termsvcs communicating with the loopback address",
    "tags": [
      "attack.defense_evasion",
      "attack.command_and_control",
      "attack.lateral_movement",
      "attack.t1076",
      "attack.t1090",
      "car.2013-07-002",
      "attack.t1021"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5156\" AND ((winlog.event_data.SourcePort:\"3389\" AND DestinationAddress.keyword:(127.* OR \\:\\:1)) OR (winlog.event_data.DestinationPort:\"3389\" AND SourceAddress.keyword:(127.* OR \\:\\:1))))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5156\" AND ((winlog.event_data.SourcePort:\"3389\" AND DestinationAddress.keyword:(127.* OR \\:\\:1)) OR (winlog.event_data.DestinationPort:\"3389\" AND SourceAddress.keyword:(127.* OR \\:\\:1))))",
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
        "subject": "Sigma Rule 'RDP over Reverse SSH Tunnel WFP'",
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
(EventID:"5156" AND ((SourcePort:"3389" AND DestinationAddress.keyword:(127.* \:\:1)) OR (DestinationPort:"3389" AND SourceAddress.keyword:(127.* \:\:1))))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5156" ((SourcePort="3389" (DestinationAddress="127.*" OR DestinationAddress="::1")) OR (DestinationPort="3389" (SourceAddress="127.*" OR SourceAddress="::1"))))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5156" ((SourcePort="3389" DestinationAddress IN ["127.*", "::1"]) OR (DestinationPort="3389" SourceAddress IN ["127.*", "::1"])))
```


### grep
    
```
grep -P '^(?:.*(?=.*5156)(?=.*(?:.*(?:.*(?:.*(?=.*3389)(?=.*(?:.*127\..*|.*::1)))|.*(?:.*(?=.*3389)(?=.*(?:.*127\..*|.*::1)))))))'
```



