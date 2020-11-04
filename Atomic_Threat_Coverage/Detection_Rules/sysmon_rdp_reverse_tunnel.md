| Title                    | RDP Over Reverse SSH Tunnel       |
|:-------------------------|:------------------|
| **Description**          | Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1076: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1076)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1076: Remote Desktop Protocol](../Triggers/T1076.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/SBousseaden/status/1096148422984384514](https://twitter.com/SBousseaden/status/1096148422984384514)</li></ul>  |
| **Author**               | Samir Bousseaden |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: RDP Over Reverse SSH Tunnel
id: 5f699bc5-5446-4a4a-a0b7-5ef2885a3eb4
status: experimental
description: Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389
references:
    - https://twitter.com/SBousseaden/status/1096148422984384514
author: Samir Bousseaden
date: 2019/02/16
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1076
    - car.2013-07-002
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Image: '*\svchost.exe'
        Initiated: 'true'
        SourcePort: 3389
        DestinationIp:
            - '127.*'
            - '::1'
    condition: selection
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Image.*.*\\svchost.exe" -and $_.message -match "Initiated.*true" -and $_.message -match "SourcePort.*3389" -and ($_.message -match "DestinationIp.*127..*" -or $_.message -match "::1")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"3" AND winlog.event_data.Image.keyword:*\\svchost.exe AND Initiated:"true" AND SourcePort:"3389" AND winlog.event_data.DestinationIp.keyword:(127.* OR \:\:1))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/5f699bc5-5446-4a4a-a0b7-5ef2885a3eb4 <<EOF
{
  "metadata": {
    "title": "RDP Over Reverse SSH Tunnel",
    "description": "Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389",
    "tags": [
      "attack.defense_evasion",
      "attack.command_and_control",
      "attack.t1076",
      "car.2013-07-002"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"3\" AND winlog.event_data.Image.keyword:*\\\\svchost.exe AND Initiated:\"true\" AND SourcePort:\"3389\" AND winlog.event_data.DestinationIp.keyword:(127.* OR \\:\\:1))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"3\" AND winlog.event_data.Image.keyword:*\\\\svchost.exe AND Initiated:\"true\" AND SourcePort:\"3389\" AND winlog.event_data.DestinationIp.keyword:(127.* OR \\:\\:1))",
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
        "subject": "Sigma Rule 'RDP Over Reverse SSH Tunnel'",
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
(EventID:"3" AND Image.keyword:*\\svchost.exe AND Initiated:"true" AND SourcePort:"3389" AND DestinationIp.keyword:(127.* \:\:1))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="3" Image="*\\svchost.exe" Initiated="true" SourcePort="3389" (DestinationIp="127.*" OR DestinationIp="::1"))
```


### logpoint
    
```
(event_id="3" Image="*\\svchost.exe" Initiated="true" SourcePort="3389" DestinationIp IN ["127.*", "::1"])
```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*.*\svchost\.exe)(?=.*true)(?=.*3389)(?=.*(?:.*127\..*|.*::1)))'
```



