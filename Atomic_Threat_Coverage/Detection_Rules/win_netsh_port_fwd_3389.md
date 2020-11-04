| Title                    | Netsh RDP Port Forwarding       |
|:-------------------------|:------------------|
| **Description**          | Detects netsh commands that configure a port forwarding of port 3389 used for RDP |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1021: Remote Services](https://attack.mitre.org/techniques/T1021)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate administration</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Netsh RDP Port Forwarding
id: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
description: Detects netsh commands that configure a port forwarding of port 3389 used for RDP
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.t1021
    - car.2013-07-002
status: experimental
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - netsh i* p*=3389 c*
    condition: selection
falsepositives:
    - Legitimate administration
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*netsh i.* p.*=3389 c.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(netsh\ i*\ p*\=3389\ c*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/782d6f3e-4c5d-4b8c-92a3-1d05fed72e63 <<EOF
{
  "metadata": {
    "title": "Netsh RDP Port Forwarding",
    "description": "Detects netsh commands that configure a port forwarding of port 3389 used for RDP",
    "tags": [
      "attack.lateral_movement",
      "attack.t1021",
      "car.2013-07-002"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(netsh\\ i*\\ p*\\=3389\\ c*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(netsh\\ i*\\ p*\\=3389\\ c*)",
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
        "subject": "Sigma Rule 'Netsh RDP Port Forwarding'",
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
CommandLine.keyword:(netsh i* p*=3389 c*)
```


### splunk
    
```
(CommandLine="netsh i* p*=3389 c*")
```


### logpoint
    
```
CommandLine IN ["netsh i* p*=3389 c*"]
```


### grep
    
```
grep -P '^(?:.*netsh i.* p.*=3389 c.*)'
```



