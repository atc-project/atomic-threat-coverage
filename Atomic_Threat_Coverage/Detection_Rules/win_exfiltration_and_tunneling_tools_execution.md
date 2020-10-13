| Title                    | Exfiltration and Tunneling Tools Execution       |
|:-------------------------|:------------------|
| **Description**          | Execution of well known tools for data exfiltration and tunneling |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1043: Commonly Used Port](https://attack.mitre.org/techniques/T1043)</li><li>[T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)</li><li>[T1572: Protocol Tunneling](https://attack.mitre.org/techniques/T1572)</li><li>[T1071.001: Web Protocols](https://attack.mitre.org/techniques/T1071/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1071.001: Web Protocols](../Triggers/T1071.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate Administrator using tools</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Exfiltration and Tunneling Tools Execution
id: c75309a3-59f8-4a8d-9c2c-4c927ad50555
description: Execution of well known tools for data exfiltration and tunneling
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2020/08/29
tags:
    - attack.exfiltration
    - attack.command_and_control
    - attack.t1043   # an old one
    - attack.t1041
    - attack.t1572
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\plink.exe'
            - '\socat.exe'
            - '\stunnel.exe'
            - '\httptunnel.exe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tools
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\plink.exe" -or $_.message -match "Image.*.*\\socat.exe" -or $_.message -match "Image.*.*\\stunnel.exe" -or $_.message -match "Image.*.*\\httptunnel.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Image.keyword:(*\\plink.exe OR *\\socat.exe OR *\\stunnel.exe OR *\\httptunnel.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c75309a3-59f8-4a8d-9c2c-4c927ad50555 <<EOF
{
  "metadata": {
    "title": "Exfiltration and Tunneling Tools Execution",
    "description": "Execution of well known tools for data exfiltration and tunneling",
    "tags": [
      "attack.exfiltration",
      "attack.command_and_control",
      "attack.t1043",
      "attack.t1041",
      "attack.t1572",
      "attack.t1071.001"
    ],
    "query": "winlog.event_data.Image.keyword:(*\\\\plink.exe OR *\\\\socat.exe OR *\\\\stunnel.exe OR *\\\\httptunnel.exe)"
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
                    "query": "winlog.event_data.Image.keyword:(*\\\\plink.exe OR *\\\\socat.exe OR *\\\\stunnel.exe OR *\\\\httptunnel.exe)",
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
        "subject": "Sigma Rule 'Exfiltration and Tunneling Tools Execution'",
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
Image.keyword:(*\\plink.exe *\\socat.exe *\\stunnel.exe *\\httptunnel.exe)
```


### splunk
    
```
(Image="*\\plink.exe" OR Image="*\\socat.exe" OR Image="*\\stunnel.exe" OR Image="*\\httptunnel.exe")
```


### logpoint
    
```
Image IN ["*\\plink.exe", "*\\socat.exe", "*\\stunnel.exe", "*\\httptunnel.exe"]
```


### grep
    
```
grep -P '^(?:.*.*\plink\.exe|.*.*\socat\.exe|.*.*\stunnel\.exe|.*.*\httptunnel\.exe)'
```



