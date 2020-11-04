| Title                    | Exfiltration and Tunneling Tools Execution       |
|:-------------------------|:------------------|
| **Description**          | Execution of well known tools for data exfiltration and tunneling |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
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
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName|endswith:
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
Get-WinEvent | where {($_.message -match "NewProcessName.*.*\\plink.exe" -or $_.message -match "NewProcessName.*.*\\socat.exe" -or $_.message -match "NewProcessName.*.*\\stunnel.exe" -or $_.message -match "NewProcessName.*.*\\httptunnel.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.NewProcessName.keyword:(*\\plink.exe OR *\\socat.exe OR *\\stunnel.exe OR *\\httptunnel.exe)
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
      "attack.t1020"
    ],
    "query": "winlog.event_data.NewProcessName.keyword:(*\\\\plink.exe OR *\\\\socat.exe OR *\\\\stunnel.exe OR *\\\\httptunnel.exe)"
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
                    "query": "winlog.event_data.NewProcessName.keyword:(*\\\\plink.exe OR *\\\\socat.exe OR *\\\\stunnel.exe OR *\\\\httptunnel.exe)",
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
NewProcessName.keyword:(*\\plink.exe *\\socat.exe *\\stunnel.exe *\\httptunnel.exe)
```


### splunk
    
```
(NewProcessName="*\\plink.exe" OR NewProcessName="*\\socat.exe" OR NewProcessName="*\\stunnel.exe" OR NewProcessName="*\\httptunnel.exe")
```


### logpoint
    
```
NewProcessName IN ["*\\plink.exe", "*\\socat.exe", "*\\stunnel.exe", "*\\httptunnel.exe"]
```


### grep
    
```
grep -P '^(?:.*.*\plink\.exe|.*.*\socat\.exe|.*.*\stunnel\.exe|.*.*\httptunnel\.exe)'
```



