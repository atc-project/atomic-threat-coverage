| Title                    | Netsh Port Forwarding       |
|:-------------------------|:------------------|
| **Description**          | Detects netsh commands that configure a port forwarding |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1090: Proxy](https://attack.mitre.org/techniques/T1090)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1090: Proxy](../Triggers/T1090.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administration</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Netsh Port Forwarding
id: 322ed9ec-fcab-4f67-9a34-e7c6aef43614
description: Detects netsh commands that configure a port forwarding
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.command_and_control
    - attack.t1090
status: experimental
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - netsh interface portproxy add v4tov4 *
    condition: selection
falsepositives:
    - Legitimate administration
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*netsh interface portproxy add v4tov4 .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(netsh\ interface\ portproxy\ add\ v4tov4\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/322ed9ec-fcab-4f67-9a34-e7c6aef43614 <<EOF
{
  "metadata": {
    "title": "Netsh Port Forwarding",
    "description": "Detects netsh commands that configure a port forwarding",
    "tags": [
      "attack.lateral_movement",
      "attack.command_and_control",
      "attack.t1090"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(netsh\\ interface\\ portproxy\\ add\\ v4tov4\\ *)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(netsh\\ interface\\ portproxy\\ add\\ v4tov4\\ *)",
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
        "subject": "Sigma Rule 'Netsh Port Forwarding'",
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
CommandLine.keyword:(netsh interface portproxy add v4tov4 *)
```


### splunk
    
```
(CommandLine="netsh interface portproxy add v4tov4 *")
```


### logpoint
    
```
CommandLine IN ["netsh interface portproxy add v4tov4 *"]
```


### grep
    
```
grep -P '^(?:.*netsh interface portproxy add v4tov4 .*)'
```



