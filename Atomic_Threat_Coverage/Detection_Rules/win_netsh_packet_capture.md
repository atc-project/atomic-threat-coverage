| Title                    | Capture a Network Trace with netsh.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects capture a network trace via netsh.exe trace functionality |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/](https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/)</li></ul>  |
| **Author**               | Kutepov Anton, oscd.community |


## Detection Rules

### Sigma rule

```
title: Capture a Network Trace with netsh.exe
id: d3c3861d-c504-4c77-ba55-224ba82d0118
status: experimental
description: Detects capture a network trace via netsh.exe trace functionality
references:
    - https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/
author: Kutepov Anton, oscd.community
date: 2019/10/24
tags:
    - attack.discovery
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - netsh
            - trace
            - start
    condition: selection    
falsepositives: 
    - Legitimate administrator or user uses netsh.exe trace functionality for legitimate reason
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*netsh.*" -and $_.message -match "CommandLine.*.*trace.*" -and $_.message -match "CommandLine.*.*start.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*netsh* AND winlog.event_data.CommandLine.keyword:*trace* AND winlog.event_data.CommandLine.keyword:*start*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d3c3861d-c504-4c77-ba55-224ba82d0118 <<EOF
{
  "metadata": {
    "title": "Capture a Network Trace with netsh.exe",
    "description": "Detects capture a network trace via netsh.exe trace functionality",
    "tags": [
      "attack.discovery",
      "attack.t1040"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*netsh* AND winlog.event_data.CommandLine.keyword:*trace* AND winlog.event_data.CommandLine.keyword:*start*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*netsh* AND winlog.event_data.CommandLine.keyword:*trace* AND winlog.event_data.CommandLine.keyword:*start*)",
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
        "subject": "Sigma Rule 'Capture a Network Trace with netsh.exe'",
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
(CommandLine.keyword:*netsh* AND CommandLine.keyword:*trace* AND CommandLine.keyword:*start*)
```


### splunk
    
```
(CommandLine="*netsh*" CommandLine="*trace*" CommandLine="*start*")
```


### logpoint
    
```
(event_id="1" CommandLine="*netsh*" CommandLine="*trace*" CommandLine="*start*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*netsh.*)(?=.*.*trace.*)(?=.*.*start.*))'
```



