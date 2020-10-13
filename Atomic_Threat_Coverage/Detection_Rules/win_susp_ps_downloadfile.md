| Title                    | PowerShell DownloadFile       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1104: Multi-Stage Channels](https://attack.mitre.org/techniques/T1104)</li><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html](https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell DownloadFile
id: 8f70ac5f-1f6f-4f8e-b454-db19561216c5
status: experimental
description: Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line
references:
    - https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html
author: Florian Roth
date: 2020/08/28
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one     
    - attack.command_and_control
    - attack.t1104
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - '.DownloadFile'
            - 'System.Net.WebClient'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*powershell.*" -and $_.message -match "CommandLine.*.*.DownloadFile.*" -and $_.message -match "CommandLine.*.*System.Net.WebClient.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*powershell* AND winlog.event_data.CommandLine.keyword:*.DownloadFile* AND winlog.event_data.CommandLine.keyword:*System.Net.WebClient*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8f70ac5f-1f6f-4f8e-b454-db19561216c5 <<EOF
{
  "metadata": {
    "title": "PowerShell DownloadFile",
    "description": "Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line",
    "tags": [
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086",
      "attack.command_and_control",
      "attack.t1104",
      "attack.t1105"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*powershell* AND winlog.event_data.CommandLine.keyword:*.DownloadFile* AND winlog.event_data.CommandLine.keyword:*System.Net.WebClient*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*powershell* AND winlog.event_data.CommandLine.keyword:*.DownloadFile* AND winlog.event_data.CommandLine.keyword:*System.Net.WebClient*)",
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
        "subject": "Sigma Rule 'PowerShell DownloadFile'",
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
(CommandLine.keyword:*powershell* AND CommandLine.keyword:*.DownloadFile* AND CommandLine.keyword:*System.Net.WebClient*)
```


### splunk
    
```
(CommandLine="*powershell*" CommandLine="*.DownloadFile*" CommandLine="*System.Net.WebClient*")
```


### logpoint
    
```
(CommandLine="*powershell*" CommandLine="*.DownloadFile*" CommandLine="*System.Net.WebClient*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*powershell.*)(?=.*.*\.DownloadFile.*)(?=.*.*System\.Net\.WebClient.*))'
```



