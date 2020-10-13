| Title                    | Powershell AMSI Bypass via .NET Reflection       |
|:-------------------------|:------------------|
| **Description**          | Detects Request to amsiInitFailed that can be used to disable AMSI Scanning |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1562.001: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1562.001: Disable or Modify Tools](../Triggers/T1562.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Potential Admin Activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/mattifestation/status/735261176745988096](https://twitter.com/mattifestation/status/735261176745988096)</li><li>[https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120](https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120)</li></ul>  |
| **Author**               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Powershell AMSI Bypass via .NET Reflection
id: 30edb182-aa75-42c0-b0a9-e998bb29067c
status: experimental
description: Detects Request to amsiInitFailed that can be used to disable AMSI Scanning
references:
    - https://twitter.com/mattifestation/status/735261176745988096
    - https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120
tags:
    - attack.defense_evasion
    - attack.t1089         # an old one
    - attack.t1562.001
author: Markus Neis
date: 2018/08/17
modified: 2020/09/01
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*System.Management.Automation.AmsiUtils*'
    selection2:
        CommandLine:
            - '*amsiInitFailed*'
    condition: selection1 and selection2
falsepositives:
    - Potential Admin Activity
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*System.Management.Automation.AmsiUtils.*") -and ($_.message -match "CommandLine.*.*amsiInitFailed.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*System.Management.Automation.AmsiUtils*) AND winlog.event_data.CommandLine.keyword:(*amsiInitFailed*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/30edb182-aa75-42c0-b0a9-e998bb29067c <<EOF
{
  "metadata": {
    "title": "Powershell AMSI Bypass via .NET Reflection",
    "description": "Detects Request to amsiInitFailed that can be used to disable AMSI Scanning",
    "tags": [
      "attack.defense_evasion",
      "attack.t1089",
      "attack.t1562.001"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*System.Management.Automation.AmsiUtils*) AND winlog.event_data.CommandLine.keyword:(*amsiInitFailed*))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*System.Management.Automation.AmsiUtils*) AND winlog.event_data.CommandLine.keyword:(*amsiInitFailed*))",
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
        "subject": "Sigma Rule 'Powershell AMSI Bypass via .NET Reflection'",
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
(CommandLine.keyword:(*System.Management.Automation.AmsiUtils*) AND CommandLine.keyword:(*amsiInitFailed*))
```


### splunk
    
```
((CommandLine="*System.Management.Automation.AmsiUtils*") (CommandLine="*amsiInitFailed*"))
```


### logpoint
    
```
(CommandLine IN ["*System.Management.Automation.AmsiUtils*"] CommandLine IN ["*amsiInitFailed*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*System\.Management\.Automation\.AmsiUtils.*))(?=.*(?:.*.*amsiInitFailed.*)))'
```



