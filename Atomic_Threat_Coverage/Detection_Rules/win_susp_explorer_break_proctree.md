| Title                    | Explorer Root Flag Process Tree Break       |
|:-------------------------|:------------------|
| **Description**          | Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown how many legitimate software products use that method</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/CyberRaiju/status/1273597319322058752](https://twitter.com/CyberRaiju/status/1273597319322058752)</li><li>[https://twitter.com/bohops/status/1276357235954909188?s=12](https://twitter.com/bohops/status/1276357235954909188?s=12)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Explorer Root Flag Process Tree Break
id: 949f1ffb-6e85-4f00-ae1e-c3c5b190d605
description: Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer
status: experimental
references:
    - https://twitter.com/CyberRaiju/status/1273597319322058752
    - https://twitter.com/bohops/status/1276357235954909188?s=12
author: Florian Roth
date: 2019/06/29
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'explorer.exe'
            - ' /root,'
    condition: selection
falsepositives:
    - Unknown how many legitimate software products use that method
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*explorer.exe.*" -and $_.message -match "CommandLine.*.* /root,.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*explorer.exe* AND winlog.event_data.CommandLine.keyword:*\ \/root,*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/949f1ffb-6e85-4f00-ae1e-c3c5b190d605 <<EOF
{
  "metadata": {
    "title": "Explorer Root Flag Process Tree Break",
    "description": "Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer",
    "tags": [
      "attack.defense_evasion"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*explorer.exe* AND winlog.event_data.CommandLine.keyword:*\\ \\/root,*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*explorer.exe* AND winlog.event_data.CommandLine.keyword:*\\ \\/root,*)",
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
        "subject": "Sigma Rule 'Explorer Root Flag Process Tree Break'",
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
(CommandLine.keyword:*explorer.exe* AND CommandLine.keyword:* \/root,*)
```


### splunk
    
```
(CommandLine="*explorer.exe*" CommandLine="* /root,*")
```


### logpoint
    
```
(event_id="1" CommandLine="*explorer.exe*" CommandLine="* /root,*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*explorer\.exe.*)(?=.*.* /root,.*))'
```



