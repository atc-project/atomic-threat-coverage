| Title                    | Windows 10 Scheduled Task SandboxEscaper 0-day       |
|:-------------------------|:------------------|
| **Description**          | Detects Task Scheduler .job import arbitrary DACL write\par |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005)</li><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe](https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe)</li></ul>  |
| **Author**               | Olaf Hartong |
| Other Tags           | <ul><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Windows 10 Scheduled Task SandboxEscaper 0-day
id: 931b6802-d6a6-4267-9ffa-526f57f22aaf
status: experimental
description: Detects Task Scheduler .job import arbitrary DACL write\par
references:
    - https://github.com/SandboxEscaper/polarbearrepo/tree/master/bearlpe
author: Olaf Hartong
date: 2019/05/22
modified: 2020/08/29
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine: '*/change*/TN*/RU*/RP*'
    condition: selection
falsepositives:
    - Unknown
tags:
    - attack.privilege_escalation
    - attack.t1053.005
    - attack.t1053      # an old one
    - car.2013-08-001
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.*/change.*/TN.*/RU.*/RP.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\schtasks.exe AND winlog.event_data.CommandLine.keyword:*\/change*\/TN*\/RU*\/RP*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/931b6802-d6a6-4267-9ffa-526f57f22aaf <<EOF
{
  "metadata": {
    "title": "Windows 10 Scheduled Task SandboxEscaper 0-day",
    "description": "Detects Task Scheduler .job import arbitrary DACL write\\par",
    "tags": [
      "attack.privilege_escalation",
      "attack.t1053.005",
      "attack.t1053",
      "car.2013-08-001"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\schtasks.exe AND winlog.event_data.CommandLine.keyword:*\\/change*\\/TN*\\/RU*\\/RP*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\schtasks.exe AND winlog.event_data.CommandLine.keyword:*\\/change*\\/TN*\\/RU*\\/RP*)",
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
        "subject": "Sigma Rule 'Windows 10 Scheduled Task SandboxEscaper 0-day'",
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
(Image.keyword:*\\schtasks.exe AND CommandLine.keyword:*\/change*\/TN*\/RU*\/RP*)
```


### splunk
    
```
(Image="*\\schtasks.exe" CommandLine="*/change*/TN*/RU*/RP*")
```


### logpoint
    
```
(Image="*\\schtasks.exe" CommandLine="*/change*/TN*/RU*/RP*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\schtasks\.exe)(?=.*.*/change.*/TN.*/RU.*/RP.*))'
```



