| Title                    | CMSTP UAC Bypass via COM Object Access       |
|:-------------------------|:------------------|
| **Description**          | Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1548.002: Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002)</li><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li><li>[T1218.003: CMSTP](https://attack.mitre.org/techniques/T1218/003)</li><li>[T1191: CMSTP](https://attack.mitre.org/techniques/T1191)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1548.002: Bypass User Access Control](../Triggers/T1548.002.md)</li><li>[T1218.003: CMSTP](../Triggers/T1218.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate CMSTP use (unlikely in modern enterprise environments)</li></ul>  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/](https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/)</li><li>[https://twitter.com/hFireF0X/status/897640081053364225](https://twitter.com/hFireF0X/status/897640081053364225)</li></ul>  |
| **Author**               | Nik Seetharaman |
| Other Tags           | <ul><li>attack.g0069</li><li>car.2019-04-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: CMSTP UAC Bypass via COM Object Access
id: 4b60e6f2-bf39-47b4-b4ea-398e33cfe253
status: stable
description: Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
    - attack.t1088  # an old one
    - attack.t1218.003
    - attack.t1191  # an old one
    - attack.g0069
    - car.2019-04-001
author: Nik Seetharaman
modified: 2019/07/31
date: 2019/01/16
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
    - https://twitter.com/hFireF0X/status/897640081053364225
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        ParentCommandLine|contains: '\DllHost.exe '
    selection2:
        ParentCommandLine|endswith:
            - '{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'
            - '{3E000D72-A845-4CD9-BD83-80C07C3B881F}'
    condition: selection1 and selection2
fields:
    - CommandLine
    - ParentCommandLine
    - Hashes
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentCommandLine.*.*\\DllHost.exe .*" -and ($_.message -match "ParentCommandLine.*.*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" -or $_.message -match "ParentCommandLine.*.*{3E000D72-A845-4CD9-BD83-80C07C3B881F}")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentCommandLine.keyword:*\\DllHost.exe\ * AND winlog.event_data.ParentCommandLine.keyword:(*\{3E5FC7F9\-9A51\-4367\-9063\-A120244FBEC7\} OR *\{3E000D72\-A845\-4CD9\-BD83\-80C07C3B881F\}))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/4b60e6f2-bf39-47b4-b4ea-398e33cfe253 <<EOF
{
  "metadata": {
    "title": "CMSTP UAC Bypass via COM Object Access",
    "description": "Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects",
    "tags": [
      "attack.execution",
      "attack.defense_evasion",
      "attack.privilege_escalation",
      "attack.t1548.002",
      "attack.t1088",
      "attack.t1218.003",
      "attack.t1191",
      "attack.g0069",
      "car.2019-04-001"
    ],
    "query": "(winlog.event_data.ParentCommandLine.keyword:*\\\\DllHost.exe\\ * AND winlog.event_data.ParentCommandLine.keyword:(*\\{3E5FC7F9\\-9A51\\-4367\\-9063\\-A120244FBEC7\\} OR *\\{3E000D72\\-A845\\-4CD9\\-BD83\\-80C07C3B881F\\}))"
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
                    "query": "(winlog.event_data.ParentCommandLine.keyword:*\\\\DllHost.exe\\ * AND winlog.event_data.ParentCommandLine.keyword:(*\\{3E5FC7F9\\-9A51\\-4367\\-9063\\-A120244FBEC7\\} OR *\\{3E000D72\\-A845\\-4CD9\\-BD83\\-80C07C3B881F\\}))",
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
        "subject": "Sigma Rule 'CMSTP UAC Bypass via COM Object Access'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n           Hashes = {{_source.Hashes}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(ParentCommandLine.keyword:*\\DllHost.exe * AND ParentCommandLine.keyword:(*\{3E5FC7F9\-9A51\-4367\-9063\-A120244FBEC7\} *\{3E000D72\-A845\-4CD9\-BD83\-80C07C3B881F\}))
```


### splunk
    
```
(ParentCommandLine="*\\DllHost.exe *" (ParentCommandLine="*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" OR ParentCommandLine="*{3E000D72-A845-4CD9-BD83-80C07C3B881F}")) | table CommandLine,ParentCommandLine,Hashes
```


### logpoint
    
```
(ParentCommandLine="*\\DllHost.exe *" ParentCommandLine IN ["*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "*{3E000D72-A845-4CD9-BD83-80C07C3B881F}"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\DllHost\.exe .*)(?=.*(?:.*.*\{3E5FC7F9-9A51-4367-9063-A120244FBEC7\}|.*.*\{3E000D72-A845-4CD9-BD83-80C07C3B881F\})))'
```



