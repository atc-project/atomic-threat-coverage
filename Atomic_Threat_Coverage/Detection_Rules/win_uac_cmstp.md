| Title                    | Bypass UAC via CMSTP       |
|:-------------------------|:------------------|
| **Description**          | Detect child processes of automatically elevated instances of Microsoft Connection Manager Profile Installer (cmstp.exe). |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1548.002: Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002)</li><li>[T1218.003: CMSTP](https://attack.mitre.org/techniques/T1218/003)</li><li>[T1191: CMSTP](https://attack.mitre.org/techniques/T1191)</li><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1548.002: Bypass User Access Control](../Triggers/T1548.002.md)</li><li>[T1218.003: CMSTP](../Triggers/T1218.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate use of cmstp.exe utility by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/e584f1a1-c303-4885-8a66-21360c90995b.html](https://eqllib.readthedocs.io/en/latest/analytics/e584f1a1-c303-4885-8a66-21360c90995b.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1191/T1191.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1191/T1191.md)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Bypass UAC via CMSTP
id: e66779cc-383e-4224-a3a4-267eeb585c40
description: Detect child processes of automatically elevated instances of Microsoft Connection Manager Profile Installer (cmstp.exe).
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2020/08/29
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/e584f1a1-c303-4885-8a66-21360c90995b.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1191/T1191.md
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1548.002
    - attack.t1218.003
    - attack.t1191      # an old one
    - attack.t1088      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmstp.exe'
        CommandLine|contains:
            - '/s'
            - '/au'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate use of cmstp.exe utility by legitimate user
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\cmstp.exe" -and ($_.message -match "CommandLine.*.*/s.*" -or $_.message -match "CommandLine.*.*/au.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\cmstp.exe AND winlog.event_data.CommandLine.keyword:(*\/s* OR *\/au*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e66779cc-383e-4224-a3a4-267eeb585c40 <<EOF
{
  "metadata": {
    "title": "Bypass UAC via CMSTP",
    "description": "Detect child processes of automatically elevated instances of Microsoft Connection Manager Profile Installer (cmstp.exe).",
    "tags": [
      "attack.privilege_escalation",
      "attack.defense_evasion",
      "attack.t1548.002",
      "attack.t1218.003",
      "attack.t1191",
      "attack.t1088"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\cmstp.exe AND winlog.event_data.CommandLine.keyword:(*\\/s* OR *\\/au*))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\cmstp.exe AND winlog.event_data.CommandLine.keyword:(*\\/s* OR *\\/au*))",
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
        "subject": "Sigma Rule 'Bypass UAC via CMSTP'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\cmstp.exe AND CommandLine.keyword:(*\/s* *\/au*))
```


### splunk
    
```
(Image="*\\cmstp.exe" (CommandLine="*/s*" OR CommandLine="*/au*")) | table ComputerName,User,CommandLine
```


### logpoint
    
```
(Image="*\\cmstp.exe" CommandLine IN ["*/s*", "*/au*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\cmstp\.exe)(?=.*(?:.*.*/s.*|.*.*/au.*)))'
```



