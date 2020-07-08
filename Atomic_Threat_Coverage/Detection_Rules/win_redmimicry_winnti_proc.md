| Title                    | RedMimicry Winnti Playbook Execute       |
|:-------------------------|:------------------|
| **Description**          | Detects actions caused by the RedMimicry Winnti playbook |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1106: Native API](https://attack.mitre.org/techniques/T1106)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1106: Native API](../Triggers/T1106.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://redmimicry.com](https://redmimicry.com)</li></ul>  |
| **Author**               | Alexander Rausch |


## Detection Rules

### Sigma rule

```
title: RedMimicry Winnti Playbook Execute
id: 95022b85-ff2a-49fa-939a-d7b8f56eeb9b
description: Detects actions caused by the RedMimicry Winnti playbook
references:
    - https://redmimicry.com
author: Alexander Rausch
date: 2020/06/24
tags:
    - attack.execution
    - attack.t1059
    - attack.t1106
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - rundll32.exe
            - cmd.exe
        CommandLine|contains:
            - gthread-3.6.dll
            - \Windows\Temp\tmp.bat
            - sigcmm-2.4.dll
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*rundll32.exe.*" -or $_.message -match "Image.*.*cmd.exe.*") -and ($_.message -match "CommandLine.*.*gthread-3.6.dll.*" -or $_.message -match "CommandLine.*.*\\Windows\\Temp\\tmp.bat.*" -or $_.message -match "CommandLine.*.*sigcmm-2.4.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*rundll32.exe* OR *cmd.exe*) AND winlog.event_data.CommandLine.keyword:(*gthread\-3.6.dll* OR *\\Windows\\Temp\\tmp.bat* OR *sigcmm\-2.4.dll*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/95022b85-ff2a-49fa-939a-d7b8f56eeb9b <<EOF
{
  "metadata": {
    "title": "RedMimicry Winnti Playbook Execute",
    "description": "Detects actions caused by the RedMimicry Winnti playbook",
    "tags": [
      "attack.execution",
      "attack.t1059",
      "attack.t1106"
    ],
    "query": "(winlog.event_data.Image.keyword:(*rundll32.exe* OR *cmd.exe*) AND winlog.event_data.CommandLine.keyword:(*gthread\\-3.6.dll* OR *\\\\Windows\\\\Temp\\\\tmp.bat* OR *sigcmm\\-2.4.dll*))"
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
                    "query": "(winlog.event_data.Image.keyword:(*rundll32.exe* OR *cmd.exe*) AND winlog.event_data.CommandLine.keyword:(*gthread\\-3.6.dll* OR *\\\\Windows\\\\Temp\\\\tmp.bat* OR *sigcmm\\-2.4.dll*))",
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
        "subject": "Sigma Rule 'RedMimicry Winnti Playbook Execute'",
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
(Image.keyword:(*rundll32.exe* *cmd.exe*) AND CommandLine.keyword:(*gthread\-3.6.dll* *\\Windows\\Temp\\tmp.bat* *sigcmm\-2.4.dll*))
```


### splunk
    
```
((Image="*rundll32.exe*" OR Image="*cmd.exe*") (CommandLine="*gthread-3.6.dll*" OR CommandLine="*\\Windows\\Temp\\tmp.bat*" OR CommandLine="*sigcmm-2.4.dll*"))
```


### logpoint
    
```
(event_id="1" Image IN ["*rundll32.exe*", "*cmd.exe*"] CommandLine IN ["*gthread-3.6.dll*", "*\\Windows\\Temp\\tmp.bat*", "*sigcmm-2.4.dll*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*rundll32\.exe.*|.*.*cmd\.exe.*))(?=.*(?:.*.*gthread-3\.6\.dll.*|.*.*\Windows\Temp\tmp\.bat.*|.*.*sigcmm-2\.4\.dll.*)))'
```



