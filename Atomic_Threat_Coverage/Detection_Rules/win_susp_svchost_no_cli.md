| Title                    | Suspect Svchost Activity       |
|:-------------------------|:------------------|
| **Description**          | It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>rpcnet.exe / rpcnetp.exe which is a lojack style software. https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2](https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2)</li></ul>  |
| **Author**               | David Burkett |


## Detection Rules

### Sigma rule

```
title: Suspect Svchost Activity
id: 16c37b52-b141-42a5-a3ea-bbe098444397
status: experimental
description: It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.
references:
    - https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2
author: David Burkett
date: 2019/12/28
modified: 2020/08/28
tags:
    - attack.defense_evasion
    - attack.privilege_escalation    
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|endswith: 'svchost.exe' 
    selection2:
        Image|endswith: '\svchost.exe'
    filter:
        ParentImage|endswith:
            - '\rpcnet.exe'
            - '\rpcnetp.exe'
    condition: (selection1 and selection2) and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - rpcnet.exe / rpcnetp.exe which is a lojack style software. https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*svchost.exe" -and $_.message -match "Image.*.*\\svchost.exe") -and  -not (($_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\rpcnetp.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.CommandLine.keyword:*svchost.exe AND winlog.event_data.Image.keyword:*\\svchost.exe) AND (NOT (winlog.event_data.ParentImage.keyword:(*\\rpcnet.exe OR *\\rpcnetp.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/16c37b52-b141-42a5-a3ea-bbe098444397 <<EOF
{
  "metadata": {
    "title": "Suspect Svchost Activity",
    "description": "It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.",
    "tags": [
      "attack.defense_evasion",
      "attack.privilege_escalation",
      "attack.t1055"
    ],
    "query": "((winlog.event_data.CommandLine.keyword:*svchost.exe AND winlog.event_data.Image.keyword:*\\\\svchost.exe) AND (NOT (winlog.event_data.ParentImage.keyword:(*\\\\rpcnet.exe OR *\\\\rpcnetp.exe))))"
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
                    "query": "((winlog.event_data.CommandLine.keyword:*svchost.exe AND winlog.event_data.Image.keyword:*\\\\svchost.exe) AND (NOT (winlog.event_data.ParentImage.keyword:(*\\\\rpcnet.exe OR *\\\\rpcnetp.exe))))",
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
        "subject": "Sigma Rule 'Suspect Svchost Activity'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((CommandLine.keyword:*svchost.exe AND Image.keyword:*\\svchost.exe) AND (NOT (ParentImage.keyword:(*\\rpcnet.exe *\\rpcnetp.exe))))
```


### splunk
    
```
((CommandLine="*svchost.exe" Image="*\\svchost.exe") NOT ((ParentImage="*\\rpcnet.exe" OR ParentImage="*\\rpcnetp.exe"))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((CommandLine="*svchost.exe" Image="*\\svchost.exe")  -(ParentImage IN ["*\\rpcnet.exe", "*\\rpcnetp.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*svchost\.exe)(?=.*.*\svchost\.exe)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\rpcnet\.exe|.*.*\rpcnetp\.exe))))))'
```



