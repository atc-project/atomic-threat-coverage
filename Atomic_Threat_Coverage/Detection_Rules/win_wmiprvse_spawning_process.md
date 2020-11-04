| Title                    | Wmiprvse Spawning Process       |
|:-------------------------|:------------------|
| **Description**          | Detects wmiprvse spawning processes |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_win32_process_create_remote.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_win32_process_create_remote.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: Wmiprvse Spawning Process
id: d21374ff-f574-44a7-9998-4a8c8bf33d7d
description: Detects wmiprvse spawning processes
status: experimental
date: 2019/08/15
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1047_windows_management_instrumentation/wmi_win32_process_create_remote.md
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\WmiPrvSe.exe'
    filter:
        - LogonId: '0x3e7'  # LUID 999 for SYSTEM
        - Username: 'NT AUTHORITY\SYSTEM'  # if we don't have LogonId data, fallback on username detection
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "ParentImage.*.*\\WmiPrvSe.exe" -and  -not ($_.message -match "LogonId.*0x3e7" -or $_.message -match "Username.*NT AUTHORITY\\SYSTEM")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\WmiPrvSe.exe AND (NOT (LogonId:"0x3e7" OR Username:"NT\ AUTHORITY\\SYSTEM")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d21374ff-f574-44a7-9998-4a8c8bf33d7d <<EOF
{
  "metadata": {
    "title": "Wmiprvse Spawning Process",
    "description": "Detects wmiprvse spawning processes",
    "tags": [
      "attack.execution",
      "attack.t1047"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\WmiPrvSe.exe AND (NOT (LogonId:\"0x3e7\" OR Username:\"NT\\ AUTHORITY\\\\SYSTEM\")))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\WmiPrvSe.exe AND (NOT (LogonId:\"0x3e7\" OR Username:\"NT\\ AUTHORITY\\\\SYSTEM\")))",
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
        "subject": "Sigma Rule 'Wmiprvse Spawning Process'",
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
(ParentImage.keyword:*\\WmiPrvSe.exe AND (NOT (LogonId:"0x3e7" OR Username:"NT AUTHORITY\\SYSTEM")))
```


### splunk
    
```
(ParentImage="*\\WmiPrvSe.exe" NOT (LogonId="0x3e7" OR Username="NT AUTHORITY\\SYSTEM"))
```


### logpoint
    
```
(ParentImage="*\\WmiPrvSe.exe"  -(LogonId="0x3e7" OR Username="NT AUTHORITY\\SYSTEM"))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\WmiPrvSe\.exe)(?=.*(?!.*(?:.*(?:.*(?=.*0x3e7)|.*(?=.*NT AUTHORITY\SYSTEM))))))'
```



