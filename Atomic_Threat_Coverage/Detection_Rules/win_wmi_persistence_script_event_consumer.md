| Title                    | WMI Persistence - Script Event Consumer       |
|:-------------------------|:------------------|
| **Description**          | Detects WMI script event consumers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1546.003: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003)</li><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1546.003: Windows Management Instrumentation Event Subscription](../Triggers/T1546.003.md)</li><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate event consumers</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: WMI Persistence - Script Event Consumer
id: ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e
status: experimental
description: Detects WMI script event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
modified: 2020/08/29
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.003
    - attack.t1047 # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: C:\WINDOWS\system32\wbem\scrcons.exe
        ParentImage: C:\Windows\System32\svchost.exe
    condition: selection
falsepositives:
    - Legitimate event consumers
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*C:\\WINDOWS\\system32\\wbem\\scrcons.exe" -and $_.message -match "ParentImage.*C:\\Windows\\System32\\svchost.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image:"C\:\\WINDOWS\\system32\\wbem\\scrcons.exe" AND winlog.event_data.ParentImage:"C\:\\Windows\\System32\\svchost.exe")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e <<EOF
{
  "metadata": {
    "title": "WMI Persistence - Script Event Consumer",
    "description": "Detects WMI script event consumers",
    "tags": [
      "attack.persistence",
      "attack.privilege_escalation",
      "attack.t1546.003",
      "attack.t1047"
    ],
    "query": "(winlog.event_data.Image:\"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe\" AND winlog.event_data.ParentImage:\"C\\:\\\\Windows\\\\System32\\\\svchost.exe\")"
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
                    "query": "(winlog.event_data.Image:\"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe\" AND winlog.event_data.ParentImage:\"C\\:\\\\Windows\\\\System32\\\\svchost.exe\")",
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
        "subject": "Sigma Rule 'WMI Persistence - Script Event Consumer'",
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
(Image:"C\:\\WINDOWS\\system32\\wbem\\scrcons.exe" AND ParentImage:"C\:\\Windows\\System32\\svchost.exe")
```


### splunk
    
```
(Image="C:\\WINDOWS\\system32\\wbem\\scrcons.exe" ParentImage="C:\\Windows\\System32\\svchost.exe")
```


### logpoint
    
```
(Image="C:\\WINDOWS\\system32\\wbem\\scrcons.exe" ParentImage="C:\\Windows\\System32\\svchost.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*C:\WINDOWS\system32\wbem\scrcons\.exe)(?=.*C:\Windows\System32\svchost\.exe))'
```



