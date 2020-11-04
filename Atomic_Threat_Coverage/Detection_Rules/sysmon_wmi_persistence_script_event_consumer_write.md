| Title                    | WMI Persistence - Script Event Consumer File Write       |
|:-------------------------|:------------------|
| **Description**          | Detects file writes of WMI script event consumer |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1084)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](../Triggers/T1084.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown (data set is too small; further testing needed)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: WMI Persistence - Script Event Consumer File Write
id: 33f41cdd-35ac-4ba8-814b-c6a4244a1ad4
status: experimental
description: Detects file writes of WMI script event consumer
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
tags:
    - attack.t1084
    - attack.persistence
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        Image: 'C:\WINDOWS\system32\wbem\scrcons.exe'
    condition: selection
falsepositives: 
    - Unknown (data set is too small; further testing needed)
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "Image.*C:\\WINDOWS\\system32\\wbem\\scrcons.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND winlog.event_data.Image:"C\:\\WINDOWS\\system32\\wbem\\scrcons.exe")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/33f41cdd-35ac-4ba8-814b-c6a4244a1ad4 <<EOF
{
  "metadata": {
    "title": "WMI Persistence - Script Event Consumer File Write",
    "description": "Detects file writes of WMI script event consumer",
    "tags": [
      "attack.t1084",
      "attack.persistence"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.Image:\"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.Image:\"C\\:\\\\WINDOWS\\\\system32\\\\wbem\\\\scrcons.exe\")",
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
        "subject": "Sigma Rule 'WMI Persistence - Script Event Consumer File Write'",
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
(EventID:"11" AND Image:"C\:\\WINDOWS\\system32\\wbem\\scrcons.exe")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" Image="C:\\WINDOWS\\system32\\wbem\\scrcons.exe")
```


### logpoint
    
```
(event_id="11" Image="C:\\WINDOWS\\system32\\wbem\\scrcons.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*C:\WINDOWS\system32\wbem\scrcons\.exe))'
```



