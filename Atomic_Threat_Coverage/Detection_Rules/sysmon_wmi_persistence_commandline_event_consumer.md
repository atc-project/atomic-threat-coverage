| Title                    | WMI Persistence - Command Line Event Consumer       |
|:-------------------------|:------------------|
| **Description**          | Detects WMI command line event consumers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1084)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1084: Windows Management Instrumentation Event Subscription](../Triggers/T1084.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown (data set is too small; further testing needed)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: WMI Persistence - Command Line Event Consumer
id: 05936ce2-ee05-4dae-9d03-9a391cf2d2c6
status: experimental
description: Detects WMI command line event consumers
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
        EventID: 7
        Image: 'C:\Windows\System32\wbem\WmiPrvSE.exe'
        ImageLoaded: 'wbemcons.dll'
    condition: selection
falsepositives: 
    - Unknown (data set is too small; further testing needed)
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" -and $_.message -match "ImageLoaded.*wbemcons.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"7" AND winlog.event_data.Image:"C\:\\Windows\\System32\\wbem\\WmiPrvSE.exe" AND winlog.event_data.ImageLoaded:"wbemcons.dll")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/05936ce2-ee05-4dae-9d03-9a391cf2d2c6 <<EOF
{
  "metadata": {
    "title": "WMI Persistence - Command Line Event Consumer",
    "description": "Detects WMI command line event consumers",
    "tags": [
      "attack.t1084",
      "attack.persistence"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image:\"C\\:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe\" AND winlog.event_data.ImageLoaded:\"wbemcons.dll\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image:\"C\\:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe\" AND winlog.event_data.ImageLoaded:\"wbemcons.dll\")",
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
        "subject": "Sigma Rule 'WMI Persistence - Command Line Event Consumer'",
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
(EventID:"7" AND Image:"C\:\\Windows\\System32\\wbem\\WmiPrvSE.exe" AND ImageLoaded:"wbemcons.dll")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="7" Image="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" ImageLoaded="wbemcons.dll")
```


### logpoint
    
```
(event_id="7" Image="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" ImageLoaded="wbemcons.dll")
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*C:\Windows\System32\wbem\WmiPrvSE\.exe)(?=.*wbemcons\.dll))'
```



