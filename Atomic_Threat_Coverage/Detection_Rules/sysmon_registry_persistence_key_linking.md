| Title                    | Windows Registry Persistence COM Key Linking       |
|:-------------------------|:------------------|
| **Description**          | Detects COM object hijacking via TreatAs subkey |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1122: Component Object Model Hijacking](https://attack.mitre.org/techniques/T1122)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Maybe some system utilities in rare cases use linking keys for backward compability</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)</li></ul>  |
| **Author**               | Kutepov Anton, oscd.community |


## Detection Rules

### Sigma rule

```
title: Windows Registry Persistence COM Key Linking
id: 9b0f8a61-91b2-464f-aceb-0527e0a45020
status: experimental
description: Detects COM object hijacking via TreatAs subkey
references:
    - https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
author: Kutepov Anton, oscd.community
date: 2019/10/23
modified: 2019/11/07
tags:
    - attack.persistence
    - attack.t1122
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 12
        TargetObject: 'HKU\\*_Classes\CLSID\\*\TreatAs'
    condition: selection
falsepositives:
    - Maybe some system utilities in rare cases use linking keys for backward compability
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "12" -and $_.message -match "TargetObject.*HKU\\.*_Classes\\CLSID\\.*\\TreatAs") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"12" AND winlog.event_data.TargetObject.keyword:HKU\\*_Classes\\CLSID\\*\\TreatAs)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9b0f8a61-91b2-464f-aceb-0527e0a45020 <<EOF
{
  "metadata": {
    "title": "Windows Registry Persistence COM Key Linking",
    "description": "Detects COM object hijacking via TreatAs subkey",
    "tags": [
      "attack.persistence",
      "attack.t1122"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"12\" AND winlog.event_data.TargetObject.keyword:HKU\\\\*_Classes\\\\CLSID\\\\*\\\\TreatAs)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"12\" AND winlog.event_data.TargetObject.keyword:HKU\\\\*_Classes\\\\CLSID\\\\*\\\\TreatAs)",
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
        "subject": "Sigma Rule 'Windows Registry Persistence COM Key Linking'",
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
(EventID:"12" AND TargetObject.keyword:HKU\\*_Classes\\CLSID\\*\\TreatAs)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="12" TargetObject="HKU\\*_Classes\\CLSID\\*\\TreatAs")
```


### logpoint
    
```
(event_id="12" TargetObject="HKU\\*_Classes\\CLSID\\*\\TreatAs")
```


### grep
    
```
grep -P '^(?:.*(?=.*12)(?=.*HKU\\.*_Classes\CLSID\\.*\TreatAs))'
```



