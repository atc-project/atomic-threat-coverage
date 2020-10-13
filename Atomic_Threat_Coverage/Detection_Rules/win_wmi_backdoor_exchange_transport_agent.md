| Title                    | WMI Backdoor Exchange Transport Agent       |
|:-------------------------|:------------------|
| **Description**          | Detects a WMi backdoor in Exchange Transport Agents via WMi event filters |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1546.003: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003)</li><li>[T1084: Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1084)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1546.003: Windows Management Instrumentation Event Subscription](../Triggers/T1546.003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/cglyer/status/1182389676876980224](https://twitter.com/cglyer/status/1182389676876980224)</li><li>[https://twitter.com/cglyer/status/1182391019633029120](https://twitter.com/cglyer/status/1182391019633029120)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: WMI Backdoor Exchange Transport Agent
id: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
status: experimental
description: Detects a WMi backdoor in Exchange Transport Agents via WMi event filters
author: Florian Roth
date: 2019/10/11
references:
    - https://twitter.com/cglyer/status/1182389676876980224
    - https://twitter.com/cglyer/status/1182391019633029120
logsource:
    category: process_creation
    product: windows
tags:
    - attack.persistence
    - attack.t1546.003
    - attack.t1084      # an old one
detection:
    selection:
        ParentImage: '*\EdgeTransport.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical


```





### powershell
    
```
Get-WinEvent | where {$_.message -match "ParentImage.*.*\\EdgeTransport.exe" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.ParentImage.keyword:*\\EdgeTransport.exe
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/797011dc-44f4-4e6f-9f10-a8ceefbe566b <<EOF
{
  "metadata": {
    "title": "WMI Backdoor Exchange Transport Agent",
    "description": "Detects a WMi backdoor in Exchange Transport Agents via WMi event filters",
    "tags": [
      "attack.persistence",
      "attack.t1546.003",
      "attack.t1084"
    ],
    "query": "winlog.event_data.ParentImage.keyword:*\\\\EdgeTransport.exe"
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
                    "query": "winlog.event_data.ParentImage.keyword:*\\\\EdgeTransport.exe",
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
        "subject": "Sigma Rule 'WMI Backdoor Exchange Transport Agent'",
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
ParentImage.keyword:*\\EdgeTransport.exe
```


### splunk
    
```
ParentImage="*\\EdgeTransport.exe"
```


### logpoint
    
```
ParentImage="*\\EdgeTransport.exe"
```


### grep
    
```
grep -P '^.*\EdgeTransport\.exe'
```



