| Title                    | Windows Registry Trust Record Modification       |
|:-------------------------|:------------------|
| **Description**          | Alerts on trust record modification within the registry, indicating usage of macros |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/techniques/T1193)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1193: Spearphishing Attachment](../Triggers/T1193.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Alerts on legitimate macro usage as well, will need to filter as appropriate</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/](https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/)</li><li>[http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html](http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html)</li></ul>  |
| **Author**               | Antonlovesdnb |


## Detection Rules

### Sigma rule

```
title: Windows Registry Trust Record Modification
id: 295a59c1-7b79-4b47-a930-df12c15fc9c2
status: experimental
description: Alerts on trust record modification within the registry, indicating usage of macros
references:
    - https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
    - http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html
author: Antonlovesdnb
date: 2020/02/19
modified: 2020/02/19
tags:
    - attack.initial_access
    - attack.t1193
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 12
        TargetObject|contains: 'TrustRecords'
    condition: selection
falsepositives:
    - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "12" -and $_.message -match "TargetObject.*.*TrustRecords.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"12" AND winlog.event_data.TargetObject.keyword:*TrustRecords*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/295a59c1-7b79-4b47-a930-df12c15fc9c2 <<EOF
{
  "metadata": {
    "title": "Windows Registry Trust Record Modification",
    "description": "Alerts on trust record modification within the registry, indicating usage of macros",
    "tags": [
      "attack.initial_access",
      "attack.t1193"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"12\" AND winlog.event_data.TargetObject.keyword:*TrustRecords*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"12\" AND winlog.event_data.TargetObject.keyword:*TrustRecords*)",
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
        "subject": "Sigma Rule 'Windows Registry Trust Record Modification'",
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
(EventID:"12" AND TargetObject.keyword:*TrustRecords*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="12" TargetObject="*TrustRecords*")
```


### logpoint
    
```
(event_id="12" TargetObject="*TrustRecords*")
```


### grep
    
```
grep -P '^(?:.*(?=.*12)(?=.*.*TrustRecords.*))'
```



