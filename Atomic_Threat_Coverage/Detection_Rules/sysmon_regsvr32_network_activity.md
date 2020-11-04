| Title                    | Regsvr32 Network Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects network connections and DNS queries initiated by Regsvr32.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1117: Regsvr32](https://attack.mitre.org/techniques/T1117)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li><li>[DN_0085_22_windows_sysmon_DnsQuery](../Data_Needed/DN_0085_22_windows_sysmon_DnsQuery.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1117: Regsvr32](../Triggers/T1117.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/](https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/)</li><li>[https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/](https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md)</li></ul>  |
| **Author**               | Dmitriy Lifanov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Regsvr32 Network Activity
id: c7e91a02-d771-4a6d-a700-42587e0b1095
description: Detects network connections and DNS queries initiated by Regsvr32.exe
references:
    - https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
    - https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1117
author: Dmitriy Lifanov, oscd.community
status: experimental
date: 2019/10/25
modified: 2019/11/10
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID:
         - 3
         - 22
        Image|endswith: '\regsvr32.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - Image
    - DestinationIp
    - DestinationPort
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3" -or $_.ID -eq "22") -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:("3" OR "22") AND winlog.event_data.Image.keyword:*\\regsvr32.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c7e91a02-d771-4a6d-a700-42587e0b1095 <<EOF
{
  "metadata": {
    "title": "Regsvr32 Network Activity",
    "description": "Detects network connections and DNS queries initiated by Regsvr32.exe",
    "tags": [
      "attack.execution",
      "attack.defense_evasion",
      "attack.t1117"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:(\"3\" OR \"22\") AND winlog.event_data.Image.keyword:*\\\\regsvr32.exe)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:(\"3\" OR \"22\") AND winlog.event_data.Image.keyword:*\\\\regsvr32.exe)",
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
        "subject": "Sigma Rule 'Regsvr32 Network Activity'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n   ComputerName = {{_source.ComputerName}}\n           User = {{_source.User}}\n          Image = {{_source.Image}}\n  DestinationIp = {{_source.DestinationIp}}\nDestinationPort = {{_source.DestinationPort}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:("3" "22") AND Image.keyword:*\\regsvr32.exe)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="3" OR EventCode="22") Image="*\\regsvr32.exe") | table ComputerName,User,Image,DestinationIp,DestinationPort
```


### logpoint
    
```
(event_id IN ["3", "22"] Image="*\\regsvr32.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*3|.*22))(?=.*.*\regsvr32\.exe))'
```



