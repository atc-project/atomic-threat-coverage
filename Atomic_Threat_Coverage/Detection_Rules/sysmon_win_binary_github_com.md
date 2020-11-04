| Title                    | Microsoft Binary Github Communication       |
|:-------------------------|:------------------|
| **Description**          | Detects an executable in the Windows folder accessing github.com |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li><li>@subTee in your network</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/M_haggis/status/900741347035889665](https://twitter.com/M_haggis/status/900741347035889665)</li><li>[https://twitter.com/M_haggis/status/1032799638213066752](https://twitter.com/M_haggis/status/1032799638213066752)</li></ul>  |
| **Author**               | Michael Haag (idea), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Microsoft Binary Github Communication
id: 635dbb88-67b3-4b41-9ea5-a3af2dd88153
status: experimental
description: Detects an executable in the Windows folder accessing github.com
references:
    - https://twitter.com/M_haggis/status/900741347035889665
    - https://twitter.com/M_haggis/status/1032799638213066752
author: Michael Haag (idea), Florian Roth (rule)
date: 2017/08/24
tags:
    - attack.lateral_movement
    - attack.t1105
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Initiated: 'true'
        DestinationHostname:
            - '*.github.com'
            - '*.githubusercontent.com'
        Image: 'C:\Windows\\*'
    condition: selection
falsepositives:
    - 'Unknown'
    - '@subTee in your network'
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Initiated.*true" -and ($_.message -match "DestinationHostname.*.*.github.com" -or $_.message -match "DestinationHostname.*.*.githubusercontent.com") -and $_.message -match "Image.*C:\\Windows\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"3" AND Initiated:"true" AND winlog.event_data.DestinationHostname.keyword:(*.github.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\:\\Windows\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/635dbb88-67b3-4b41-9ea5-a3af2dd88153 <<EOF
{
  "metadata": {
    "title": "Microsoft Binary Github Communication",
    "description": "Detects an executable in the Windows folder accessing github.com",
    "tags": [
      "attack.lateral_movement",
      "attack.t1105"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"3\" AND Initiated:\"true\" AND winlog.event_data.DestinationHostname.keyword:(*.github.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\\:\\\\Windows\\\\*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"3\" AND Initiated:\"true\" AND winlog.event_data.DestinationHostname.keyword:(*.github.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\\:\\\\Windows\\\\*)",
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
        "subject": "Sigma Rule 'Microsoft Binary Github Communication'",
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
(EventID:"3" AND Initiated:"true" AND DestinationHostname.keyword:(*.github.com *.githubusercontent.com) AND Image.keyword:C\:\\Windows\\*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="3" Initiated="true" (DestinationHostname="*.github.com" OR DestinationHostname="*.githubusercontent.com") Image="C:\\Windows\\*")
```


### logpoint
    
```
(event_id="3" Initiated="true" DestinationHostname IN ["*.github.com", "*.githubusercontent.com"] Image="C:\\Windows\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*true)(?=.*(?:.*.*\.github\.com|.*.*\.githubusercontent\.com))(?=.*C:\Windows\\.*))'
```



