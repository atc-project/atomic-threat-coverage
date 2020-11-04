| Title                    | Microsoft Binary Suspicious Communication Endpoint       |
|:-------------------------|:------------------|
| **Description**          | Detects an executable in the Windows folder accessing suspicious domains |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/M_haggis/status/900741347035889665](https://twitter.com/M_haggis/status/900741347035889665)</li><li>[https://twitter.com/M_haggis/status/1032799638213066752](https://twitter.com/M_haggis/status/1032799638213066752)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Microsoft Binary Suspicious Communication Endpoint
id: e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97
status: experimental
description: Detects an executable in the Windows folder accessing suspicious domains
references:
    - https://twitter.com/M_haggis/status/900741347035889665
    - https://twitter.com/M_haggis/status/1032799638213066752
author: Florian Roth
date: 2018/08/30
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
            - '*dl.dropboxusercontent.com'
            - '*.pastebin.com'
            - '*.githubusercontent.com' # includes both gists and github repositories
        Image: 'C:\Windows\\*'
    condition: selection
falsepositives:
    - 'Unknown'
level: high


```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Initiated.*true" -and ($_.message -match "DestinationHostname.*.*dl.dropboxusercontent.com" -or $_.message -match "DestinationHostname.*.*.pastebin.com" -or $_.message -match "DestinationHostname.*.*.githubusercontent.com") -and $_.message -match "Image.*C:\\Windows\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"3" AND Initiated:"true" AND winlog.event_data.DestinationHostname.keyword:(*dl.dropboxusercontent.com OR *.pastebin.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\:\\Windows\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97 <<EOF
{
  "metadata": {
    "title": "Microsoft Binary Suspicious Communication Endpoint",
    "description": "Detects an executable in the Windows folder accessing suspicious domains",
    "tags": [
      "attack.lateral_movement",
      "attack.t1105"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"3\" AND Initiated:\"true\" AND winlog.event_data.DestinationHostname.keyword:(*dl.dropboxusercontent.com OR *.pastebin.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\\:\\\\Windows\\\\*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"3\" AND Initiated:\"true\" AND winlog.event_data.DestinationHostname.keyword:(*dl.dropboxusercontent.com OR *.pastebin.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\\:\\\\Windows\\\\*)",
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
        "subject": "Sigma Rule 'Microsoft Binary Suspicious Communication Endpoint'",
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
(EventID:"3" AND Initiated:"true" AND DestinationHostname.keyword:(*dl.dropboxusercontent.com *.pastebin.com *.githubusercontent.com) AND Image.keyword:C\:\\Windows\\*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="3" Initiated="true" (DestinationHostname="*dl.dropboxusercontent.com" OR DestinationHostname="*.pastebin.com" OR DestinationHostname="*.githubusercontent.com") Image="C:\\Windows\\*")
```


### logpoint
    
```
(event_id="3" Initiated="true" DestinationHostname IN ["*dl.dropboxusercontent.com", "*.pastebin.com", "*.githubusercontent.com"] Image="C:\\Windows\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*true)(?=.*(?:.*.*dl\.dropboxusercontent\.com|.*.*\.pastebin\.com|.*.*\.githubusercontent\.com))(?=.*C:\Windows\\.*))'
```



