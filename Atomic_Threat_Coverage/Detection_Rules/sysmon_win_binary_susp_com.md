| Title                    | Microsoft Binary Suspicious Communication Endpoint       |
|:-------------------------|:------------------|
| **Description**          | Detects an executable in the Windows folder accessing suspicious domains |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1105: Remote File Copy](../Triggers/T1105.md)</li></ul>  |
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
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Initiated.*true" -and ($_.message -match "DestinationHostname.*.*dl.dropboxusercontent.com" -or $_.message -match "DestinationHostname.*.*.pastebin.com" -or $_.message -match "DestinationHostname.*.*.githubusercontent.com") -and $_.message -match "Image.*C:\\\\Windows\\\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"3" AND Initiated:"true" AND winlog.event_data.DestinationHostname.keyword:(*dl.dropboxusercontent.com OR *.pastebin.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\\:\\\\Windows\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97 <<EOF\n{\n  "metadata": {\n    "title": "Microsoft Binary Suspicious Communication Endpoint",\n    "description": "Detects an executable in the Windows folder accessing suspicious domains",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1105"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"3\\" AND Initiated:\\"true\\" AND winlog.event_data.DestinationHostname.keyword:(*dl.dropboxusercontent.com OR *.pastebin.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\\\\:\\\\\\\\Windows\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"3\\" AND Initiated:\\"true\\" AND winlog.event_data.DestinationHostname.keyword:(*dl.dropboxusercontent.com OR *.pastebin.com OR *.githubusercontent.com) AND winlog.event_data.Image.keyword:C\\\\:\\\\\\\\Windows\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Microsoft Binary Suspicious Communication Endpoint\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"3" AND Initiated:"true" AND DestinationHostname.keyword:(*dl.dropboxusercontent.com *.pastebin.com *.githubusercontent.com) AND Image.keyword:C\\:\\\\Windows\\\\*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="3" Initiated="true" (DestinationHostname="*dl.dropboxusercontent.com" OR DestinationHostname="*.pastebin.com" OR DestinationHostname="*.githubusercontent.com") Image="C:\\\\Windows\\\\*")
```


### logpoint
    
```
(event_id="3" Initiated="true" DestinationHostname IN ["*dl.dropboxusercontent.com", "*.pastebin.com", "*.githubusercontent.com"] Image="C:\\\\Windows\\\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*true)(?=.*(?:.*.*dl\\.dropboxusercontent\\.com|.*.*\\.pastebin\\.com|.*.*\\.githubusercontent\\.com))(?=.*C:\\Windows\\\\.*))'
```



