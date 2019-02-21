| Title                | Microsoft Binary Github Communication                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an executable in the Windows folder accessing github.com                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li><li>@subTee in your network</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/M_haggis/status/900741347035889665](https://twitter.com/M_haggis/status/900741347035889665)</li><li>[https://twitter.com/M_haggis/status/1032799638213066752](https://twitter.com/M_haggis/status/1032799638213066752)</li></ul>                                                          |
| Author               | Michael Haag (idea), Florian Roth (rule)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Microsoft Binary Github Communication
status: experimental
description: Detects an executable in the Windows folder accessing github.com
references:
    - https://twitter.com/M_haggis/status/900741347035889665
    - https://twitter.com/M_haggis/status/1032799638213066752
author: Michael Haag (idea), Florian Roth (rule)
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationHostname: 
            - '*.github.com'
            - '*.githubusercontent.com'
        Image: 'C:\Windows\*'
    condition: selection
falsepositives:
    - 'Unknown'
    - '@subTee in your network'
level: high


```




### esqs
    
```
(EventID:"3" AND DestinationHostname.keyword:(*.github.com *.githubusercontent.com) AND Image:"C\\:\\\\Windows\\*")
```


### xpackwatcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Microsoft-Binary-Github-Communication <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"3\\" AND DestinationHostname.keyword:(*.github.com *.githubusercontent.com) AND Image:\\"C\\\\:\\\\\\\\Windows\\\\*\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Microsoft Binary Github Communication\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"3" AND DestinationHostname:("*.github.com" "*.githubusercontent.com") AND Image:"C\\:\\\\Windows\\*")
```


### splunk
    
```
(EventID="3" (DestinationHostname="*.github.com" OR DestinationHostname="*.githubusercontent.com") Image="C:\\\\Windows\\*")
```


### logpoint
    
```
(EventID="3" DestinationHostname IN ["*.github.com", "*.githubusercontent.com"] Image="C:\\\\Windows\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*3)(?=.*(?:.*.*\\.github\\.com|.*.*\\.githubusercontent\\.com))(?=.*C:\\Windows\\.*))'
```


