| Title                | Microsoft Binary Suspicious Communication Endpoint                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an executable in the Windows folder accessing suspicious domains                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/M_haggis/status/900741347035889665](https://twitter.com/M_haggis/status/900741347035889665)</li><li>[https://twitter.com/M_haggis/status/1032799638213066752](https://twitter.com/M_haggis/status/1032799638213066752)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Microsoft Binary Suspicious Communication Endpoint
status: experimental
description: Detects an executable in the Windows folder accessing suspicious domains
references:
    - https://twitter.com/M_haggis/status/900741347035889665
    - https://twitter.com/M_haggis/status/1032799638213066752
author: Florian Roth
date: 2018/08/30
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationHostname: 
            - '*dl.dropboxusercontent.com'
            - '*.pastebin.com'
        Image: 'C:\Windows\*'
    condition: selection
falsepositives:
    - 'Unknown'
level: high


```





### Kibana query

```
(EventID:"3" AND DestinationHostname:("*dl.dropboxusercontent.com" "*.pastebin.com") AND Image:"C\\:\\\\Windows\\*")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Microsoft-Binary-Suspicious-Communication-Endpoint <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"3\\" AND DestinationHostname:(\\"*dl.dropboxusercontent.com\\" \\"*.pastebin.com\\") AND Image:\\"C\\\\:\\\\\\\\Windows\\\\*\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Microsoft Binary Suspicious Communication Endpoint\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"3" AND DestinationHostname:("*dl.dropboxusercontent.com" "*.pastebin.com") AND Image:"C\\:\\\\Windows\\*")
```

