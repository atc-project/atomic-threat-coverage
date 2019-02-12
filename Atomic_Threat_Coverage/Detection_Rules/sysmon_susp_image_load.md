| Title                | Possible Process Hollowing Image Loading                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Very likely, needs more tuning</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Possible Process Hollowing Image Loading 
status: experimental
description: Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz
references:
    - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html
author: Markus Neis
date: 2018/01/07
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image:
            - '*\notepad.exe'
        ImageLoaded:
            - '*\samlib.dll'
            - '*\WinSCard.dll'
    condition: selection
falsepositives:
    - Very likely, needs more tuning
level: high

```





### Kibana query

```
(EventID:"7" AND Image:("*\\\\notepad.exe") AND ImageLoaded:("*\\\\samlib.dll" "*\\\\WinSCard.dll"))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Process-Hollowing-Image-Loading <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"7\\" AND Image:(\\"*\\\\\\\\notepad.exe\\") AND ImageLoaded:(\\"*\\\\\\\\samlib.dll\\" \\"*\\\\\\\\WinSCard.dll\\"))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Process Hollowing Image Loading\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"7" AND Image:("*\\\\notepad.exe") AND ImageLoaded:("*\\\\samlib.dll" "*\\\\WinSCard.dll"))
```

