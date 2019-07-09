| Title                | Possible Process Hollowing Image Loading                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Very likely, needs more tuning</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html)</li></ul>  |
| Author               | Markus Neis |


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
tags:
    - attack.defense_evasion
    - attack.t1073
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





### es-qs
    
```
(EventID:"7" AND Image.keyword:(*\\\\notepad.exe) AND ImageLoaded.keyword:(*\\\\samlib.dll *\\\\WinSCard.dll))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Possible-Process-Hollowing-Image-Loading <<EOF\n{\n  "metadata": {\n    "title": "Possible Process Hollowing Image Loading",\n    "description": "Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1073"\n    ],\n    "query": "(EventID:\\"7\\" AND Image.keyword:(*\\\\\\\\notepad.exe) AND ImageLoaded.keyword:(*\\\\\\\\samlib.dll *\\\\\\\\WinSCard.dll))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7\\" AND Image.keyword:(*\\\\\\\\notepad.exe) AND ImageLoaded.keyword:(*\\\\\\\\samlib.dll *\\\\\\\\WinSCard.dll))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Possible Process Hollowing Image Loading\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7" AND Image:("*\\\\notepad.exe") AND ImageLoaded:("*\\\\samlib.dll" "*\\\\WinSCard.dll"))
```


### splunk
    
```
(EventID="7" (Image="*\\\\notepad.exe") (ImageLoaded="*\\\\samlib.dll" OR ImageLoaded="*\\\\WinSCard.dll"))
```


### logpoint
    
```
(EventID="7" Image IN ["*\\\\notepad.exe"] ImageLoaded IN ["*\\\\samlib.dll", "*\\\\WinSCard.dll"])
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*(?:.*.*\\notepad\\.exe))(?=.*(?:.*.*\\samlib\\.dll|.*.*\\WinSCard\\.dll)))'
```



