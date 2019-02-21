| Title                | MSHTA spwaned by SVCHOST as seen in LethalHTA                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects MSHTA.EXE spwaned by SVCHOST described in report                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://codewhitesec.blogspot.com/2018/07/lethalhta.html](https://codewhitesec.blogspot.com/2018/07/lethalhta.html)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: MSHTA spwaned by SVCHOST as seen in LethalHTA 
status: experimental
description: Detects MSHTA.EXE spwaned by SVCHOST described in report
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
author: Markus Neis
date: 2018/06/07
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage: '*\svchost.exe'
        Image: '*\mshta.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(EventID:"1" AND ParentImage.keyword:*\\\\svchost.exe AND Image.keyword:*\\\\mshta.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/MSHTA-spwaned-by-SVCHOST-as-seen-in-LethalHTA <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND ParentImage.keyword:*\\\\\\\\svchost.exe AND Image.keyword:*\\\\\\\\mshta.exe)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'MSHTA spwaned by SVCHOST as seen in LethalHTA\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"1" AND ParentImage:"*\\\\svchost.exe" AND Image:"*\\\\mshta.exe")
```


### splunk
    
```
(EventID="1" ParentImage="*\\\\svchost.exe" Image="*\\\\mshta.exe")
```


### logpoint
    
```
(EventID="1" ParentImage="*\\\\svchost.exe" Image="*\\\\mshta.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*1)(?=.*.*\\svchost\\.exe)(?=.*.*\\mshta\\.exe))'
```



