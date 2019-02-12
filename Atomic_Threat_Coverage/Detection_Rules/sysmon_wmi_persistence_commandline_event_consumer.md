| Title                | WMI Persistence - Command Line Event Consumer                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI command line event consumers                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1084](https://attack.mitre.org/tactics/T1084)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1084](../Triggers/T1084.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown (data set is too small; further testing needed)</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: WMI Persistence - Command Line Event Consumer
status: experimental
description: Detects WMI command line event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
tags:
    - attack.t1084
    - attack.persistence
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image: 'C:\Windows\System32\wbem\WmiPrvSE.exe'
        ImageLoaded: 'wbemcons.dll'
    condition: selection
falsepositives: 
    - Unknown (data set is too small; further testing needed)
level: high

```





### Kibana query

```
(EventID:"7" AND Image:"C\\:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe" AND ImageLoaded:"wbemcons.dll")
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/WMI-Persistence---Command-Line-Event-Consumer <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"7\\" AND Image:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\wbem\\\\\\\\WmiPrvSE.exe\\" AND ImageLoaded:\\"wbemcons.dll\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'WMI Persistence - Command Line Event Consumer\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"7" AND Image:"C\\:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe" AND ImageLoaded:"wbemcons.dll")
```

