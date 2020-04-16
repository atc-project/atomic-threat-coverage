| Title                    | Suspicious desktop.ini Action       |
|:-------------------------|:------------------|
| **Description**          | Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1023: Shortcut Modification](https://attack.mitre.org/techniques/T1023)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1023: Shortcut Modification](../Triggers/T1023.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Operations performed through Windows SCCM or equivalent</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/](https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/)</li></ul>  |
| **Author**               | Maxime Thiebaut (@0xThiebaut) |


## Detection Rules

### Sigma rule

```
title: Suspicious desktop.ini Action
id: 81315b50-6b60-4d8f-9928-3466e1022515
status: experimental
description: Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
references:
    - https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/
author: Maxime Thiebaut (@0xThiebaut)
date: 2020/03/19
tags:
    - attack.persistence
    - attack.t1023
logsource:
    product: windows
    service: sysmon
detection:
    filter:
        Image:
            - 'C:\Windows\explorer.exe'
            - 'C:\Windows\System32\msiexec.exe'
            - 'C:\Windows\System32\mmc.exe'
    selection:
        EventID: 11
        TargetFilename|endswith: '\desktop.ini'
    condition: selection and not filter
falsepositives:
    - Operations performed through Windows SCCM or equivalent
level: medium

```





### es-qs
    
```
((EventID:"11" AND TargetFilename.keyword:*\\\\desktop.ini) AND (NOT (Image:("C\\:\\\\Windows\\\\explorer.exe" OR "C\\:\\\\Windows\\\\System32\\\\msiexec.exe" OR "C\\:\\\\Windows\\\\System32\\\\mmc.exe"))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/81315b50-6b60-4d8f-9928-3466e1022515 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious desktop.ini Action",\n    "description": "Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder\'s content (i.e. renaming files) without changing them on disk.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1023"\n    ],\n    "query": "((EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\desktop.ini) AND (NOT (Image:(\\"C\\\\:\\\\\\\\Windows\\\\\\\\explorer.exe\\" OR \\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\msiexec.exe\\" OR \\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\mmc.exe\\"))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"11\\" AND TargetFilename.keyword:*\\\\\\\\desktop.ini) AND (NOT (Image:(\\"C\\\\:\\\\\\\\Windows\\\\\\\\explorer.exe\\" OR \\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\msiexec.exe\\" OR \\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\mmc.exe\\"))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious desktop.ini Action\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"11" AND TargetFilename.keyword:*\\\\desktop.ini) AND (NOT (Image:("C\\:\\\\Windows\\\\explorer.exe" "C\\:\\\\Windows\\\\System32\\\\msiexec.exe" "C\\:\\\\Windows\\\\System32\\\\mmc.exe"))))
```


### splunk
    
```
((EventID="11" TargetFilename="*\\\\desktop.ini") NOT ((Image="C:\\\\Windows\\\\explorer.exe" OR Image="C:\\\\Windows\\\\System32\\\\msiexec.exe" OR Image="C:\\\\Windows\\\\System32\\\\mmc.exe")))
```


### logpoint
    
```
((event_id="11" TargetFilename="*\\\\desktop.ini")  -(Image IN ["C:\\\\Windows\\\\explorer.exe", "C:\\\\Windows\\\\System32\\\\msiexec.exe", "C:\\\\Windows\\\\System32\\\\mmc.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*11)(?=.*.*\\desktop\\.ini)))(?=.*(?!.*(?:.*(?=.*(?:.*C:\\Windows\\explorer\\.exe|.*C:\\Windows\\System32\\msiexec\\.exe|.*C:\\Windows\\System32\\mmc\\.exe))))))'
```



