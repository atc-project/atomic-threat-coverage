| Title                    | Unsigned Image Loaded Into LSASS Process       |
|:-------------------------|:------------------|
| **Description**          | Loading unsigned image (DLL, EXE) into LSASS process |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Valid user connecting using RDP</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Unsigned Image Loaded Into LSASS Process
id: 857c8db3-c89b-42fb-882b-f681c7cf4da2
description: Loading unsigned image (DLL, EXE) into LSASS process
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
modified: 2019/11/13
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image|endswith: '\lsass.exe'
        Signed: 'false'
    condition: selection
falsepositives:
    - Valid user connecting using RDP
status: experimental
level: medium

```





### es-qs
    
```
(EventID:"7" AND Image.keyword:*\\\\lsass.exe AND Signed:"false")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/857c8db3-c89b-42fb-882b-f681c7cf4da2 <<EOF\n{\n  "metadata": {\n    "title": "Unsigned Image Loaded Into LSASS Process",\n    "description": "Loading unsigned image (DLL, EXE) into LSASS process",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(EventID:\\"7\\" AND Image.keyword:*\\\\\\\\lsass.exe AND Signed:\\"false\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7\\" AND Image.keyword:*\\\\\\\\lsass.exe AND Signed:\\"false\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Unsigned Image Loaded Into LSASS Process\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7" AND Image.keyword:*\\\\lsass.exe AND Signed:"false")
```


### splunk
    
```
(EventID="7" Image="*\\\\lsass.exe" Signed="false")
```


### logpoint
    
```
(event_id="7" Image="*\\\\lsass.exe" Signed="false")
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*.*\\lsass\\.exe)(?=.*false))'
```



