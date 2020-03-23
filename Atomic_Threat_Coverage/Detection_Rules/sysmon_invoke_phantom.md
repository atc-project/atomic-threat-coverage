| Title                | Suspect Svchost Memory Asccess                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| Data Needed          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>  |
| Trigger              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/hlldz/Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)</li><li>[https://twitter.com/timbmsft/status/900724491076214784](https://twitter.com/timbmsft/status/900724491076214784)</li></ul>  |
| Author               | Tim Burrell |


## Detection Rules

### Sigma rule

```
title: Suspect Svchost Memory Asccess
id: 166e9c50-8cd9-44af-815d-d1f0c0e90dde
status: experimental
description: Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.
author: Tim Burrell
date: 2020/01/02
references:
    - https://github.com/hlldz/Invoke-Phant0m
    - https://twitter.com/timbmsft/status/900724491076214784
tags:
    - attack.t1089
    - attack.defense_evasion
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage: '*\windows\system32\svchost.exe'
        GrantedAccess: '0x1f3fff'
        CallTrace:
         - '*unknown*'
    condition: selection
falsepositives:
    - unknown
level: high

```





### es-qs
    
```
(EventID:"10" AND TargetImage.keyword:*\\\\windows\\\\system32\\\\svchost.exe AND GrantedAccess:"0x1f3fff" AND CallTrace.keyword:(*unknown*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/166e9c50-8cd9-44af-815d-d1f0c0e90dde <<EOF\n{\n  "metadata": {\n    "title": "Suspect Svchost Memory Asccess",\n    "description": "Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.",\n    "tags": [\n      "attack.t1089",\n      "attack.defense_evasion"\n    ],\n    "query": "(EventID:\\"10\\" AND TargetImage.keyword:*\\\\\\\\windows\\\\\\\\system32\\\\\\\\svchost.exe AND GrantedAccess:\\"0x1f3fff\\" AND CallTrace.keyword:(*unknown*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"10\\" AND TargetImage.keyword:*\\\\\\\\windows\\\\\\\\system32\\\\\\\\svchost.exe AND GrantedAccess:\\"0x1f3fff\\" AND CallTrace.keyword:(*unknown*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspect Svchost Memory Asccess\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"10" AND TargetImage.keyword:*\\\\windows\\\\system32\\\\svchost.exe AND GrantedAccess:"0x1f3fff" AND CallTrace.keyword:(*unknown*))
```


### splunk
    
```
(EventID="10" TargetImage="*\\\\windows\\\\system32\\\\svchost.exe" GrantedAccess="0x1f3fff" (CallTrace="*unknown*"))
```


### logpoint
    
```
(event_id="10" TargetImage="*\\\\windows\\\\system32\\\\svchost.exe" GrantedAccess="0x1f3fff" CallTrace IN ["*unknown*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*10)(?=.*.*\\windows\\system32\\svchost\\.exe)(?=.*0x1f3fff)(?=.*(?:.*.*unknown.*)))'
```



