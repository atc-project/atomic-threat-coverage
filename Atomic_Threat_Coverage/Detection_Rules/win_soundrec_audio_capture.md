| Title                | Audio Capture via SoundRecorder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect attacker collecting audio via SoundRecorder application                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1123: Audio Capture](https://attack.mitre.org/techniques/T1123)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1123: Audio Capture](../Triggers/T1123.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate audio capture by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html](https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html)</li></ul>  |
| Author               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Audio Capture via SoundRecorder
id: 83865853-59aa-449e-9600-74b9d89a6d6e
description: Detect attacker collecting audio via SoundRecorder application
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html
tags:
    - attack.collection
    - attack.t1123
detection:
    selection:
        Image|endswith: '\SoundRecorder.exe'
        CommandLine|contains: '/FILE'
    condition: selection
falsepositives:
    - Legitimate audio capture by legitimate user
level: medium
logsource:
    category: process_creation
    product: windows

```





### es-qs
    
```
(Image.keyword:*\\\\SoundRecorder.exe AND CommandLine.keyword:*\\/FILE*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Audio-Capture-via-SoundRecorder <<EOF\n{\n  "metadata": {\n    "title": "Audio Capture via SoundRecorder",\n    "description": "Detect attacker collecting audio via SoundRecorder application",\n    "tags": [\n      "attack.collection",\n      "attack.t1123"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\SoundRecorder.exe AND CommandLine.keyword:*\\\\/FILE*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\SoundRecorder.exe AND CommandLine.keyword:*\\\\/FILE*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Audio Capture via SoundRecorder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\SoundRecorder.exe AND CommandLine.keyword:*\\/FILE*)
```


### splunk
    
```
(Image="*\\\\SoundRecorder.exe" CommandLine="*/FILE*")
```


### logpoint
    
```
(event_id="1" Image="*\\\\SoundRecorder.exe" CommandLine="*/FILE*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\SoundRecorder\\.exe)(?=.*.*/FILE.*))'
```



