| Title                | Audio Capture via PowerShell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects audio capture via PowerShell Cmdlet                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1123: Audio Capture](https://attack.mitre.org/techniques/T1123)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1123: Audio Capture](../Triggers/T1123.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate audio capture by legitimate user</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html](https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html)</li></ul>  |
| Author               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Audio Capture via PowerShell
id: 932fb0d8-692b-4b0f-a26e-5643a50fe7d6
description: Detects audio capture via PowerShell Cmdlet
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html
tags:
    - attack.collection
    - attack.t1123
detection:
    selection:
        CommandLine|contains: 'WindowsAudioDevice-Powershell-Cmdlet'
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
CommandLine.keyword:*WindowsAudioDevice\\-Powershell\\-Cmdlet*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Audio-Capture-via-PowerShell <<EOF\n{\n  "metadata": {\n    "title": "Audio Capture via PowerShell",\n    "description": "Detects audio capture via PowerShell Cmdlet",\n    "tags": [\n      "attack.collection",\n      "attack.t1123"\n    ],\n    "query": "CommandLine.keyword:*WindowsAudioDevice\\\\-Powershell\\\\-Cmdlet*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:*WindowsAudioDevice\\\\-Powershell\\\\-Cmdlet*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Audio Capture via PowerShell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:*WindowsAudioDevice\\-Powershell\\-Cmdlet*
```


### splunk
    
```
CommandLine="*WindowsAudioDevice-Powershell-Cmdlet*"
```


### logpoint
    
```
(event_id="1" CommandLine="*WindowsAudioDevice-Powershell-Cmdlet*")
```


### grep
    
```
grep -P '^.*WindowsAudioDevice-Powershell-Cmdlet.*'
```



