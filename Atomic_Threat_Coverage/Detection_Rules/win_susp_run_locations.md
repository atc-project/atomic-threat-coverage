| Title                | Suspicious Process Start Locations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process run from unusual locations                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-05-002](https://car.mitre.org/wiki/CAR-2013-05-002)</li></ul>  |
| Author               | juju4 |
| Other Tags           | <ul><li>car.2013-05-002</li><li>car.2013-05-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Process Start Locations
description: Detects suspicious process run from unusual locations
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4
tags:
    - attack.defense_evasion
    - attack.t1036
    - car.2013-05-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*:\RECYCLER\\*'
            - '*:\SystemVolumeInformation\\*'
            - 'C:\\Windows\\Tasks\\*'
            - 'C:\\Windows\\debug\\*'
            - 'C:\\Windows\\fonts\\*'
            - 'C:\\Windows\\help\\*'
            - 'C:\\Windows\\drivers\\*'
            - 'C:\\Windows\\addins\\*'
            - 'C:\\Windows\\cursors\\*'
            - 'C:\\Windows\\system32\tasks\\*'
            
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### es-qs
    
```
Image.keyword:(*\\:\\\\RECYCLER\\\\* *\\:\\\\SystemVolumeInformation\\\\* C\\:\\\\Windows\\\\Tasks\\\\* C\\:\\\\Windows\\\\debug\\\\* C\\:\\\\Windows\\\\fonts\\\\* C\\:\\\\Windows\\\\help\\\\* C\\:\\\\Windows\\\\drivers\\\\* C\\:\\\\Windows\\\\addins\\\\* C\\:\\\\Windows\\\\cursors\\\\* C\\:\\\\Windows\\\\system32\\\\tasks\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Process-Start-Locations <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Process Start Locations",\n    "description": "Detects suspicious process run from unusual locations",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036",\n      "car.2013-05-002"\n    ],\n    "query": "Image.keyword:(*\\\\:\\\\\\\\RECYCLER\\\\\\\\* *\\\\:\\\\\\\\SystemVolumeInformation\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\Tasks\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\debug\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\fonts\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\help\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\drivers\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\addins\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\cursors\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\tasks\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "Image.keyword:(*\\\\:\\\\\\\\RECYCLER\\\\\\\\* *\\\\:\\\\\\\\SystemVolumeInformation\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\Tasks\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\debug\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\fonts\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\help\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\drivers\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\addins\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\cursors\\\\\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\tasks\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Process Start Locations\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Image:("*\\:\\\\RECYCLER\\\\*" "*\\:\\\\SystemVolumeInformation\\\\*" "C\\:\\\\Windows\\\\Tasks\\\\*" "C\\:\\\\Windows\\\\debug\\\\*" "C\\:\\\\Windows\\\\fonts\\\\*" "C\\:\\\\Windows\\\\help\\\\*" "C\\:\\\\Windows\\\\drivers\\\\*" "C\\:\\\\Windows\\\\addins\\\\*" "C\\:\\\\Windows\\\\cursors\\\\*" "C\\:\\\\Windows\\\\system32\\\\tasks\\\\*")
```


### splunk
    
```
(Image="*:\\\\RECYCLER\\\\*" OR Image="*:\\\\SystemVolumeInformation\\\\*" OR Image="C:\\\\Windows\\\\Tasks\\\\*" OR Image="C:\\\\Windows\\\\debug\\\\*" OR Image="C:\\\\Windows\\\\fonts\\\\*" OR Image="C:\\\\Windows\\\\help\\\\*" OR Image="C:\\\\Windows\\\\drivers\\\\*" OR Image="C:\\\\Windows\\\\addins\\\\*" OR Image="C:\\\\Windows\\\\cursors\\\\*" OR Image="C:\\\\Windows\\\\system32\\\\tasks\\\\*")
```


### logpoint
    
```
Image IN ["*:\\\\RECYCLER\\\\*", "*:\\\\SystemVolumeInformation\\\\*", "C:\\\\Windows\\\\Tasks\\\\*", "C:\\\\Windows\\\\debug\\\\*", "C:\\\\Windows\\\\fonts\\\\*", "C:\\\\Windows\\\\help\\\\*", "C:\\\\Windows\\\\drivers\\\\*", "C:\\\\Windows\\\\addins\\\\*", "C:\\\\Windows\\\\cursors\\\\*", "C:\\\\Windows\\\\system32\\\\tasks\\\\*"]
```


### grep
    
```
grep -P '^(?:.*.*:\\RECYCLER\\\\.*|.*.*:\\SystemVolumeInformation\\\\.*|.*C:\\\\Windows\\\\Tasks\\\\.*|.*C:\\\\Windows\\\\debug\\\\.*|.*C:\\\\Windows\\\\fonts\\\\.*|.*C:\\\\Windows\\\\help\\\\.*|.*C:\\\\Windows\\\\drivers\\\\.*|.*C:\\\\Windows\\\\addins\\\\.*|.*C:\\\\Windows\\\\cursors\\\\.*|.*C:\\\\Windows\\\\system32\\tasks\\\\.*)'
```



