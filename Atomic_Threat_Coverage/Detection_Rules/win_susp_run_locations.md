| Title                | Suspicious Process Start Locations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious process run from unusual locations                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-05-002](https://car.mitre.org/wiki/CAR-2013-05-002)</li></ul>                                                          |
| Author               | juju4                                                                                                                                                |


## Detection Rules

### Sigma rule

```
action: global
title: Suspicious Process Start Locations
description: Detects suspicious process run from unusual locations
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4
tags:
    - attack.defense_evasion
    - attack.t1036
detection:
    selection:
        CommandLine:
            - "*:\\RECYCLER\\*"
            - "*:\\SystemVolumeInformation\\*"
            - "%windir%\\Tasks\\*"
            - "%systemroot%\\debug\\*"
    condition: selection
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
---
# Windows Audit Log
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
---
# Sysmon
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1

```




### esqs
    
```
(EventID:"4688" AND CommandLine.keyword:(*\\:\\\\RECYCLER\\* *\\:\\\\SystemVolumeInformation\\* %windir%\\\\Tasks\\* %systemroot%\\\\debug\\*))\n(EventID:"1" AND CommandLine.keyword:(*\\:\\\\RECYCLER\\* *\\:\\\\SystemVolumeInformation\\* %windir%\\\\Tasks\\* %systemroot%\\\\debug\\*))
```


### xpackwatcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Process-Start-Locations <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine.keyword:(*\\\\:\\\\\\\\RECYCLER\\\\* *\\\\:\\\\\\\\SystemVolumeInformation\\\\* %windir%\\\\\\\\Tasks\\\\* %systemroot%\\\\\\\\debug\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Process Start Locations\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-Process-Start-Locations-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine.keyword:(*\\\\:\\\\\\\\RECYCLER\\\\* *\\\\:\\\\\\\\SystemVolumeInformation\\\\* %windir%\\\\\\\\Tasks\\\\* %systemroot%\\\\\\\\debug\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious Process Start Locations\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4688" AND CommandLine:("*\\:\\\\RECYCLER\\*" "*\\:\\\\SystemVolumeInformation\\*" "%windir%\\\\Tasks\\*" "%systemroot%\\\\debug\\*"))\n(EventID:"1" AND CommandLine:("*\\:\\\\RECYCLER\\*" "*\\:\\\\SystemVolumeInformation\\*" "%windir%\\\\Tasks\\*" "%systemroot%\\\\debug\\*"))
```


### splunk
    
```
(EventID="4688" (CommandLine="*:\\\\RECYCLER\\*" OR CommandLine="*:\\\\SystemVolumeInformation\\*" OR CommandLine="%windir%\\\\Tasks\\*" OR CommandLine="%systemroot%\\\\debug\\*"))\n(EventID="1" (CommandLine="*:\\\\RECYCLER\\*" OR CommandLine="*:\\\\SystemVolumeInformation\\*" OR CommandLine="%windir%\\\\Tasks\\*" OR CommandLine="%systemroot%\\\\debug\\*"))
```


### logpoint
    
```
(EventID="4688" CommandLine IN ["*:\\\\RECYCLER\\*", "*:\\\\SystemVolumeInformation\\*", "%windir%\\\\Tasks\\*", "%systemroot%\\\\debug\\*"])\n(EventID="1" CommandLine IN ["*:\\\\RECYCLER\\*", "*:\\\\SystemVolumeInformation\\*", "%windir%\\\\Tasks\\*", "%systemroot%\\\\debug\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4688)(?=.*(?:.*.*:\\RECYCLER\\.*|.*.*:\\SystemVolumeInformation\\.*|.*%windir%\\Tasks\\.*|.*%systemroot%\\debug\\.*)))'\ngrep -P '^(?:.*(?=.*1)(?=.*(?:.*.*:\\RECYCLER\\.*|.*.*:\\SystemVolumeInformation\\.*|.*%windir%\\Tasks\\.*|.*%systemroot%\\debug\\.*)))'
```


