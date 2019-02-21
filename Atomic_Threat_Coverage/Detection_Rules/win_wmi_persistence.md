| Title                | WMI Persistence                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0081_5861_wmi_activity](../Data_Needed/DN_0081_5861_wmi_activity.md)</li><li>[DN_0080_5859_wmi_activity](../Data_Needed/DN_0080_5859_wmi_activity.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown (data set is too small; further testing needed)</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/mattifestation/status/899646620148539397](https://twitter.com/mattifestation/status/899646620148539397)</li><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: WMI Persistence
status: experimental
description: Detects suspicious WMI event filter and command line event consumer based on event id 5861 and 5859 (Windows 10, 2012 and higher)
author: Florian Roth
references:
    - https://twitter.com/mattifestation/status/899646620148539397
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
tags:
    - attack.execution
    - attack.persistence
    - attack.t1047
logsource:
    product: windows
    service: wmi
detection:
    selection:
        EventID: 5861
    keywords:
        - 'ActiveScriptEventConsumer'
        - 'CommandLineEventConsumer'
        - 'CommandLineTemplate'
        - 'Binding EventFilter'
    selection2:
        EventID: 5859
    condition: selection and 1 of keywords or selection2
falsepositives:
    - Unknown (data set is too small; further testing needed)
level: high


```




### es-qs
    
```
((EventID:"5861" AND ("ActiveScriptEventConsumer" OR "CommandLineEventConsumer" OR "CommandLineTemplate" OR "Binding\\ EventFilter")) OR EventID:"5859")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/WMI-Persistence <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"5861\\" AND (\\"ActiveScriptEventConsumer\\" OR \\"CommandLineEventConsumer\\" OR \\"CommandLineTemplate\\" OR \\"Binding\\\\ EventFilter\\")) OR EventID:\\"5859\\")",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'WMI Persistence\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"5861" AND ("ActiveScriptEventConsumer" OR "CommandLineEventConsumer" OR "CommandLineTemplate" OR "Binding EventFilter")) OR EventID:"5859")
```


### splunk
    
```
((EventID="5861" ("ActiveScriptEventConsumer" OR "CommandLineEventConsumer" OR "CommandLineTemplate" OR "Binding EventFilter")) OR EventID="5859")
```


### logpoint
    
```
((EventID="5861" ("ActiveScriptEventConsumer" OR "CommandLineEventConsumer" OR "CommandLineTemplate" OR "Binding EventFilter")) OR EventID="5859")
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*5861)(?=.*(?:.*(?:.*ActiveScriptEventConsumer|.*CommandLineEventConsumer|.*CommandLineTemplate|.*Binding EventFilter))))|.*5859))'
```


