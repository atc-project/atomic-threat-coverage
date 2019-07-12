| Title                | Secure Deletion with SDelete                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects renaming of file while deletion with SDelete tool                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1107: File Deletion](https://attack.mitre.org/techniques/T1107)</li><li>[T1066: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1066)</li></ul>  |
| Data Needed          | <ul><li>[DN_0060_4658_handle_to_an_object_was_closed](../Data_Needed/DN_0060_4658_handle_to_an_object_was_closed.md)</li><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1107: File Deletion](../Triggers/T1107.md)</li><li>[T1066: Indicator Removal from Tools](../Triggers/T1066.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitime usage of SDelete</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx](https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx)</li></ul>  |
| Author               | Thomas Patzke |
| Other Tags           | <ul><li>attack.s0195</li><li>attack.s0195</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Secure Deletion with SDelete
status: experimental
description: Detects renaming of file while deletion with SDelete tool
author: Thomas Patzke
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx
tags:
    - attack.defense_evasion
    - attack.t1107
    - attack.t1066
    - attack.s0195
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
            - 4658
        ObjectName:
            - '*.AAA'
            - '*.ZZZ'
    condition: selection
falsepositives:
    - Legitime usage of SDelete
level: medium

```





### es-qs
    
```
(EventID:("4656" "4663" "4658") AND ObjectName.keyword:(*.AAA *.ZZZ))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Secure-Deletion-with-SDelete <<EOF\n{\n  "metadata": {\n    "title": "Secure Deletion with SDelete",\n    "description": "Detects renaming of file while deletion with SDelete tool",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1107",\n      "attack.t1066",\n      "attack.s0195"\n    ],\n    "query": "(EventID:(\\"4656\\" \\"4663\\" \\"4658\\") AND ObjectName.keyword:(*.AAA *.ZZZ))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"4656\\" \\"4663\\" \\"4658\\") AND ObjectName.keyword:(*.AAA *.ZZZ))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Secure Deletion with SDelete\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4656" "4663" "4658") AND ObjectName:("*.AAA" "*.ZZZ"))
```


### splunk
    
```
((EventID="4656" OR EventID="4663" OR EventID="4658") (ObjectName="*.AAA" OR ObjectName="*.ZZZ"))
```


### logpoint
    
```
(EventID IN ["4656", "4663", "4658"] ObjectName IN ["*.AAA", "*.ZZZ"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4656|.*4663|.*4658))(?=.*(?:.*.*\\.AAA|.*.*\\.ZZZ)))'
```



