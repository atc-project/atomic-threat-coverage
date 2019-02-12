| Title                | Secure Deletion with SDelete                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects renaming of file while deletion with SDelete tool                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1107: File Deletion](https://attack.mitre.org/tactics/T1107)</li><li>[T1116: Code Signing](https://attack.mitre.org/tactics/T1116)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[('File Deletion', 'T1107')](../Triggers/('File Deletion', 'T1107').md)</li><li>[('Code Signing', 'T1116')](../Triggers/('Code Signing', 'T1116').md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Legitime usage of SDelete</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx](https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |
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
    - attack.t1116
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





### Kibana query

```
(EventID:("4656" "4663" "4658") AND ObjectName.keyword:(*.AAA *.ZZZ))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Secure-Deletion-with-SDelete <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:(\\"4656\\" \\"4663\\" \\"4658\\") AND ObjectName.keyword:(*.AAA *.ZZZ))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Secure Deletion with SDelete\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:("4656" "4663" "4658") AND ObjectName:("*.AAA" "*.ZZZ"))
```

