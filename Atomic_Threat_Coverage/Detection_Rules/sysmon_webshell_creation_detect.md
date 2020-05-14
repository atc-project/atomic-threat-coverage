| Title                    | Windows Webshell Creation       |
|:-------------------------|:------------------|
| **Description**          | Possible webshell file creation on a static web site |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate administrator or developer creating legitimate executable files in a web application folder</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[PT ESC rule and personal experience](PT ESC rule and personal experience)</li></ul>  |
| **Author**               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Windows Webshell Creation
id: 39f1f9f2-9636-45de-98f6-a4046aa8e4b9
status: experimental
description: Possible webshell file creation on a static web site
references:
    - PT ESC rule and personal experience
author: Beyu Denis, oscd.community
date: 2019/10/22
modified: 2019/11/04
tags:
    - attack.persistence
    - attack.t1100
level: critical
logsource:
    product: windows
    service: sysmon
detection:
    selection_1:
        EventID: 11
    selection_2:
        TargetFilename|contains: '\inetpub\wwwroot\'
    selection_3:
        TargetFilename|contains:
            - '.asp'
            - '.ashx'
            - '.ph'
    selection_4:
        TargetFilename|contains:
            - '\www\'
            - '\htdocs\'
            - '\html\'
    selection_5:
        TargetFilename|contains: '.ph'
    selection_6:
        - TargetFilename|endswith: '.jsp'
        - TargetFilename|contains|all:
            - '\cgi-bin\'
            - '.pl'
    condition: selection_1 and ( selection_2 and selection_3 ) or
               selection_1 and ( selection_4 and selection_5 ) or
               selection_1 and selection_6
falsepositives:
    - Legitimate administrator or developer creating legitimate executable files in a web application folder

```





### es-qs
    
```
(EventID:"11" AND ((TargetFilename.keyword:*\\\\inetpub\\\\wwwroot\\\\* AND TargetFilename.keyword:(*.asp* OR *.ashx* OR *.ph*)) OR (TargetFilename.keyword:(*\\\\www\\\\* OR *\\\\htdocs\\\\* OR *\\\\html\\\\*) AND TargetFilename.keyword:*.ph*) OR TargetFilename.keyword:*.jsp OR (TargetFilename.keyword:*\\\\cgi\\-bin\\\\* AND TargetFilename.keyword:*.pl*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/39f1f9f2-9636-45de-98f6-a4046aa8e4b9 <<EOF\n{\n  "metadata": {\n    "title": "Windows Webshell Creation",\n    "description": "Possible webshell file creation on a static web site",\n    "tags": [\n      "attack.persistence",\n      "attack.t1100"\n    ],\n    "query": "(EventID:\\"11\\" AND ((TargetFilename.keyword:*\\\\\\\\inetpub\\\\\\\\wwwroot\\\\\\\\* AND TargetFilename.keyword:(*.asp* OR *.ashx* OR *.ph*)) OR (TargetFilename.keyword:(*\\\\\\\\www\\\\\\\\* OR *\\\\\\\\htdocs\\\\\\\\* OR *\\\\\\\\html\\\\\\\\*) AND TargetFilename.keyword:*.ph*) OR TargetFilename.keyword:*.jsp OR (TargetFilename.keyword:*\\\\\\\\cgi\\\\-bin\\\\\\\\* AND TargetFilename.keyword:*.pl*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"11\\" AND ((TargetFilename.keyword:*\\\\\\\\inetpub\\\\\\\\wwwroot\\\\\\\\* AND TargetFilename.keyword:(*.asp* OR *.ashx* OR *.ph*)) OR (TargetFilename.keyword:(*\\\\\\\\www\\\\\\\\* OR *\\\\\\\\htdocs\\\\\\\\* OR *\\\\\\\\html\\\\\\\\*) AND TargetFilename.keyword:*.ph*) OR TargetFilename.keyword:*.jsp OR (TargetFilename.keyword:*\\\\\\\\cgi\\\\-bin\\\\\\\\* AND TargetFilename.keyword:*.pl*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows Webshell Creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"11" AND ((TargetFilename.keyword:*\\\\inetpub\\\\wwwroot\\\\* AND TargetFilename.keyword:(*.asp* *.ashx* *.ph*)) OR (TargetFilename.keyword:(*\\\\www\\\\* *\\\\htdocs\\\\* *\\\\html\\\\*) AND TargetFilename.keyword:*.ph*) OR TargetFilename.keyword:*.jsp OR (TargetFilename.keyword:*\\\\cgi\\-bin\\\\* AND TargetFilename.keyword:*.pl*)))
```


### splunk
    
```
(EventID="11" ((TargetFilename="*\\\\inetpub\\\\wwwroot\\\\*" (TargetFilename="*.asp*" OR TargetFilename="*.ashx*" OR TargetFilename="*.ph*")) OR ((TargetFilename="*\\\\www\\\\*" OR TargetFilename="*\\\\htdocs\\\\*" OR TargetFilename="*\\\\html\\\\*") TargetFilename="*.ph*") OR TargetFilename="*.jsp" OR (TargetFilename="*\\\\cgi-bin\\\\*" TargetFilename="*.pl*")))
```


### logpoint
    
```
(event_id="11" ((TargetFilename="*\\\\inetpub\\\\wwwroot\\\\*" TargetFilename IN ["*.asp*", "*.ashx*", "*.ph*"]) OR (TargetFilename IN ["*\\\\www\\\\*", "*\\\\htdocs\\\\*", "*\\\\html\\\\*"] TargetFilename="*.ph*") OR TargetFilename="*.jsp" OR (TargetFilename="*\\\\cgi-bin\\\\*" TargetFilename="*.pl*")))
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*(?:.*(?:.*(?:.*(?=.*.*\\inetpub\\wwwroot\\\\.*)(?=.*(?:.*.*\\.asp.*|.*.*\\.ashx.*|.*.*\\.ph.*)))|.*(?:.*(?=.*(?:.*.*\\www\\\\.*|.*.*\\htdocs\\\\.*|.*.*\\html\\\\.*))(?=.*.*\\.ph.*))|.*.*\\.jsp|.*(?:.*(?=.*.*\\cgi-bin\\\\.*)(?=.*.*\\.pl.*))))))'
```



