| Title                | Suspicious access to sensitive file extensions                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects known sensitive file extensions                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Help Desk operator doing backup or re-imaging end user machine or pentest or backup software</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious access to sensitive file extensions
description: Detects known sensitive file extensions
author: Samir Bousseaden
tags:
    - attack.collection
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5145
        RelativeTargetName:
            - '*.pst'
            - '*.ost'
            - '*.msg'
            - '*.nst'
            - '*.oab'
            - '*.edb'
            - '*.nsf' 
            - '*.bak'
            - '*.dmp'
            - '*.kirbi'
            - '*\ntds.dit'
            - '*\groups.xml'
            - '*.rdp'
    condition: selection
falsepositives:
    - Help Desk operator doing backup or re-imaging end user machine or pentest or backup software
level: high

```





### es-qs
    
```
(EventID:("5145") AND RelativeTargetName.keyword:(*.pst *.ost *.msg *.nst *.oab *.edb *.nsf *.bak *.dmp *.kirbi *\\\\ntds.dit *\\\\groups.xml *.rdp))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Suspicious-access-to-sensitive-file-extensions <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:(\\"5145\\") AND RelativeTargetName.keyword:(*.pst *.ost *.msg *.nst *.oab *.edb *.nsf *.bak *.dmp *.kirbi *\\\\\\\\ntds.dit *\\\\\\\\groups.xml *.rdp))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Suspicious access to sensitive file extensions\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("5145") AND RelativeTargetName:("*.pst" "*.ost" "*.msg" "*.nst" "*.oab" "*.edb" "*.nsf" "*.bak" "*.dmp" "*.kirbi" "*\\\\ntds.dit" "*\\\\groups.xml" "*.rdp"))
```


### splunk
    
```
((EventID="5145") (RelativeTargetName="*.pst" OR RelativeTargetName="*.ost" OR RelativeTargetName="*.msg" OR RelativeTargetName="*.nst" OR RelativeTargetName="*.oab" OR RelativeTargetName="*.edb" OR RelativeTargetName="*.nsf" OR RelativeTargetName="*.bak" OR RelativeTargetName="*.dmp" OR RelativeTargetName="*.kirbi" OR RelativeTargetName="*\\\\ntds.dit" OR RelativeTargetName="*\\\\groups.xml" OR RelativeTargetName="*.rdp"))
```


### logpoint
    
```
(EventID IN ["5145"] RelativeTargetName IN ["*.pst", "*.ost", "*.msg", "*.nst", "*.oab", "*.edb", "*.nsf", "*.bak", "*.dmp", "*.kirbi", "*\\\\ntds.dit", "*\\\\groups.xml", "*.rdp"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*5145))(?=.*(?:.*.*\\.pst|.*.*\\.ost|.*.*\\.msg|.*.*\\.nst|.*.*\\.oab|.*.*\\.edb|.*.*\\.nsf|.*.*\\.bak|.*.*\\.dmp|.*.*\\.kirbi|.*.*\\ntds\\.dit|.*.*\\groups\\.xml|.*.*\\.rdp)))'
```



