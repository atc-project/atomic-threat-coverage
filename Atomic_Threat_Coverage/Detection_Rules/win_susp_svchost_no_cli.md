| Title                    | Suspect Svchost Activity       |
|:-------------------------|:------------------|
| **Description**          | It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space. |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>rpcnet.exe / rpcnetp.exe which is a lojack style software. https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2](https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2)</li></ul>  |
| **Author**               | David Burkett |


## Detection Rules

### Sigma rule

```
title: Suspect Svchost Activity
id: 16c37b52-b141-42a5-a3ea-bbe098444397
status: experimental
description: It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.
references:
    - https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2
author: David Burkett
date: 2019/12/28
tags:
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: null
    selection2:
        Image: '*\svchost.exe'
    filter:
        ParentImage:
            - '*\rpcnet.exe'
            - '*\rpcnetp.exe'
    condition: (selection1 and selection2) and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - rpcnet.exe / rpcnetp.exe which is a lojack style software. https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf
level: critical

```





### es-qs
    
```
((NOT _exists_:CommandLine AND Image.keyword:*\\\\svchost.exe) AND (NOT (ParentImage.keyword:(*\\\\rpcnet.exe OR *\\\\rpcnetp.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/16c37b52-b141-42a5-a3ea-bbe098444397 <<EOF\n{\n  "metadata": {\n    "title": "Suspect Svchost Activity",\n    "description": "It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.",\n    "tags": [\n      "attack.t1055"\n    ],\n    "query": "((NOT _exists_:CommandLine AND Image.keyword:*\\\\\\\\svchost.exe) AND (NOT (ParentImage.keyword:(*\\\\\\\\rpcnet.exe OR *\\\\\\\\rpcnetp.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((NOT _exists_:CommandLine AND Image.keyword:*\\\\\\\\svchost.exe) AND (NOT (ParentImage.keyword:(*\\\\\\\\rpcnet.exe OR *\\\\\\\\rpcnetp.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspect Svchost Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((NOT _exists_:CommandLine AND Image.keyword:*\\\\svchost.exe) AND (NOT (ParentImage.keyword:(*\\\\rpcnet.exe *\\\\rpcnetp.exe))))
```


### splunk
    
```
((NOT CommandLine="*" Image="*\\\\svchost.exe") NOT ((ParentImage="*\\\\rpcnet.exe" OR ParentImage="*\\\\rpcnetp.exe"))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" (event_id="1" -CommandLine=* Image="*\\\\svchost.exe")  -(ParentImage IN ["*\\\\rpcnet.exe", "*\\\\rpcnetp.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?!CommandLine))(?=.*.*\\svchost\\.exe)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\rpcnet\\.exe|.*.*\\rpcnetp\\.exe))))))'
```



