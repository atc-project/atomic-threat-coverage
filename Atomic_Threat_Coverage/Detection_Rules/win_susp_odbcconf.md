| Title                    | Application Whitelisting Bypass via DLL Loaded by odbcconf.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects defence evasion attempt via odbcconf.exe execution to load DLL |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate use of odbcconf.exe by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml)</li><li>[https://twitter.com/Hexacorn/status/1187143326673330176](https://twitter.com/Hexacorn/status/1187143326673330176)</li></ul>  |
| **Author**               | Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application Whitelisting Bypass via DLL Loaded by odbcconf.exe
id: 65d2be45-8600-4042-b4c0-577a1ff8a60e
description: Detects defence evasion attempt via odbcconf.exe execution to load DLL
status: experimental
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Odbcconf.yml
    - https://twitter.com/Hexacorn/status/1187143326673330176
author: Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community
date: 2019/10/25
modified: 2019/11/07
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\odbcconf.exe'
        CommandLine|contains:
            - '-f'
            - 'regsvr'
    selection_2:
        ParentImage|endswith: '\odbcconf.exe'
        Image|endswith: '\rundll32.exe'
    condition: selection_1 or selection_2
level: medium
falsepositives:
    - Legitimate use of odbcconf.exe by legitimate user

```





### es-qs
    
```
((Image.keyword:*\\\\odbcconf.exe AND CommandLine.keyword:(*\\-f* OR *regsvr*)) OR (ParentImage.keyword:*\\\\odbcconf.exe AND Image.keyword:*\\\\rundll32.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/65d2be45-8600-4042-b4c0-577a1ff8a60e <<EOF\n{\n  "metadata": {\n    "title": "Application Whitelisting Bypass via DLL Loaded by odbcconf.exe",\n    "description": "Detects defence evasion attempt via odbcconf.exe execution to load DLL",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1218"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\odbcconf.exe AND CommandLine.keyword:(*\\\\-f* OR *regsvr*)) OR (ParentImage.keyword:*\\\\\\\\odbcconf.exe AND Image.keyword:*\\\\\\\\rundll32.exe))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\odbcconf.exe AND CommandLine.keyword:(*\\\\-f* OR *regsvr*)) OR (ParentImage.keyword:*\\\\\\\\odbcconf.exe AND Image.keyword:*\\\\\\\\rundll32.exe))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Application Whitelisting Bypass via DLL Loaded by odbcconf.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\odbcconf.exe AND CommandLine.keyword:(*\\-f* *regsvr*)) OR (ParentImage.keyword:*\\\\odbcconf.exe AND Image.keyword:*\\\\rundll32.exe))
```


### splunk
    
```
((Image="*\\\\odbcconf.exe" (CommandLine="*-f*" OR CommandLine="*regsvr*")) OR (ParentImage="*\\\\odbcconf.exe" Image="*\\\\rundll32.exe"))
```


### logpoint
    
```
(event_id="1" ((Image="*\\\\odbcconf.exe" CommandLine IN ["*-f*", "*regsvr*"]) OR (ParentImage="*\\\\odbcconf.exe" Image="*\\\\rundll32.exe")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\odbcconf\\.exe)(?=.*(?:.*.*-f.*|.*.*regsvr.*)))|.*(?:.*(?=.*.*\\odbcconf\\.exe)(?=.*.*\\rundll32\\.exe))))'
```



