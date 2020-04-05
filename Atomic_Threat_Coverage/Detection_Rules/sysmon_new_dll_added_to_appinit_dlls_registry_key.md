| Title                    | New DLL Added to AppInit_DLLs Registry Key       |
|:-------------------------|:------------------|
| **Description**          | DLLs that are specified in the AppInit_DLLs value in the Registry key HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll into every process that loads user32.dll |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1103: AppInit DLLs](https://attack.mitre.org/techniques/T1103)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1103: AppInit DLLs](../Triggers/T1103.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/822dc4c5-b355-4df8-bd37-29c458997b8f.html](https://eqllib.readthedocs.io/en/latest/analytics/822dc4c5-b355-4df8-bd37-29c458997b8f.html)</li></ul>  |
| **Author**               | Ilyas Ochkov, oscd.community |


## Detection Rules

### Sigma rule

```
title: New DLL Added to AppInit_DLLs Registry Key
id: 4f84b697-c9ed-4420-8ab5-e09af5b2345d
status: experimental
description: DLLs that are specified in the AppInit_DLLs value in the Registry key HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll
    into every process that loads user32.dll
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/822dc4c5-b355-4df8-bd37-29c458997b8f.html
tags:
    - attack.persistence
    - attack.t1103
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2019/11/13
logsource:
    product: windows
    service: sysmon
detection:
    selection:
      - EventID: 
            - 12 # key create
            - 13 # value set
        TargetObject:
                - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls'
                - '*\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls'
      - EventID: 14 # key rename
        NewName:
                - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls'
                - '*\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls'
    condition: selection
fields:
    - EventID
    - Image
    - TargetObject
    - NewName
falsepositives:
    - Unkown
level: medium

```





### es-qs
    
```
((EventID:("12" OR "13") AND TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls OR *\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls)) OR (EventID:"14" AND NewName.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls OR *\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/4f84b697-c9ed-4420-8ab5-e09af5b2345d <<EOF\n{\n  "metadata": {\n    "title": "New DLL Added to AppInit_DLLs Registry Key",\n    "description": "DLLs that are specified in the AppInit_DLLs value in the Registry key HKLM\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows are loaded by user32.dll into every process that loads user32.dll",\n    "tags": [\n      "attack.persistence",\n      "attack.t1103"\n    ],\n    "query": "((EventID:(\\"12\\" OR \\"13\\") AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows\\\\\\\\AppInit_Dlls OR *\\\\\\\\SOFTWARE\\\\\\\\Wow6432Node\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows\\\\\\\\AppInit_Dlls)) OR (EventID:\\"14\\" AND NewName.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows\\\\\\\\AppInit_Dlls OR *\\\\\\\\SOFTWARE\\\\\\\\Wow6432Node\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows\\\\\\\\AppInit_Dlls)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:(\\"12\\" OR \\"13\\") AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows\\\\\\\\AppInit_Dlls OR *\\\\\\\\SOFTWARE\\\\\\\\Wow6432Node\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows\\\\\\\\AppInit_Dlls)) OR (EventID:\\"14\\" AND NewName.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows\\\\\\\\AppInit_Dlls OR *\\\\\\\\SOFTWARE\\\\\\\\Wow6432Node\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows\\\\\\\\AppInit_Dlls)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'New DLL Added to AppInit_DLLs Registry Key\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     EventID = {{_source.EventID}}\\n       Image = {{_source.Image}}\\nTargetObject = {{_source.TargetObject}}\\n     NewName = {{_source.NewName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:("12" "13") AND TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls *\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls)) OR (EventID:"14" AND NewName.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls *\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls)))
```


### splunk
    
```
(((EventID="12" OR EventID="13") (TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls" OR TargetObject="*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls")) OR (EventID="14" (NewName="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls" OR NewName="*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls"))) | table EventID,Image,TargetObject,NewName
```


### logpoint
    
```
((event_id IN ["12", "13"] TargetObject IN ["*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls", "*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls"]) OR (event_id="14" NewName IN ["*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls", "*\\\\SOFTWARE\\\\Wow6432Node\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_Dlls"]))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*12|.*13))(?=.*(?:.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls|.*.*\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls)))|.*(?:.*(?=.*14)(?=.*(?:.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls|.*.*\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls)))))'
```



