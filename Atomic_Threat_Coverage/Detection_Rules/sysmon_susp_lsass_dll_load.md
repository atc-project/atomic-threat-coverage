| Title                    | DLL Load via LSASS       |
|:-------------------------|:------------------|
| **Description**          | Detects a method to load DLL via LSASS process using an undocumented Registry key |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1177: LSASS Driver](https://attack.mitre.org/techniques/T1177)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.xpnsec.com/exploring-mimikatz-part-1/](https://blog.xpnsec.com/exploring-mimikatz-part-1/)</li><li>[https://twitter.com/SBousseaden/status/1183745981189427200](https://twitter.com/SBousseaden/status/1183745981189427200)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: DLL Load via LSASS
id: b3503044-60ce-4bf4-bbcb-e3db98788823
status: experimental
description: Detects a method to load DLL via LSASS process using an undocumented Registry key
author: Florian Roth
date: 2019/10/16
references:
    - https://blog.xpnsec.com/exploring-mimikatz-part-1/
    - https://twitter.com/SBousseaden/status/1183745981189427200
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID:
            - 12 
            - 13
        TargetObject: 
            - '*\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt*'
            - '*\CurrentControlSet\Services\NTDS\LsaDbExtPt*'
    condition: selection
tags:
    - attack.execution
    - attack.t1177
falsepositives:
    - Unknown
level: high


```





### es-qs
    
```
(EventID:("12" OR "13") AND TargetObject.keyword:(*\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\DirectoryServiceExtPt* OR *\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\LsaDbExtPt*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/b3503044-60ce-4bf4-bbcb-e3db98788823 <<EOF\n{\n  "metadata": {\n    "title": "DLL Load via LSASS",\n    "description": "Detects a method to load DLL via LSASS process using an undocumented Registry key",\n    "tags": [\n      "attack.execution",\n      "attack.t1177"\n    ],\n    "query": "(EventID:(\\"12\\" OR \\"13\\") AND TargetObject.keyword:(*\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\NTDS\\\\\\\\DirectoryServiceExtPt* OR *\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\NTDS\\\\\\\\LsaDbExtPt*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"12\\" OR \\"13\\") AND TargetObject.keyword:(*\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\NTDS\\\\\\\\DirectoryServiceExtPt* OR *\\\\\\\\CurrentControlSet\\\\\\\\Services\\\\\\\\NTDS\\\\\\\\LsaDbExtPt*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DLL Load via LSASS\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("12" "13") AND TargetObject.keyword:(*\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\DirectoryServiceExtPt* *\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\LsaDbExtPt*))
```


### splunk
    
```
((EventID="12" OR EventID="13") (TargetObject="*\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\DirectoryServiceExtPt*" OR TargetObject="*\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\LsaDbExtPt*"))
```


### logpoint
    
```
(event_id IN ["12", "13"] TargetObject IN ["*\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\DirectoryServiceExtPt*", "*\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\LsaDbExtPt*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*12|.*13))(?=.*(?:.*.*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt.*|.*.*\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt.*)))'
```



