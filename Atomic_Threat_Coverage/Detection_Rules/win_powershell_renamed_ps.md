| Title                | Renamed Powershell.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects copying and renaming of powershell.exe before execution (RETEFE malware DOC/macro starting Sept 2018)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>penetration tests, red teaming</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1086/](https://attack.mitre.org/techniques/T1086/)</li><li>[https://isc.sans.edu/forums/diary/Maldoc+Duplicating+PowerShell+Prior+to+Use/24254/](https://isc.sans.edu/forums/diary/Maldoc+Duplicating+PowerShell+Prior+to+Use/24254/)</li></ul>  |
| Author               | Tom Ueltschi (@c_APT_ure) |
| Other Tags           | <ul><li>car.2013-05-009</li><li>car.2013-05-009</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Renamed Powershell.exe
status: experimental
description: Detects copying and renaming of powershell.exe before execution (RETEFE malware DOC/macro starting Sept 2018)
references:
    - https://attack.mitre.org/techniques/T1086/
    - https://isc.sans.edu/forums/diary/Maldoc+Duplicating+PowerShell+Prior+to+Use/24254/
tags:
    - attack.t1086
    - attack.execution
    - car.2013-05-009
author: Tom Ueltschi (@c_APT_ure)
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description: Windows PowerShell
    exclusion_1:
        Image:
            - '*\powershell.exe'
            - '*\powershell_ise.exe'
    exclusion_2:
        Description: Windows PowerShell ISE
    condition: all of selection and not (1 of exclusion_*)
falsepositives:
    - penetration tests, red teaming
level: high

```





### es-qs
    
```
(Description:"Windows\\ PowerShell" AND (NOT ((Image.keyword:(*\\\\powershell.exe *\\\\powershell_ise.exe) OR Description:"Windows\\ PowerShell\\ ISE"))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Renamed-Powershell.exe <<EOF\n{\n  "metadata": {\n    "title": "Renamed Powershell.exe",\n    "description": "Detects copying and renaming of powershell.exe before execution (RETEFE malware DOC/macro starting Sept 2018)",\n    "tags": [\n      "attack.t1086",\n      "attack.execution",\n      "car.2013-05-009"\n    ],\n    "query": "(Description:\\"Windows\\\\ PowerShell\\" AND (NOT ((Image.keyword:(*\\\\\\\\powershell.exe *\\\\\\\\powershell_ise.exe) OR Description:\\"Windows\\\\ PowerShell\\\\ ISE\\"))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Description:\\"Windows\\\\ PowerShell\\" AND (NOT ((Image.keyword:(*\\\\\\\\powershell.exe *\\\\\\\\powershell_ise.exe) OR Description:\\"Windows\\\\ PowerShell\\\\ ISE\\"))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Renamed Powershell.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Description:"Windows PowerShell" AND NOT ((Image:("*\\\\powershell.exe" "*\\\\powershell_ise.exe") OR Description:"Windows PowerShell ISE")))
```


### splunk
    
```
(Description="Windows PowerShell" NOT (((Image="*\\\\powershell.exe" OR Image="*\\\\powershell_ise.exe") OR Description="Windows PowerShell ISE")))
```


### logpoint
    
```
(Description="Windows PowerShell"  -((Image IN ["*\\\\powershell.exe", "*\\\\powershell_ise.exe"] OR Description="Windows PowerShell ISE")))
```


### grep
    
```
grep -P '^(?:.*(?=.*Windows PowerShell)(?=.*(?!.*(?:.*(?:.*(?:.*(?:.*.*\\powershell\\.exe|.*.*\\powershell_ise\\.exe)|.*Windows PowerShell ISE))))))'
```



