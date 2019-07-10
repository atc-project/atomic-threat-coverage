| Title                | Windows Processes Suspicious Parent Directory                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect suspicious parent processes of well-known Windows processes                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Some security products seem to spawn these</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2](https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2)</li><li>[https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/](https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/)</li><li>[https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf](https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf)</li><li>[https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)</li></ul>  |
| Author               | vburov |


## Detection Rules

### Sigma rule

```
title: Windows Processes Suspicious Parent Directory
status: experimental
description: Detect suspicious parent processes of well-known Windows processes
author: 'vburov'
references:
    - https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2
    - https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/
    - https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf
    - https://attack.mitre.org/techniques/T1036/
date: 2019/02/23
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\svchost.exe'
            - '*\taskhost.exe'
            - '*\lsm.exe'
            - '*\lsass.exe'
            - '*\services.exe'
            - '*\lsaiso.exe'
            - '*\csrss.exe'
            - '*\wininit.exe'
            - '*\winlogon.exe'
    filter:
        ParentImage:
            - '*\System32\\*'
            - '*\SysWOW64\\*'
    condition: selection and not filter
falsepositives:
    - Some security products seem to spawn these
level: low

```





### es-qs
    
```
(Image.keyword:(*\\\\svchost.exe *\\\\taskhost.exe *\\\\lsm.exe *\\\\lsass.exe *\\\\services.exe *\\\\lsaiso.exe *\\\\csrss.exe *\\\\wininit.exe *\\\\winlogon.exe) AND (NOT (ParentImage.keyword:(*\\\\System32\\\\* *\\\\SysWOW64\\\\*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Windows-Processes-Suspicious-Parent-Directory <<EOF\n{\n  "metadata": {\n    "title": "Windows Processes Suspicious Parent Directory",\n    "description": "Detect suspicious parent processes of well-known Windows processes",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\svchost.exe *\\\\\\\\taskhost.exe *\\\\\\\\lsm.exe *\\\\\\\\lsass.exe *\\\\\\\\services.exe *\\\\\\\\lsaiso.exe *\\\\\\\\csrss.exe *\\\\\\\\wininit.exe *\\\\\\\\winlogon.exe) AND (NOT (ParentImage.keyword:(*\\\\\\\\System32\\\\\\\\* *\\\\\\\\SysWOW64\\\\\\\\*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\svchost.exe *\\\\\\\\taskhost.exe *\\\\\\\\lsm.exe *\\\\\\\\lsass.exe *\\\\\\\\services.exe *\\\\\\\\lsaiso.exe *\\\\\\\\csrss.exe *\\\\\\\\wininit.exe *\\\\\\\\winlogon.exe) AND (NOT (ParentImage.keyword:(*\\\\\\\\System32\\\\\\\\* *\\\\\\\\SysWOW64\\\\\\\\*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows Processes Suspicious Parent Directory\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:("*\\\\svchost.exe" "*\\\\taskhost.exe" "*\\\\lsm.exe" "*\\\\lsass.exe" "*\\\\services.exe" "*\\\\lsaiso.exe" "*\\\\csrss.exe" "*\\\\wininit.exe" "*\\\\winlogon.exe") AND NOT (ParentImage:("*\\\\System32\\\\*" "*\\\\SysWOW64\\\\*")))
```


### splunk
    
```
((Image="*\\\\svchost.exe" OR Image="*\\\\taskhost.exe" OR Image="*\\\\lsm.exe" OR Image="*\\\\lsass.exe" OR Image="*\\\\services.exe" OR Image="*\\\\lsaiso.exe" OR Image="*\\\\csrss.exe" OR Image="*\\\\wininit.exe" OR Image="*\\\\winlogon.exe") NOT ((ParentImage="*\\\\System32\\\\*" OR ParentImage="*\\\\SysWOW64\\\\*")))
```


### logpoint
    
```
(Image IN ["*\\\\svchost.exe", "*\\\\taskhost.exe", "*\\\\lsm.exe", "*\\\\lsass.exe", "*\\\\services.exe", "*\\\\lsaiso.exe", "*\\\\csrss.exe", "*\\\\wininit.exe", "*\\\\winlogon.exe"]  -(ParentImage IN ["*\\\\System32\\\\*", "*\\\\SysWOW64\\\\*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\svchost\\.exe|.*.*\\taskhost\\.exe|.*.*\\lsm\\.exe|.*.*\\lsass\\.exe|.*.*\\services\\.exe|.*.*\\lsaiso\\.exe|.*.*\\csrss\\.exe|.*.*\\wininit\\.exe|.*.*\\winlogon\\.exe))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\System32\\\\.*|.*.*\\SysWOW64\\\\.*))))))'
```



