| Title                    | Svchost DLL Search Order Hijack       |
|:-------------------------|:------------------|
| **Description**          | IKEEXT and SessionEnv service, as they call LoadLibrary on files that do not exist within C:\Windows\System32\ by default. An attacker can place their malicious logic within the PROCESS_ATTACH block of their library and restart the aforementioned services "svchost.exe -k netsvcs" to gain code execution on a remote machine. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1038: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1038)</li><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li><li>[T1038: DLL Search Order Hijacking](../Triggers/T1038.md)</li><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Pentest</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992](https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992)</li></ul>  |
| **Author**               | SBousseaden |


## Detection Rules

### Sigma rule

```
title: Svchost DLL Search Order Hijack
id: 602a1f13-c640-4d73-b053-be9a2fa58b77
status: experimental
description: IKEEXT and SessionEnv service, as they call LoadLibrary on files that do not exist within C:\Windows\System32\ by default. An attacker can place their
    malicious logic within the PROCESS_ATTACH block of their library and restart the aforementioned services "svchost.exe -k netsvcs" to gain code execution on a
    remote machine.
references:
    - https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992
author: SBousseaden
date: 2019/10/28
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1073
    - attack.t1038
    - attack.t1112
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7
        Image:
            - '*\svchost.exe'
        ImageLoaded:
            - '*\tsmsisrv.dll'
            - '*\tsvipsrv.dll'
            - '*\wlbsctrl.dll'
    filter:
        EventID: 7
        Image:
            - '*\svchost.exe'
        ImageLoaded:
            - 'C:\Windows\WinSxS\*'        
    condition: selection and not filter
falsepositives:
    - Pentest
level: high
```





### es-qs
    
```
((EventID:"7" AND Image.keyword:(*\\\\svchost.exe) AND ImageLoaded.keyword:(*\\\\tsmsisrv.dll OR *\\\\tsvipsrv.dll OR *\\\\wlbsctrl.dll)) AND (NOT (EventID:"7" AND Image.keyword:(*\\\\svchost.exe) AND ImageLoaded:("C\\:\\\\Windows\\\\WinSxS\\*"))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/602a1f13-c640-4d73-b053-be9a2fa58b77 <<EOF\n{\n  "metadata": {\n    "title": "Svchost DLL Search Order Hijack",\n    "description": "IKEEXT and SessionEnv service, as they call LoadLibrary on files that do not exist within C:\\\\Windows\\\\System32\\\\ by default. An attacker can place their malicious logic within the PROCESS_ATTACH block of their library and restart the aforementioned services \\"svchost.exe -k netsvcs\\" to gain code execution on a remote machine.",\n    "tags": [\n      "attack.persistence",\n      "attack.defense_evasion",\n      "attack.t1073",\n      "attack.t1038",\n      "attack.t1112"\n    ],\n    "query": "((EventID:\\"7\\" AND Image.keyword:(*\\\\\\\\svchost.exe) AND ImageLoaded.keyword:(*\\\\\\\\tsmsisrv.dll OR *\\\\\\\\tsvipsrv.dll OR *\\\\\\\\wlbsctrl.dll)) AND (NOT (EventID:\\"7\\" AND Image.keyword:(*\\\\\\\\svchost.exe) AND ImageLoaded:(\\"C\\\\:\\\\\\\\Windows\\\\\\\\WinSxS\\\\*\\"))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"7\\" AND Image.keyword:(*\\\\\\\\svchost.exe) AND ImageLoaded.keyword:(*\\\\\\\\tsmsisrv.dll OR *\\\\\\\\tsvipsrv.dll OR *\\\\\\\\wlbsctrl.dll)) AND (NOT (EventID:\\"7\\" AND Image.keyword:(*\\\\\\\\svchost.exe) AND ImageLoaded:(\\"C\\\\:\\\\\\\\Windows\\\\\\\\WinSxS\\\\*\\"))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Svchost DLL Search Order Hijack\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"7" AND Image.keyword:(*\\\\svchost.exe) AND ImageLoaded.keyword:(*\\\\tsmsisrv.dll *\\\\tsvipsrv.dll *\\\\wlbsctrl.dll)) AND (NOT (EventID:"7" AND Image.keyword:(*\\\\svchost.exe) AND ImageLoaded:("C\\:\\\\Windows\\\\WinSxS\\*"))))
```


### splunk
    
```
((EventID="7" (Image="*\\\\svchost.exe") (ImageLoaded="*\\\\tsmsisrv.dll" OR ImageLoaded="*\\\\tsvipsrv.dll" OR ImageLoaded="*\\\\wlbsctrl.dll")) NOT (EventID="7" (Image="*\\\\svchost.exe") (ImageLoaded="C:\\\\Windows\\\\WinSxS\\*")))
```


### logpoint
    
```
((event_id="7" Image IN ["*\\\\svchost.exe"] ImageLoaded IN ["*\\\\tsmsisrv.dll", "*\\\\tsvipsrv.dll", "*\\\\wlbsctrl.dll"])  -(event_id="7" Image IN ["*\\\\svchost.exe"] ImageLoaded IN ["C:\\\\Windows\\\\WinSxS\\*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*7)(?=.*(?:.*.*\\svchost\\.exe))(?=.*(?:.*.*\\tsmsisrv\\.dll|.*.*\\tsvipsrv\\.dll|.*.*\\wlbsctrl\\.dll))))(?=.*(?!.*(?:.*(?=.*7)(?=.*(?:.*.*\\svchost\\.exe))(?=.*(?:.*C:\\Windows\\WinSxS\\.*))))))'
```



