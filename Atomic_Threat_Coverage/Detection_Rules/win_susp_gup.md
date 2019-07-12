| Title                | Suspicious GUP Usage                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Execution of tools named GUP.exe and located in folders different than Notepad++\updater</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious GUP Usage
description: Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks
status: experimental
references:
    - https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html
tags:
  - attack.defense_evasion
  - attack.t1073
author: Florian Roth
date: 2019/02/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\GUP.exe'
    filter:
        Image:
            - 'C:\Users\*\AppData\Local\Notepad++\updater\gup.exe'
            - 'C:\Users\*\AppData\Roaming\Notepad++\updater\gup.exe'
            - 'C:\Program Files\Notepad++\updater\gup.exe'
            - 'C:\Program Files (x86)\Notepad++\updater\gup.exe'
    condition: selection and not filter
falsepositives:
    - Execution of tools named GUP.exe and located in folders different than Notepad++\updater
level: high

```





### es-qs
    
```
(Image.keyword:*\\\\GUP.exe AND (NOT (Image:("C\\:\\\\Users\\*\\\\AppData\\\\Local\\\\Notepad\\+\\+\\\\updater\\\\gup.exe" "C\\:\\\\Users\\*\\\\AppData\\\\Roaming\\\\Notepad\\+\\+\\\\updater\\\\gup.exe" "C\\:\\\\Program\\ Files\\\\Notepad\\+\\+\\\\updater\\\\gup.exe" "C\\:\\\\Program\\ Files\\ \\(x86\\)\\\\Notepad\\+\\+\\\\updater\\\\gup.exe"))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-GUP-Usage <<EOF\n{\n  "metadata": {\n    "title": "Suspicious GUP Usage",\n    "description": "Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1073"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\GUP.exe AND (NOT (Image:(\\"C\\\\:\\\\\\\\Users\\\\*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Notepad\\\\+\\\\+\\\\\\\\updater\\\\\\\\gup.exe\\" \\"C\\\\:\\\\\\\\Users\\\\*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\Notepad\\\\+\\\\+\\\\\\\\updater\\\\\\\\gup.exe\\" \\"C\\\\:\\\\\\\\Program\\\\ Files\\\\\\\\Notepad\\\\+\\\\+\\\\\\\\updater\\\\\\\\gup.exe\\" \\"C\\\\:\\\\\\\\Program\\\\ Files\\\\ \\\\(x86\\\\)\\\\\\\\Notepad\\\\+\\\\+\\\\\\\\updater\\\\\\\\gup.exe\\"))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\GUP.exe AND (NOT (Image:(\\"C\\\\:\\\\\\\\Users\\\\*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Notepad\\\\+\\\\+\\\\\\\\updater\\\\\\\\gup.exe\\" \\"C\\\\:\\\\\\\\Users\\\\*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\Notepad\\\\+\\\\+\\\\\\\\updater\\\\\\\\gup.exe\\" \\"C\\\\:\\\\\\\\Program\\\\ Files\\\\\\\\Notepad\\\\+\\\\+\\\\\\\\updater\\\\\\\\gup.exe\\" \\"C\\\\:\\\\\\\\Program\\\\ Files\\\\ \\\\(x86\\\\)\\\\\\\\Notepad\\\\+\\\\+\\\\\\\\updater\\\\\\\\gup.exe\\"))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious GUP Usage\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:"*\\\\GUP.exe" AND NOT (Image:("C\\:\\\\Users\\*\\\\AppData\\\\Local\\\\Notepad\\+\\+\\\\updater\\\\gup.exe" "C\\:\\\\Users\\*\\\\AppData\\\\Roaming\\\\Notepad\\+\\+\\\\updater\\\\gup.exe" "C\\:\\\\Program Files\\\\Notepad\\+\\+\\\\updater\\\\gup.exe" "C\\:\\\\Program Files \\(x86\\)\\\\Notepad\\+\\+\\\\updater\\\\gup.exe")))
```


### splunk
    
```
(Image="*\\\\GUP.exe" NOT ((Image="C:\\\\Users\\*\\\\AppData\\\\Local\\\\Notepad++\\\\updater\\\\gup.exe" OR Image="C:\\\\Users\\*\\\\AppData\\\\Roaming\\\\Notepad++\\\\updater\\\\gup.exe" OR Image="C:\\\\Program Files\\\\Notepad++\\\\updater\\\\gup.exe" OR Image="C:\\\\Program Files (x86)\\\\Notepad++\\\\updater\\\\gup.exe")))
```


### logpoint
    
```
(Image="*\\\\GUP.exe"  -(Image IN ["C:\\\\Users\\*\\\\AppData\\\\Local\\\\Notepad++\\\\updater\\\\gup.exe", "C:\\\\Users\\*\\\\AppData\\\\Roaming\\\\Notepad++\\\\updater\\\\gup.exe", "C:\\\\Program Files\\\\Notepad++\\\\updater\\\\gup.exe", "C:\\\\Program Files (x86)\\\\Notepad++\\\\updater\\\\gup.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\GUP\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*C:\\Users\\.*\\AppData\\Local\\Notepad\\+\\+\\updater\\gup\\.exe|.*C:\\Users\\.*\\AppData\\Roaming\\Notepad\\+\\+\\updater\\gup\\.exe|.*C:\\Program Files\\Notepad\\+\\+\\updater\\gup\\.exe|.*C:\\Program Files \\(x86\\)\\Notepad\\+\\+\\updater\\gup\\.exe))))))'
```



