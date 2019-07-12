| Title                | Hiding files with attrib.exe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects usage of attrib.exe to hide files from users.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1158: Hidden Files and Directories](https://attack.mitre.org/techniques/T1158)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1158: Hidden Files and Directories](../Triggers/T1158.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)</li><li>msiexec.exe hiding desktop.ini</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Sami Ruohonen |


## Detection Rules

### Sigma rule

```
title: Hiding files with attrib.exe
status: experimental
description: Detects usage of attrib.exe to hide files from users.
author: Sami Ruohonen
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\attrib.exe'
        CommandLine: '* +h *'
    ini:
        CommandLine: '*\desktop.ini *'
    intel:
        ParentImage: '*\cmd.exe'
        CommandLine: +R +H +S +A \\*.cui
        ParentCommandLine: C:\WINDOWS\system32\\*.bat
    condition: selection and not (ini or intel)
fields:
    - CommandLine
    - ParentCommandLine
    - User
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1158
falsepositives:
    - igfxCUIService.exe hiding *.cui files via .bat script (attrib.exe a child of cmd.exe and igfxCUIService.exe is the parent of the cmd.exe)
    - msiexec.exe hiding desktop.ini
level: low

```





### es-qs
    
```
((Image.keyword:*\\\\attrib.exe AND CommandLine.keyword:*\\ \\+h\\ *) AND (NOT ((CommandLine.keyword:*\\\\desktop.ini\\ * OR (ParentImage.keyword:*\\\\cmd.exe AND CommandLine:"\\+R\\ \\+H\\ \\+S\\ \\+A\\ \\\\*.cui" AND ParentCommandLine:"C\\:\\\\WINDOWS\\\\system32\\\\*.bat")))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Hiding-files-with-attrib.exe <<EOF\n{\n  "metadata": {\n    "title": "Hiding files with attrib.exe",\n    "description": "Detects usage of attrib.exe to hide files from users.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.persistence",\n      "attack.t1158"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\attrib.exe AND CommandLine.keyword:*\\\\ \\\\+h\\\\ *) AND (NOT ((CommandLine.keyword:*\\\\\\\\desktop.ini\\\\ * OR (ParentImage.keyword:*\\\\\\\\cmd.exe AND CommandLine:\\"\\\\+R\\\\ \\\\+H\\\\ \\\\+S\\\\ \\\\+A\\\\ \\\\\\\\*.cui\\" AND ParentCommandLine:\\"C\\\\:\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\*.bat\\")))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\attrib.exe AND CommandLine.keyword:*\\\\ \\\\+h\\\\ *) AND (NOT ((CommandLine.keyword:*\\\\\\\\desktop.ini\\\\ * OR (ParentImage.keyword:*\\\\\\\\cmd.exe AND CommandLine:\\"\\\\+R\\\\ \\\\+H\\\\ \\\\+S\\\\ \\\\+A\\\\ \\\\\\\\*.cui\\" AND ParentCommandLine:\\"C\\\\:\\\\\\\\WINDOWS\\\\\\\\system32\\\\\\\\*.bat\\")))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Hiding files with attrib.exe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n             User = {{_source.User}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image:"*\\\\attrib.exe" AND CommandLine:"* \\+h *") AND NOT ((CommandLine:"*\\\\desktop.ini *" OR (ParentImage:"*\\\\cmd.exe" AND CommandLine:"\\+R \\+H \\+S \\+A \\\\*.cui" AND ParentCommandLine:"C\\:\\\\WINDOWS\\\\system32\\\\*.bat"))))
```


### splunk
    
```
((Image="*\\\\attrib.exe" CommandLine="* +h *") NOT ((CommandLine="*\\\\desktop.ini *" OR (ParentImage="*\\\\cmd.exe" CommandLine="+R +H +S +A \\\\*.cui" ParentCommandLine="C:\\\\WINDOWS\\\\system32\\\\*.bat")))) | table CommandLine,ParentCommandLine,User
```


### logpoint
    
```
((Image="*\\\\attrib.exe" CommandLine="* +h *")  -((CommandLine="*\\\\desktop.ini *" OR (ParentImage="*\\\\cmd.exe" CommandLine="+R +H +S +A \\\\*.cui" ParentCommandLine="C:\\\\WINDOWS\\\\system32\\\\*.bat"))))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\attrib\\.exe)(?=.*.* \\+h .*)))(?=.*(?!.*(?:.*(?:.*(?:.*.*\\desktop\\.ini .*|.*(?:.*(?=.*.*\\cmd\\.exe)(?=.*\\+R \\+H \\+S \\+A \\\\.*\\.cui)(?=.*C:\\WINDOWS\\system32\\\\.*\\.bat))))))))'
```



