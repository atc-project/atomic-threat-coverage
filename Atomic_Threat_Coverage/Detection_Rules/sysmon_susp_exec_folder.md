| Title                | Executables Started in Suspicious Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process starts of binaries from a suspicious folder                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt](https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt)</li><li>[https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses](https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Executables Started in Suspicious Folder
status: experimental
description: Detects process starts of binaries from a suspicious folder
author: Florian Roth
date: 2017/10/14
references:
   - https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt
   - https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses
logsource:
   product: windows
   service: sysmon
detection:
   selection:
      EventID: 1
      Image:
         - 'C:\PerfLogs\*'
         - 'C:\$Recycle.bin\*'
         - 'C:\Intel\Logs\*'
         - 'C:\Users\Default\*'
         - 'C:\Users\Public\*'
         - 'C:\Users\NetworkService\*'
         - 'C:\Windows\Fonts\*'
         - 'C:\Windows\Debug\*'
         - 'C:\Windows\Media\*'
         - 'C:\Windows\Help\*'
         - 'C:\Windows\addins\*'
         - 'C:\Windows\repair\*'
         - 'C:\Windows\security\*'
         - '*\RSA\MachineKeys\*'
         - 'C:\Windows\system32\config\systemprofile\*'
   condition: selection
falsepositives:
    - Unknown
level: high


```




### esqs
    
```
(EventID:"1" AND Image.keyword:(C\\:\\\\PerfLogs\\* C\\:\\\\$Recycle.bin\\* C\\:\\\\Intel\\\\Logs\\* C\\:\\\\Users\\\\Default\\* C\\:\\\\Users\\\\Public\\* C\\:\\\\Users\\\\NetworkService\\* C\\:\\\\Windows\\\\Fonts\\* C\\:\\\\Windows\\\\Debug\\* C\\:\\\\Windows\\\\Media\\* C\\:\\\\Windows\\\\Help\\* C\\:\\\\Windows\\\\addins\\* C\\:\\\\Windows\\\\repair\\* C\\:\\\\Windows\\\\security\\* *\\\\RSA\\\\MachineKeys\\* C\\:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\*))
```


### xpackwatcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Executables-Started-in-Suspicious-Folder <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND Image.keyword:(C\\\\:\\\\\\\\PerfLogs\\\\* C\\\\:\\\\\\\\$Recycle.bin\\\\* C\\\\:\\\\\\\\Intel\\\\\\\\Logs\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\* C\\\\:\\\\\\\\Users\\\\\\\\NetworkService\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\Fonts\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\Debug\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\Media\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\Help\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\addins\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\repair\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\security\\\\* *\\\\\\\\RSA\\\\\\\\MachineKeys\\\\* C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\config\\\\\\\\systemprofile\\\\*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Executables Started in Suspicious Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"1" AND Image:("C\\:\\\\PerfLogs\\*" "C\\:\\\\$Recycle.bin\\*" "C\\:\\\\Intel\\\\Logs\\*" "C\\:\\\\Users\\\\Default\\*" "C\\:\\\\Users\\\\Public\\*" "C\\:\\\\Users\\\\NetworkService\\*" "C\\:\\\\Windows\\\\Fonts\\*" "C\\:\\\\Windows\\\\Debug\\*" "C\\:\\\\Windows\\\\Media\\*" "C\\:\\\\Windows\\\\Help\\*" "C\\:\\\\Windows\\\\addins\\*" "C\\:\\\\Windows\\\\repair\\*" "C\\:\\\\Windows\\\\security\\*" "*\\\\RSA\\\\MachineKeys\\*" "C\\:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\*"))
```


### splunk
    
```
(EventID="1" (Image="C:\\\\PerfLogs\\*" OR Image="C:\\\\$Recycle.bin\\*" OR Image="C:\\\\Intel\\\\Logs\\*" OR Image="C:\\\\Users\\\\Default\\*" OR Image="C:\\\\Users\\\\Public\\*" OR Image="C:\\\\Users\\\\NetworkService\\*" OR Image="C:\\\\Windows\\\\Fonts\\*" OR Image="C:\\\\Windows\\\\Debug\\*" OR Image="C:\\\\Windows\\\\Media\\*" OR Image="C:\\\\Windows\\\\Help\\*" OR Image="C:\\\\Windows\\\\addins\\*" OR Image="C:\\\\Windows\\\\repair\\*" OR Image="C:\\\\Windows\\\\security\\*" OR Image="*\\\\RSA\\\\MachineKeys\\*" OR Image="C:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\*"))
```


### logpoint
    
```
(EventID="1" Image IN ["C:\\\\PerfLogs\\*", "C:\\\\$Recycle.bin\\*", "C:\\\\Intel\\\\Logs\\*", "C:\\\\Users\\\\Default\\*", "C:\\\\Users\\\\Public\\*", "C:\\\\Users\\\\NetworkService\\*", "C:\\\\Windows\\\\Fonts\\*", "C:\\\\Windows\\\\Debug\\*", "C:\\\\Windows\\\\Media\\*", "C:\\\\Windows\\\\Help\\*", "C:\\\\Windows\\\\addins\\*", "C:\\\\Windows\\\\repair\\*", "C:\\\\Windows\\\\security\\*", "*\\\\RSA\\\\MachineKeys\\*", "C:\\\\Windows\\\\system32\\\\config\\\\systemprofile\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*C:\\PerfLogs\\.*|.*C:\\\\$Recycle\\.bin\\.*|.*C:\\Intel\\Logs\\.*|.*C:\\Users\\Default\\.*|.*C:\\Users\\Public\\.*|.*C:\\Users\\NetworkService\\.*|.*C:\\Windows\\Fonts\\.*|.*C:\\Windows\\Debug\\.*|.*C:\\Windows\\Media\\.*|.*C:\\Windows\\Help\\.*|.*C:\\Windows\\addins\\.*|.*C:\\Windows\\repair\\.*|.*C:\\Windows\\security\\.*|.*.*\\RSA\\MachineKeys\\.*|.*C:\\Windows\\system32\\config\\systemprofile\\.*)))'
```


