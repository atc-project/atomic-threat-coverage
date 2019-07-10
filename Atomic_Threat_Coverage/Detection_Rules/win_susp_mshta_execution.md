| Title                | MSHTA Suspicious Execution 01                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://blog.sevagas.com/?Hacking-around-HTA-files](http://blog.sevagas.com/?Hacking-around-HTA-files)</li><li>[https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356](https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356)</li><li>[https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script](https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script)</li><li>[https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997](https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997)</li></ul>  |
| Author               | Diego Perez (@darkquassar) |


## Detection Rules

### Sigma rule

```
title: MSHTA Suspicious Execution 01
status: experimental
description: Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism
date: 22/02/2019
modified: 22/02/2019
author: Diego Perez (@darkquassar)
references:
    - http://blog.sevagas.com/?Hacking-around-HTA-files
    - https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356
    - https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script
    - https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high
detection:
    selection1:
        CommandLine: 
            - '*mshta vbscript:CreateObject("Wscript.Shell")*'
            - '*mshta vbscript:Execute("Execute*'
            - '*mshta vbscript:CreateObject("Wscript.Shell").Run("mshta.exe*'
    selection2:
        Image:
            - 'C:\Windows\system32\mshta.exe'
        CommandLine: 
            - '*.jpg*'
            - '*.png*'
            - '*.lnk*'
            # - '*.chm*'  # could be prone to false positives
            - '*.xls*'
            - '*.doc*'
            - '*.zip*'
    condition:
        selection1 or selection2

```





### es-qs
    
```
(CommandLine.keyword:(*mshta\\ vbscript\\:CreateObject\\(\\"Wscript.Shell\\"\\)* *mshta\\ vbscript\\:Execute\\(\\"Execute* *mshta\\ vbscript\\:CreateObject\\(\\"Wscript.Shell\\"\\).Run\\(\\"mshta.exe*) OR (Image:("C\\:\\\\Windows\\\\system32\\\\mshta.exe") AND CommandLine.keyword:(*.jpg* *.png* *.lnk* *.xls* *.doc* *.zip*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/MSHTA-Suspicious-Execution-01 <<EOF\n{\n  "metadata": {\n    "title": "MSHTA Suspicious Execution 01",\n    "description": "Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1140"\n    ],\n    "query": "(CommandLine.keyword:(*mshta\\\\ vbscript\\\\:CreateObject\\\\(\\\\\\"Wscript.Shell\\\\\\"\\\\)* *mshta\\\\ vbscript\\\\:Execute\\\\(\\\\\\"Execute* *mshta\\\\ vbscript\\\\:CreateObject\\\\(\\\\\\"Wscript.Shell\\\\\\"\\\\).Run\\\\(\\\\\\"mshta.exe*) OR (Image:(\\"C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\mshta.exe\\") AND CommandLine.keyword:(*.jpg* *.png* *.lnk* *.xls* *.doc* *.zip*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:(*mshta\\\\ vbscript\\\\:CreateObject\\\\(\\\\\\"Wscript.Shell\\\\\\"\\\\)* *mshta\\\\ vbscript\\\\:Execute\\\\(\\\\\\"Execute* *mshta\\\\ vbscript\\\\:CreateObject\\\\(\\\\\\"Wscript.Shell\\\\\\"\\\\).Run\\\\(\\\\\\"mshta.exe*) OR (Image:(\\"C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\mshta.exe\\") AND CommandLine.keyword:(*.jpg* *.png* *.lnk* *.xls* *.doc* *.zip*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'MSHTA Suspicious Execution 01\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine:("*mshta vbscript\\:CreateObject\\(\\"Wscript.Shell\\"\\)*" "*mshta vbscript\\:Execute\\(\\"Execute*" "*mshta vbscript\\:CreateObject\\(\\"Wscript.Shell\\"\\).Run\\(\\"mshta.exe*") OR (Image:("C\\:\\\\Windows\\\\system32\\\\mshta.exe") AND CommandLine:("*.jpg*" "*.png*" "*.lnk*" "*.xls*" "*.doc*" "*.zip*")))
```


### splunk
    
```
((CommandLine="*mshta vbscript:CreateObject(\\"Wscript.Shell\\")*" OR CommandLine="*mshta vbscript:Execute(\\"Execute*" OR CommandLine="*mshta vbscript:CreateObject(\\"Wscript.Shell\\").Run(\\"mshta.exe*") OR ((Image="C:\\\\Windows\\\\system32\\\\mshta.exe") (CommandLine="*.jpg*" OR CommandLine="*.png*" OR CommandLine="*.lnk*" OR CommandLine="*.xls*" OR CommandLine="*.doc*" OR CommandLine="*.zip*")))
```


### logpoint
    
```
(CommandLine IN ["*mshta vbscript:CreateObject(\\"Wscript.Shell\\")*", "*mshta vbscript:Execute(\\"Execute*", "*mshta vbscript:CreateObject(\\"Wscript.Shell\\").Run(\\"mshta.exe*"] OR (Image IN ["C:\\\\Windows\\\\system32\\\\mshta.exe"] CommandLine IN ["*.jpg*", "*.png*", "*.lnk*", "*.xls*", "*.doc*", "*.zip*"]))
```


### grep
    
```
grep -P \'^(?:.*(?:.*(?:.*.*mshta vbscript:CreateObject\\("Wscript\\.Shell"\\).*|.*.*mshta vbscript:Execute\\("Execute.*|.*.*mshta vbscript:CreateObject\\("Wscript\\.Shell"\\)\\.Run\\("mshta\\.exe.*)|.*(?:.*(?=.*(?:.*C:\\Windows\\system32\\mshta\\.exe))(?=.*(?:.*.*\\.jpg.*|.*.*\\.png.*|.*.*\\.lnk.*|.*.*\\.xls.*|.*.*\\.doc.*|.*.*\\.zip.*)))))\'
```



