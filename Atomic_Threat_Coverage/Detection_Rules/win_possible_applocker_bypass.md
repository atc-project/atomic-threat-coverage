| Title                | Possible Applocker Bypass                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of executables that can be used to bypass Applocker whitelisting                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)</li><li>[https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/](https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/)</li></ul>                                                          |
| Author               | juju4                                                                                                                                                |


## Detection Rules

### Sigma rule

```
action: global
title: Possible Applocker Bypass
description: Detects execution of executables that can be used to bypass Applocker whitelisting
status: experimental
references:
    - https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
    - https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/
author: juju4
tags:
    - attack.defense_evasion
detection:
    selection:
        CommandLine: 
            - '*\msdt.exe*'
            - '*\installutil.exe*'
            - '*\regsvcs.exe*'
            - '*\regasm.exe*'
            - '*\regsvr32.exe*'
            - '*\msbuild.exe*'
            - '*\ieexec.exe*'
            - '*\mshta.exe*'
            # higher risk of false positives
#            - '*\cscript.EXE*'
    condition: selection
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: low
---
# Windows Audit Log
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688
---
# Sysmon
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1

```





### es-qs
    
```
(EventID:"4688" AND CommandLine.keyword:(*\\\\msdt.exe* *\\\\installutil.exe* *\\\\regsvcs.exe* *\\\\regasm.exe* *\\\\regsvr32.exe* *\\\\msbuild.exe* *\\\\ieexec.exe* *\\\\mshta.exe*))\n(EventID:"1" AND CommandLine.keyword:(*\\\\msdt.exe* *\\\\installutil.exe* *\\\\regsvcs.exe* *\\\\regasm.exe* *\\\\regsvr32.exe* *\\\\msbuild.exe* *\\\\ieexec.exe* *\\\\mshta.exe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Applocker-Bypass <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine.keyword:(*\\\\\\\\msdt.exe* *\\\\\\\\installutil.exe* *\\\\\\\\regsvcs.exe* *\\\\\\\\regasm.exe* *\\\\\\\\regsvr32.exe* *\\\\\\\\msbuild.exe* *\\\\\\\\ieexec.exe* *\\\\\\\\mshta.exe*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Applocker Bypass\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Applocker-Bypass-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine.keyword:(*\\\\\\\\msdt.exe* *\\\\\\\\installutil.exe* *\\\\\\\\regsvcs.exe* *\\\\\\\\regasm.exe* *\\\\\\\\regsvr32.exe* *\\\\\\\\msbuild.exe* *\\\\\\\\ieexec.exe* *\\\\\\\\mshta.exe*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Applocker Bypass\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4688" AND CommandLine:("*\\\\msdt.exe*" "*\\\\installutil.exe*" "*\\\\regsvcs.exe*" "*\\\\regasm.exe*" "*\\\\regsvr32.exe*" "*\\\\msbuild.exe*" "*\\\\ieexec.exe*" "*\\\\mshta.exe*"))\n(EventID:"1" AND CommandLine:("*\\\\msdt.exe*" "*\\\\installutil.exe*" "*\\\\regsvcs.exe*" "*\\\\regasm.exe*" "*\\\\regsvr32.exe*" "*\\\\msbuild.exe*" "*\\\\ieexec.exe*" "*\\\\mshta.exe*"))
```


### splunk
    
```
(EventID="4688" (CommandLine="*\\\\msdt.exe*" OR CommandLine="*\\\\installutil.exe*" OR CommandLine="*\\\\regsvcs.exe*" OR CommandLine="*\\\\regasm.exe*" OR CommandLine="*\\\\regsvr32.exe*" OR CommandLine="*\\\\msbuild.exe*" OR CommandLine="*\\\\ieexec.exe*" OR CommandLine="*\\\\mshta.exe*"))\n(EventID="1" (CommandLine="*\\\\msdt.exe*" OR CommandLine="*\\\\installutil.exe*" OR CommandLine="*\\\\regsvcs.exe*" OR CommandLine="*\\\\regasm.exe*" OR CommandLine="*\\\\regsvr32.exe*" OR CommandLine="*\\\\msbuild.exe*" OR CommandLine="*\\\\ieexec.exe*" OR CommandLine="*\\\\mshta.exe*"))
```


### logpoint
    
```
(EventID="4688" CommandLine IN ["*\\\\msdt.exe*", "*\\\\installutil.exe*", "*\\\\regsvcs.exe*", "*\\\\regasm.exe*", "*\\\\regsvr32.exe*", "*\\\\msbuild.exe*", "*\\\\ieexec.exe*", "*\\\\mshta.exe*"])\n(EventID="1" CommandLine IN ["*\\\\msdt.exe*", "*\\\\installutil.exe*", "*\\\\regsvcs.exe*", "*\\\\regasm.exe*", "*\\\\regsvr32.exe*", "*\\\\msbuild.exe*", "*\\\\ieexec.exe*", "*\\\\mshta.exe*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*4688)(?=.*(?:.*.*\\msdt\\.exe.*|.*.*\\installutil\\.exe.*|.*.*\\regsvcs\\.exe.*|.*.*\\regasm\\.exe.*|.*.*\\regsvr32\\.exe.*|.*.*\\msbuild\\.exe.*|.*.*\\ieexec\\.exe.*|.*.*\\mshta\\.exe.*)))'\ngrep -P '^(?:.*(?=.*1)(?=.*(?:.*.*\\msdt\\.exe.*|.*.*\\installutil\\.exe.*|.*.*\\regsvcs\\.exe.*|.*.*\\regasm\\.exe.*|.*.*\\regsvr32\\.exe.*|.*.*\\msbuild\\.exe.*|.*.*\\ieexec\\.exe.*|.*.*\\mshta\\.exe.*)))'
```



