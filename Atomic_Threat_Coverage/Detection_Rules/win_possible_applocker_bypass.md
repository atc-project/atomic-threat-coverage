| Title                | Possible Applocker Bypass                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of executables that can be used to bypass Applocker whitelisting                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li><li>Using installutil to add features for .NET applications (primarly would occur in developer environments)</li></ul>                                                                  |
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
    - Using installutil to add features for .NET applications (primarly would occur in developer environments)
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





### Kibana query

```
(EventID:"4688" AND CommandLine.keyword:(*\\\\msdt.exe* *\\\\installutil.exe* *\\\\regsvcs.exe* *\\\\regasm.exe* *\\\\regsvr32.exe* *\\\\msbuild.exe* *\\\\ieexec.exe* *\\\\mshta.exe*))\n(EventID:"1" AND CommandLine.keyword:(*\\\\msdt.exe* *\\\\installutil.exe* *\\\\regsvcs.exe* *\\\\regasm.exe* *\\\\regsvr32.exe* *\\\\msbuild.exe* *\\\\ieexec.exe* *\\\\mshta.exe*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Applocker-Bypass <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"4688\\" AND CommandLine.keyword:(*\\\\\\\\msdt.exe* *\\\\\\\\installutil.exe* *\\\\\\\\regsvcs.exe* *\\\\\\\\regasm.exe* *\\\\\\\\regsvr32.exe* *\\\\\\\\msbuild.exe* *\\\\\\\\ieexec.exe* *\\\\\\\\mshta.exe*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Applocker Bypass\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Applocker-Bypass-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND CommandLine.keyword:(*\\\\\\\\msdt.exe* *\\\\\\\\installutil.exe* *\\\\\\\\regsvcs.exe* *\\\\\\\\regasm.exe* *\\\\\\\\regsvr32.exe* *\\\\\\\\msbuild.exe* *\\\\\\\\ieexec.exe* *\\\\\\\\mshta.exe*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Applocker Bypass\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"4688" AND CommandLine:("*\\\\msdt.exe*" "*\\\\installutil.exe*" "*\\\\regsvcs.exe*" "*\\\\regasm.exe*" "*\\\\regsvr32.exe*" "*\\\\msbuild.exe*" "*\\\\ieexec.exe*" "*\\\\mshta.exe*"))\n(EventID:"1" AND CommandLine:("*\\\\msdt.exe*" "*\\\\installutil.exe*" "*\\\\regsvcs.exe*" "*\\\\regasm.exe*" "*\\\\regsvr32.exe*" "*\\\\msbuild.exe*" "*\\\\ieexec.exe*" "*\\\\mshta.exe*"))
```

