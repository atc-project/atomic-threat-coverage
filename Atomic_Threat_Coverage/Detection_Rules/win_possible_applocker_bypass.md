| Title                | Possible Applocker Bypass                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of executables that can be used to bypass Applocker whitelisting                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1118: InstallUtil](https://attack.mitre.org/techniques/T1118)</li><li>[T1121: Regsvcs/Regasm](https://attack.mitre.org/techniques/T1121)</li><li>[T1127: Trusted Developer Utilities](https://attack.mitre.org/techniques/T1127)</li><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1118: InstallUtil](../Triggers/T1118.md)</li><li>[T1121: Regsvcs/Regasm](../Triggers/T1121.md)</li><li>[T1127: Trusted Developer Utilities](../Triggers/T1127.md)</li><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li><li>Using installutil to add features for .NET applications (primarly would occur in developer environments)</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)</li><li>[https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/](https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/)</li></ul>  |
| Author               | juju4 |


## Detection Rules

### Sigma rule

```
title: Possible Applocker Bypass
description: Detects execution of executables that can be used to bypass Applocker whitelisting
status: experimental
references:
    - https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
    - https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/
author: juju4
tags:
    - attack.defense_evasion
    - attack.t1118
    - attack.t1121
    - attack.t1127
    - attack.t1170
logsource:
    category: process_creation
    product: windows
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
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Using installutil to add features for .NET applications (primarly would occur in developer environments)
level: low

```





### es-qs
    
```
CommandLine.keyword:(*\\\\msdt.exe* *\\\\installutil.exe* *\\\\regsvcs.exe* *\\\\regasm.exe* *\\\\regsvr32.exe* *\\\\msbuild.exe* *\\\\ieexec.exe* *\\\\mshta.exe*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Possible-Applocker-Bypass <<EOF\n{\n  "metadata": {\n    "title": "Possible Applocker Bypass",\n    "description": "Detects execution of executables that can be used to bypass Applocker whitelisting",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1118",\n      "attack.t1121",\n      "attack.t1127",\n      "attack.t1170"\n    ],\n    "query": "CommandLine.keyword:(*\\\\\\\\msdt.exe* *\\\\\\\\installutil.exe* *\\\\\\\\regsvcs.exe* *\\\\\\\\regasm.exe* *\\\\\\\\regsvr32.exe* *\\\\\\\\msbuild.exe* *\\\\\\\\ieexec.exe* *\\\\\\\\mshta.exe*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(*\\\\\\\\msdt.exe* *\\\\\\\\installutil.exe* *\\\\\\\\regsvcs.exe* *\\\\\\\\regasm.exe* *\\\\\\\\regsvr32.exe* *\\\\\\\\msbuild.exe* *\\\\\\\\ieexec.exe* *\\\\\\\\mshta.exe*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Possible Applocker Bypass\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("*\\\\msdt.exe*" "*\\\\installutil.exe*" "*\\\\regsvcs.exe*" "*\\\\regasm.exe*" "*\\\\regsvr32.exe*" "*\\\\msbuild.exe*" "*\\\\ieexec.exe*" "*\\\\mshta.exe*")
```


### splunk
    
```
(CommandLine="*\\\\msdt.exe*" OR CommandLine="*\\\\installutil.exe*" OR CommandLine="*\\\\regsvcs.exe*" OR CommandLine="*\\\\regasm.exe*" OR CommandLine="*\\\\regsvr32.exe*" OR CommandLine="*\\\\msbuild.exe*" OR CommandLine="*\\\\ieexec.exe*" OR CommandLine="*\\\\mshta.exe*")
```


### logpoint
    
```
CommandLine IN ["*\\\\msdt.exe*", "*\\\\installutil.exe*", "*\\\\regsvcs.exe*", "*\\\\regasm.exe*", "*\\\\regsvr32.exe*", "*\\\\msbuild.exe*", "*\\\\ieexec.exe*", "*\\\\mshta.exe*"]
```


### grep
    
```
grep -P '^(?:.*.*\\msdt\\.exe.*|.*.*\\installutil\\.exe.*|.*.*\\regsvcs\\.exe.*|.*.*\\regasm\\.exe.*|.*.*\\regsvr32\\.exe.*|.*.*\\msbuild\\.exe.*|.*.*\\ieexec\\.exe.*|.*.*\\mshta\\.exe.*)'
```



