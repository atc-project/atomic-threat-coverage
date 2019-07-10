| Title                | Activity Related to NTDS.dit Domain Hash Retrieval                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious commands that could be related to activity that uses volume shadow copy to steal and retrieve hashes from the NTDS.dit file remotely                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Administrative activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/](https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/)</li><li>[https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/](https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/)</li><li>[https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM)/](https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM)/)</li><li>[https://securingtomorrow.mcafee.com/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/](https://securingtomorrow.mcafee.com/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/)</li><li>[https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/](https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/)</li></ul>  |
| Author               | Florian Roth, Michael Haag |


## Detection Rules

### Sigma rule

```
title: Activity Related to NTDS.dit Domain Hash Retrieval
status: experimental
description: Detects suspicious commands that could be related to activity that uses volume shadow copy to steal and retrieve hashes from the NTDS.dit file remotely
author: Florian Roth, Michael Haag
references:
    - https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/
    - https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/
    - https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM)/
    - https://securingtomorrow.mcafee.com/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/
    - https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - vssadmin.exe Delete Shadows
            - 'vssadmin create shadow /for=C:'
            - copy \\?\GLOBALROOT\Device\\*\windows\ntds\ntds.dit
            - copy \\?\GLOBALROOT\Device\\*\config\SAM
            - 'vssadmin delete shadows /for=C:'
            - 'reg SAVE HKLM\SYSTEM '
            - esentutl.exe /y /vss *\ntds.dit*
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: high

```





### es-qs
    
```
CommandLine.keyword:(vssadmin.exe\\ Delete\\ Shadows vssadmin\\ create\\ shadow\\ \\/for\\=C\\: copy\\ \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\windows\\\\ntds\\\\ntds.dit copy\\ \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\config\\\\SAM vssadmin\\ delete\\ shadows\\ \\/for\\=C\\: reg\\ SAVE\\ HKLM\\\\SYSTEM\\  esentutl.exe\\ \\/y\\ \\/vss\\ *\\\\ntds.dit*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Activity-Related-to-NTDS.dit-Domain-Hash-Retrieval <<EOF\n{\n  "metadata": {\n    "title": "Activity Related to NTDS.dit Domain Hash Retrieval",\n    "description": "Detects suspicious commands that could be related to activity that uses volume shadow copy to steal and retrieve hashes from the NTDS.dit file remotely",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "CommandLine.keyword:(vssadmin.exe\\\\ Delete\\\\ Shadows vssadmin\\\\ create\\\\ shadow\\\\ \\\\/for\\\\=C\\\\: copy\\\\ \\\\\\\\?\\\\\\\\GLOBALROOT\\\\\\\\Device\\\\\\\\*\\\\\\\\windows\\\\\\\\ntds\\\\\\\\ntds.dit copy\\\\ \\\\\\\\?\\\\\\\\GLOBALROOT\\\\\\\\Device\\\\\\\\*\\\\\\\\config\\\\\\\\SAM vssadmin\\\\ delete\\\\ shadows\\\\ \\\\/for\\\\=C\\\\: reg\\\\ SAVE\\\\ HKLM\\\\\\\\SYSTEM\\\\  esentutl.exe\\\\ \\\\/y\\\\ \\\\/vss\\\\ *\\\\\\\\ntds.dit*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(vssadmin.exe\\\\ Delete\\\\ Shadows vssadmin\\\\ create\\\\ shadow\\\\ \\\\/for\\\\=C\\\\: copy\\\\ \\\\\\\\?\\\\\\\\GLOBALROOT\\\\\\\\Device\\\\\\\\*\\\\\\\\windows\\\\\\\\ntds\\\\\\\\ntds.dit copy\\\\ \\\\\\\\?\\\\\\\\GLOBALROOT\\\\\\\\Device\\\\\\\\*\\\\\\\\config\\\\\\\\SAM vssadmin\\\\ delete\\\\ shadows\\\\ \\\\/for\\\\=C\\\\: reg\\\\ SAVE\\\\ HKLM\\\\\\\\SYSTEM\\\\  esentutl.exe\\\\ \\\\/y\\\\ \\\\/vss\\\\ *\\\\\\\\ntds.dit*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Activity Related to NTDS.dit Domain Hash Retrieval\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("vssadmin.exe Delete Shadows" "vssadmin create shadow \\/for=C\\:" "copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\windows\\\\ntds\\\\ntds.dit" "copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\config\\\\SAM" "vssadmin delete shadows \\/for=C\\:" "reg SAVE HKLM\\\\SYSTEM " "esentutl.exe \\/y \\/vss *\\\\ntds.dit*")
```


### splunk
    
```
(CommandLine="vssadmin.exe Delete Shadows" OR CommandLine="vssadmin create shadow /for=C:" OR CommandLine="copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\windows\\\\ntds\\\\ntds.dit" OR CommandLine="copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\config\\\\SAM" OR CommandLine="vssadmin delete shadows /for=C:" OR CommandLine="reg SAVE HKLM\\\\SYSTEM " OR CommandLine="esentutl.exe /y /vss *\\\\ntds.dit*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["vssadmin.exe Delete Shadows", "vssadmin create shadow /for=C:", "copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\windows\\\\ntds\\\\ntds.dit", "copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\config\\\\SAM", "vssadmin delete shadows /for=C:", "reg SAVE HKLM\\\\SYSTEM ", "esentutl.exe /y /vss *\\\\ntds.dit*"]
```


### grep
    
```
grep -P '^(?:.*vssadmin\\.exe Delete Shadows|.*vssadmin create shadow /for=C:|.*copy \\\\?\\GLOBALROOT\\Device\\\\.*\\windows\\ntds\\ntds\\.dit|.*copy \\\\?\\GLOBALROOT\\Device\\\\.*\\config\\SAM|.*vssadmin delete shadows /for=C:|.*reg SAVE HKLM\\SYSTEM |.*esentutl\\.exe /y /vss .*\\ntds\\.dit.*)'
```



