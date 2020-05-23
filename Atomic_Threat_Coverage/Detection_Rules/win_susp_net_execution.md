| Title                    | Net.exe Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects execution of Net.exe, whether suspicious or benign. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li><li>[T1049: System Network Connections Discovery](https://attack.mitre.org/techniques/T1049)</li><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1135: Network Share Discovery](https://attack.mitre.org/techniques/T1135)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li><li>[T1049: System Network Connections Discovery](../Triggers/T1049.md)</li><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li><li>[T1135: Network Share Discovery](../Triggers/T1135.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/4d2e7fc1-af0b-4915-89aa-03d25ba7805e.html](https://eqllib.readthedocs.io/en/latest/analytics/4d2e7fc1-af0b-4915-89aa-03d25ba7805e.html)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/e61f557c-a9d0-4c25-ab5b-bbc46bb24deb.html](https://eqllib.readthedocs.io/en/latest/analytics/e61f557c-a9d0-4c25-ab5b-bbc46bb24deb.html)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/9b3dd402-891c-4c4d-a662-28947168ce61.html](https://eqllib.readthedocs.io/en/latest/analytics/9b3dd402-891c-4c4d-a662-28947168ce61.html)</li></ul>  |
| **Author**               | Michael Haag, Mark Woan (improvements), James Pemberton / @4A616D6573 / oscd.community (improvements) |
| Other Tags           | <ul><li>attack.s0039</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Net.exe Execution
id: 183e7ea8-ac4b-4c23-9aec-b3dac4e401ac
status: experimental
description: Detects execution of Net.exe, whether suspicious or benign.
references:
    - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
    - https://eqllib.readthedocs.io/en/latest/analytics/4d2e7fc1-af0b-4915-89aa-03d25ba7805e.html
    - https://eqllib.readthedocs.io/en/latest/analytics/e61f557c-a9d0-4c25-ab5b-bbc46bb24deb.html
    - https://eqllib.readthedocs.io/en/latest/analytics/9b3dd402-891c-4c4d-a662-28947168ce61.html
author: Michael Haag, Mark Woan (improvements), James Pemberton / @4A616D6573 / oscd.community (improvements)
date: 2019/01/16
tags:
    - attack.s0039
    - attack.t1027
    - attack.t1049
    - attack.t1077
    - attack.t1135
    - attack.lateral_movement
    - attack.discovery
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\net.exe'
            - '*\net1.exe'
    cmdline:
        CommandLine:
            - '* group*'
            - '* localgroup*'
            - '* user*'
            - '* view*'
            - '* share'
            - '* accounts*'
            - '* use*'
            - '* stop *'
    condition: selection and cmdline
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.
level: low

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\net.exe" -or $_.message -match "Image.*.*\\\\net1.exe") -and ($_.message -match "CommandLine.*.* group.*" -or $_.message -match "CommandLine.*.* localgroup.*" -or $_.message -match "CommandLine.*.* user.*" -or $_.message -match "CommandLine.*.* view.*" -or $_.message -match "CommandLine.*.* share" -or $_.message -match "CommandLine.*.* accounts.*" -or $_.message -match "CommandLine.*.* use.*" -or $_.message -match "CommandLine.*.* stop .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:(*\\ group* OR *\\ localgroup* OR *\\ user* OR *\\ view* OR *\\ share OR *\\ accounts* OR *\\ use* OR *\\ stop\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/183e7ea8-ac4b-4c23-9aec-b3dac4e401ac <<EOF\n{\n  "metadata": {\n    "title": "Net.exe Execution",\n    "description": "Detects execution of Net.exe, whether suspicious or benign.",\n    "tags": [\n      "attack.s0039",\n      "attack.t1027",\n      "attack.t1049",\n      "attack.t1077",\n      "attack.t1135",\n      "attack.lateral_movement",\n      "attack.discovery",\n      "attack.defense_evasion"\n    ],\n    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:(*\\\\ group* OR *\\\\ localgroup* OR *\\\\ user* OR *\\\\ view* OR *\\\\ share OR *\\\\ accounts* OR *\\\\ use* OR *\\\\ stop\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND winlog.event_data.CommandLine.keyword:(*\\\\ group* OR *\\\\ localgroup* OR *\\\\ user* OR *\\\\ view* OR *\\\\ share OR *\\\\ accounts* OR *\\\\ use* OR *\\\\ stop\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Net.exe Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     ComputerName = {{_source.ComputerName}}\\n             User = {{_source.User}}\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\net.exe *\\\\net1.exe) AND CommandLine.keyword:(* group* * localgroup* * user* * view* * share * accounts* * use* * stop *))
```


### splunk
    
```
((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") (CommandLine="* group*" OR CommandLine="* localgroup*" OR CommandLine="* user*" OR CommandLine="* view*" OR CommandLine="* share" OR CommandLine="* accounts*" OR CommandLine="* use*" OR CommandLine="* stop *")) | table ComputerName,User,CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image IN ["*\\\\net.exe", "*\\\\net1.exe"] CommandLine IN ["* group*", "* localgroup*", "* user*", "* view*", "* share", "* accounts*", "* use*", "* stop *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*(?:.*.* group.*|.*.* localgroup.*|.*.* user.*|.*.* view.*|.*.* share|.*.* accounts.*|.*.* use.*|.*.* stop .*)))'
```



