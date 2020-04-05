| Title                    | Bloodhound and Sharphound Hack Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects command line parameters used by Bloodhound and Sharphound hack tools |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other programs that use these command line option and accepts an 'All' parameter</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)</li><li>[https://github.com/BloodHoundAD/SharpHound](https://github.com/BloodHoundAD/SharpHound)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Bloodhound and Sharphound Hack Tool
id: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
description: Detects command line parameters used by Bloodhound and Sharphound hack tools
author: Florian Roth
references:
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/BloodHoundAD/SharpHound
date: 2019/12/20
modified: 2019/12/21
tags:
    - attack.discovery
    - attack.t1087
logsource:
    category: process_creation
    product: windows
detection:
    selection1: 
        Image|contains: 
            - '\Bloodhound.exe'
            - '\SharpHound.exe'
    selection2:
        CommandLine|contains: 
            - ' -CollectionMethod All '
            - '.exe -c All -d '
            - 'Invoke-Bloodhound'
            - 'Get-BloodHoundData'
    selection3:
        CommandLine|contains|all: 
            - ' -JsonFolder '
            - ' -ZipFileName '
    selection4:
        CommandLine|contains|all: 
            - ' DCOnly '
            - ' --NoSaveCache '
    condition: 1 of them
falsepositives:
    - Other programs that use these command line option and accepts an 'All' parameter
level: high


```





### es-qs
    
```
(Image.keyword:(*\\\\Bloodhound.exe* OR *\\\\SharpHound.exe*) OR CommandLine.keyword:(*\\ \\-CollectionMethod\\ All\\ * OR *.exe\\ \\-c\\ All\\ \\-d\\ * OR *Invoke\\-Bloodhound* OR *Get\\-BloodHoundData*) OR (CommandLine.keyword:*\\ \\-JsonFolder\\ * AND CommandLine.keyword:*\\ \\-ZipFileName\\ *) OR (CommandLine.keyword:*\\ DCOnly\\ * AND CommandLine.keyword:*\\ \\-\\-NoSaveCache\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f376c8a7-a2d0-4ddc-aa0c-16c17236d962 <<EOF\n{\n  "metadata": {\n    "title": "Bloodhound and Sharphound Hack Tool",\n    "description": "Detects command line parameters used by Bloodhound and Sharphound hack tools",\n    "tags": [\n      "attack.discovery",\n      "attack.t1087"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\Bloodhound.exe* OR *\\\\\\\\SharpHound.exe*) OR CommandLine.keyword:(*\\\\ \\\\-CollectionMethod\\\\ All\\\\ * OR *.exe\\\\ \\\\-c\\\\ All\\\\ \\\\-d\\\\ * OR *Invoke\\\\-Bloodhound* OR *Get\\\\-BloodHoundData*) OR (CommandLine.keyword:*\\\\ \\\\-JsonFolder\\\\ * AND CommandLine.keyword:*\\\\ \\\\-ZipFileName\\\\ *) OR (CommandLine.keyword:*\\\\ DCOnly\\\\ * AND CommandLine.keyword:*\\\\ \\\\-\\\\-NoSaveCache\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\Bloodhound.exe* OR *\\\\\\\\SharpHound.exe*) OR CommandLine.keyword:(*\\\\ \\\\-CollectionMethod\\\\ All\\\\ * OR *.exe\\\\ \\\\-c\\\\ All\\\\ \\\\-d\\\\ * OR *Invoke\\\\-Bloodhound* OR *Get\\\\-BloodHoundData*) OR (CommandLine.keyword:*\\\\ \\\\-JsonFolder\\\\ * AND CommandLine.keyword:*\\\\ \\\\-ZipFileName\\\\ *) OR (CommandLine.keyword:*\\\\ DCOnly\\\\ * AND CommandLine.keyword:*\\\\ \\\\-\\\\-NoSaveCache\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Bloodhound and Sharphound Hack Tool\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\Bloodhound.exe* *\\\\SharpHound.exe*) OR CommandLine.keyword:(* \\-CollectionMethod All * *.exe \\-c All \\-d * *Invoke\\-Bloodhound* *Get\\-BloodHoundData*) OR (CommandLine.keyword:* \\-JsonFolder * AND CommandLine.keyword:* \\-ZipFileName *) OR (CommandLine.keyword:* DCOnly * AND CommandLine.keyword:* \\-\\-NoSaveCache *))
```


### splunk
    
```
((Image="*\\\\Bloodhound.exe*" OR Image="*\\\\SharpHound.exe*") OR (CommandLine="* -CollectionMethod All *" OR CommandLine="*.exe -c All -d *" OR CommandLine="*Invoke-Bloodhound*" OR CommandLine="*Get-BloodHoundData*") OR (CommandLine="* -JsonFolder *" CommandLine="* -ZipFileName *") OR (CommandLine="* DCOnly *" CommandLine="* --NoSaveCache *"))
```


### logpoint
    
```
(event_id="1" (Image IN ["*\\\\Bloodhound.exe*", "*\\\\SharpHound.exe*"] OR CommandLine IN ["* -CollectionMethod All *", "*.exe -c All -d *", "*Invoke-Bloodhound*", "*Get-BloodHoundData*"] OR (CommandLine="* -JsonFolder *" CommandLine="* -ZipFileName *") OR (CommandLine="* DCOnly *" CommandLine="* --NoSaveCache *")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*\\Bloodhound\\.exe.*|.*.*\\SharpHound\\.exe.*)|.*(?:.*.* -CollectionMethod All .*|.*.*\\.exe -c All -d .*|.*.*Invoke-Bloodhound.*|.*.*Get-BloodHoundData.*)|.*(?:.*(?=.*.* -JsonFolder .*)(?=.*.* -ZipFileName .*))|.*(?:.*(?=.*.* DCOnly .*)(?=.*.* --NoSaveCache .*))))'
```



