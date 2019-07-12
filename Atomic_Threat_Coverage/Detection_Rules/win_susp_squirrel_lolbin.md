| Title                | Squirrel Lolbin                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Possible Squirrel Packages Manager as Lolbin                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>1Clipboard</li><li>Beaker Browser</li><li>Caret</li><li>Collectie</li><li>Discord</li><li>Figma</li><li>Flow</li><li>Ghost</li><li>GitHub Desktop</li><li>GitKraken</li><li>Hyper</li><li>Insomnia</li><li>JIBO</li><li>Kap</li><li>Kitematic</li><li>Now Desktop</li><li>Postman</li><li>PostmanCanary</li><li>Rambox</li><li>Simplenote</li><li>Skype</li><li>Slack</li><li>SourceTree</li><li>Stride</li><li>Svgsus</li><li>WebTorrent</li><li>WhatsApp</li><li>WordPress.com</li><li>atom</li><li>gitkraken</li><li>slack</li><li>teams</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/](http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/)</li></ul>  |
| Author               | Karneades / Markus Neis |


## Detection Rules

### Sigma rule

```
title: Squirrel Lolbin
status: experimental
description: Detects Possible Squirrel Packages Manager as Lolbin 
references:
    - http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/  
tags:
    - attack.execution     
author: Karneades / Markus Neis
falsepositives:
    - 1Clipboard
    - Beaker Browser
    - Caret
    - Collectie
    - Discord
    - Figma
    - Flow
    - Ghost
    - GitHub Desktop
    - GitKraken
    - Hyper
    - Insomnia
    - JIBO
    - Kap
    - Kitematic
    - Now Desktop
    - Postman
    - PostmanCanary
    - Rambox
    - Simplenote
    - Skype
    - Slack
    - SourceTree
    - Stride
    - Svgsus
    - WebTorrent
    - WhatsApp
    - WordPress.com
    - atom
    - gitkraken
    - slack
    - teams
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\update.exe'                           # Check if folder Name matches executed binary  \\(?P<first>[^\\]*)\\Update.*Start.{2}(?P<second>\1)\.exe (example: https://regex101.com/r/SGSQGz/2)
        CommandLine:
            - '*--processStart*.exe*'
            - '*–createShortcut*.exe*'
    condition: selection 
  
    
```





### es-qs
    
```
(Image.keyword:(*\\\\update.exe) AND CommandLine.keyword:(*\\-\\-processStart*.exe* *\xe2\x80\x93createShortcut*.exe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Squirrel-Lolbin <<EOF\n{\n  "metadata": {\n    "title": "Squirrel Lolbin",\n    "description": "Detects Possible Squirrel Packages Manager as Lolbin",\n    "tags": [\n      "attack.execution"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\update.exe) AND CommandLine.keyword:(*\\\\-\\\\-processStart*.exe* *\\u2013createShortcut*.exe*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\update.exe) AND CommandLine.keyword:(*\\\\-\\\\-processStart*.exe* *\\u2013createShortcut*.exe*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Squirrel Lolbin\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:("*\\\\update.exe") AND CommandLine:("*\\-\\-processStart*.exe*" "*\xe2\x80\x93createShortcut*.exe*"))
```


### splunk
    
```
((Image="*\\\\update.exe") (CommandLine="*--processStart*.exe*" OR CommandLine="*\xe2\x80\x93createShortcut*.exe*"))
```


### logpoint
    
```
(Image IN ["*\\\\update.exe"] CommandLine IN ["*--processStart*.exe*", "*\xe2\x80\x93createShortcut*.exe*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\update\\.exe))(?=.*(?:.*.*--processStart.*\\.exe.*|.*.*\xe2\x80\x93createShortcut.*\\.exe.*)))'
```



