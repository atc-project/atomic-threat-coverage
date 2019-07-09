| Title                | Suspicious PowerShell Parameter Substring                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation with a parameter substring                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier](http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier)</li></ul>  |
| Author               | Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix) |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Parameter Substring
status: experimental
description: Detects suspicious PowerShell invocation with a parameter substring
references:
    - http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\Powershell.exe'
        CommandLine:
            - ' -windowstyle h '
            - ' -windowstyl h'
            - ' -windowsty h'
            - ' -windowst h'
            - ' -windows h'
            - ' -windo h'
            - ' -wind h'
            - ' -win h'
            - ' -wi h'
            - ' -win h '
            - ' -win hi '
            - ' -win hid '
            - ' -win hidd '
            - ' -win hidde '
            - ' -NoPr '
            - ' -NoPro '
            - ' -NoProf '
            - ' -NoProfi '
            - ' -NoProfil '
            - ' -nonin '
            - ' -nonint '
            - ' -noninte '
            - ' -noninter '
            - ' -nonintera '
            - ' -noninterac '
            - ' -noninteract '
            - ' -noninteracti '
            - ' -noninteractiv '
            - ' -ec '
            - ' -encodedComman '
            - ' -encodedComma '
            - ' -encodedComm '
            - ' -encodedCom '
            - ' -encodedCo '
            - ' -encodedC '
            - ' -encoded '
            - ' -encode '
            - ' -encod '
            - ' -enco '
            - ' -en '
    condition: selection
falsepositives:
    - Penetration tests
level: high

```





### es-qs
    
```
(Image.keyword:(*\\\\Powershell.exe) AND CommandLine:("\\ \\-windowstyle\\ h\\ " "\\ \\-windowstyl\\ h" "\\ \\-windowsty\\ h" "\\ \\-windowst\\ h" "\\ \\-windows\\ h" "\\ \\-windo\\ h" "\\ \\-wind\\ h" "\\ \\-win\\ h" "\\ \\-wi\\ h" "\\ \\-win\\ h\\ " "\\ \\-win\\ hi\\ " "\\ \\-win\\ hid\\ " "\\ \\-win\\ hidd\\ " "\\ \\-win\\ hidde\\ " "\\ \\-NoPr\\ " "\\ \\-NoPro\\ " "\\ \\-NoProf\\ " "\\ \\-NoProfi\\ " "\\ \\-NoProfil\\ " "\\ \\-nonin\\ " "\\ \\-nonint\\ " "\\ \\-noninte\\ " "\\ \\-noninter\\ " "\\ \\-nonintera\\ " "\\ \\-noninterac\\ " "\\ \\-noninteract\\ " "\\ \\-noninteracti\\ " "\\ \\-noninteractiv\\ " "\\ \\-ec\\ " "\\ \\-encodedComman\\ " "\\ \\-encodedComma\\ " "\\ \\-encodedComm\\ " "\\ \\-encodedCom\\ " "\\ \\-encodedCo\\ " "\\ \\-encodedC\\ " "\\ \\-encoded\\ " "\\ \\-encode\\ " "\\ \\-encod\\ " "\\ \\-enco\\ " "\\ \\-en\\ "))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-PowerShell-Parameter-Substring <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PowerShell Parameter Substring",\n    "description": "Detects suspicious PowerShell invocation with a parameter substring",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\Powershell.exe) AND CommandLine:(\\"\\\\ \\\\-windowstyle\\\\ h\\\\ \\" \\"\\\\ \\\\-windowstyl\\\\ h\\" \\"\\\\ \\\\-windowsty\\\\ h\\" \\"\\\\ \\\\-windowst\\\\ h\\" \\"\\\\ \\\\-windows\\\\ h\\" \\"\\\\ \\\\-windo\\\\ h\\" \\"\\\\ \\\\-wind\\\\ h\\" \\"\\\\ \\\\-win\\\\ h\\" \\"\\\\ \\\\-wi\\\\ h\\" \\"\\\\ \\\\-win\\\\ h\\\\ \\" \\"\\\\ \\\\-win\\\\ hi\\\\ \\" \\"\\\\ \\\\-win\\\\ hid\\\\ \\" \\"\\\\ \\\\-win\\\\ hidd\\\\ \\" \\"\\\\ \\\\-win\\\\ hidde\\\\ \\" \\"\\\\ \\\\-NoPr\\\\ \\" \\"\\\\ \\\\-NoPro\\\\ \\" \\"\\\\ \\\\-NoProf\\\\ \\" \\"\\\\ \\\\-NoProfi\\\\ \\" \\"\\\\ \\\\-NoProfil\\\\ \\" \\"\\\\ \\\\-nonin\\\\ \\" \\"\\\\ \\\\-nonint\\\\ \\" \\"\\\\ \\\\-noninte\\\\ \\" \\"\\\\ \\\\-noninter\\\\ \\" \\"\\\\ \\\\-nonintera\\\\ \\" \\"\\\\ \\\\-noninterac\\\\ \\" \\"\\\\ \\\\-noninteract\\\\ \\" \\"\\\\ \\\\-noninteracti\\\\ \\" \\"\\\\ \\\\-noninteractiv\\\\ \\" \\"\\\\ \\\\-ec\\\\ \\" \\"\\\\ \\\\-encodedComman\\\\ \\" \\"\\\\ \\\\-encodedComma\\\\ \\" \\"\\\\ \\\\-encodedComm\\\\ \\" \\"\\\\ \\\\-encodedCom\\\\ \\" \\"\\\\ \\\\-encodedCo\\\\ \\" \\"\\\\ \\\\-encodedC\\\\ \\" \\"\\\\ \\\\-encoded\\\\ \\" \\"\\\\ \\\\-encode\\\\ \\" \\"\\\\ \\\\-encod\\\\ \\" \\"\\\\ \\\\-enco\\\\ \\" \\"\\\\ \\\\-en\\\\ \\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\Powershell.exe) AND CommandLine:(\\"\\\\ \\\\-windowstyle\\\\ h\\\\ \\" \\"\\\\ \\\\-windowstyl\\\\ h\\" \\"\\\\ \\\\-windowsty\\\\ h\\" \\"\\\\ \\\\-windowst\\\\ h\\" \\"\\\\ \\\\-windows\\\\ h\\" \\"\\\\ \\\\-windo\\\\ h\\" \\"\\\\ \\\\-wind\\\\ h\\" \\"\\\\ \\\\-win\\\\ h\\" \\"\\\\ \\\\-wi\\\\ h\\" \\"\\\\ \\\\-win\\\\ h\\\\ \\" \\"\\\\ \\\\-win\\\\ hi\\\\ \\" \\"\\\\ \\\\-win\\\\ hid\\\\ \\" \\"\\\\ \\\\-win\\\\ hidd\\\\ \\" \\"\\\\ \\\\-win\\\\ hidde\\\\ \\" \\"\\\\ \\\\-NoPr\\\\ \\" \\"\\\\ \\\\-NoPro\\\\ \\" \\"\\\\ \\\\-NoProf\\\\ \\" \\"\\\\ \\\\-NoProfi\\\\ \\" \\"\\\\ \\\\-NoProfil\\\\ \\" \\"\\\\ \\\\-nonin\\\\ \\" \\"\\\\ \\\\-nonint\\\\ \\" \\"\\\\ \\\\-noninte\\\\ \\" \\"\\\\ \\\\-noninter\\\\ \\" \\"\\\\ \\\\-nonintera\\\\ \\" \\"\\\\ \\\\-noninterac\\\\ \\" \\"\\\\ \\\\-noninteract\\\\ \\" \\"\\\\ \\\\-noninteracti\\\\ \\" \\"\\\\ \\\\-noninteractiv\\\\ \\" \\"\\\\ \\\\-ec\\\\ \\" \\"\\\\ \\\\-encodedComman\\\\ \\" \\"\\\\ \\\\-encodedComma\\\\ \\" \\"\\\\ \\\\-encodedComm\\\\ \\" \\"\\\\ \\\\-encodedCom\\\\ \\" \\"\\\\ \\\\-encodedCo\\\\ \\" \\"\\\\ \\\\-encodedC\\\\ \\" \\"\\\\ \\\\-encoded\\\\ \\" \\"\\\\ \\\\-encode\\\\ \\" \\"\\\\ \\\\-encod\\\\ \\" \\"\\\\ \\\\-enco\\\\ \\" \\"\\\\ \\\\-en\\\\ \\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PowerShell Parameter Substring\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:("*\\\\Powershell.exe") AND CommandLine:(" \\-windowstyle h " " \\-windowstyl h" " \\-windowsty h" " \\-windowst h" " \\-windows h" " \\-windo h" " \\-wind h" " \\-win h" " \\-wi h" " \\-win h " " \\-win hi " " \\-win hid " " \\-win hidd " " \\-win hidde " " \\-NoPr " " \\-NoPro " " \\-NoProf " " \\-NoProfi " " \\-NoProfil " " \\-nonin " " \\-nonint " " \\-noninte " " \\-noninter " " \\-nonintera " " \\-noninterac " " \\-noninteract " " \\-noninteracti " " \\-noninteractiv " " \\-ec " " \\-encodedComman " " \\-encodedComma " " \\-encodedComm " " \\-encodedCom " " \\-encodedCo " " \\-encodedC " " \\-encoded " " \\-encode " " \\-encod " " \\-enco " " \\-en "))
```


### splunk
    
```
((Image="*\\\\Powershell.exe") (CommandLine=" -windowstyle h " OR CommandLine=" -windowstyl h" OR CommandLine=" -windowsty h" OR CommandLine=" -windowst h" OR CommandLine=" -windows h" OR CommandLine=" -windo h" OR CommandLine=" -wind h" OR CommandLine=" -win h" OR CommandLine=" -wi h" OR CommandLine=" -win h " OR CommandLine=" -win hi " OR CommandLine=" -win hid " OR CommandLine=" -win hidd " OR CommandLine=" -win hidde " OR CommandLine=" -NoPr " OR CommandLine=" -NoPro " OR CommandLine=" -NoProf " OR CommandLine=" -NoProfi " OR CommandLine=" -NoProfil " OR CommandLine=" -nonin " OR CommandLine=" -nonint " OR CommandLine=" -noninte " OR CommandLine=" -noninter " OR CommandLine=" -nonintera " OR CommandLine=" -noninterac " OR CommandLine=" -noninteract " OR CommandLine=" -noninteracti " OR CommandLine=" -noninteractiv " OR CommandLine=" -ec " OR CommandLine=" -encodedComman " OR CommandLine=" -encodedComma " OR CommandLine=" -encodedComm " OR CommandLine=" -encodedCom " OR CommandLine=" -encodedCo " OR CommandLine=" -encodedC " OR CommandLine=" -encoded " OR CommandLine=" -encode " OR CommandLine=" -encod " OR CommandLine=" -enco " OR CommandLine=" -en "))
```


### logpoint
    
```
(Image IN ["*\\\\Powershell.exe"] CommandLine IN [" -windowstyle h ", " -windowstyl h", " -windowsty h", " -windowst h", " -windows h", " -windo h", " -wind h", " -win h", " -wi h", " -win h ", " -win hi ", " -win hid ", " -win hidd ", " -win hidde ", " -NoPr ", " -NoPro ", " -NoProf ", " -NoProfi ", " -NoProfil ", " -nonin ", " -nonint ", " -noninte ", " -noninter ", " -nonintera ", " -noninterac ", " -noninteract ", " -noninteracti ", " -noninteractiv ", " -ec ", " -encodedComman ", " -encodedComma ", " -encodedComm ", " -encodedCom ", " -encodedCo ", " -encodedC ", " -encoded ", " -encode ", " -encod ", " -enco ", " -en "])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\Powershell\\.exe))(?=.*(?:.* -windowstyle h |.* -windowstyl h|.* -windowsty h|.* -windowst h|.* -windows h|.* -windo h|.* -wind h|.* -win h|.* -wi h|.* -win h |.* -win hi |.* -win hid |.* -win hidd |.* -win hidde |.* -NoPr |.* -NoPro |.* -NoProf |.* -NoProfi |.* -NoProfil |.* -nonin |.* -nonint |.* -noninte |.* -noninter |.* -nonintera |.* -noninterac |.* -noninteract |.* -noninteracti |.* -noninteractiv |.* -ec |.* -encodedComman |.* -encodedComma |.* -encodedComm |.* -encodedCom |.* -encodedCo |.* -encodedC |.* -encoded |.* -encode |.* -encod |.* -enco |.* -en )))'
```



