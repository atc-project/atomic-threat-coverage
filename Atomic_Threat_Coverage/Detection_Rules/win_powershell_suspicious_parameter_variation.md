| Title                    | Suspicious PowerShell Parameter Substring       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious PowerShell invocation with a parameter substring |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration tests</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier](http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier)</li></ul>  |
| **Author**               | Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix) |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Parameter Substring
id: 36210e0d-5b19-485d-a087-c096088885f0
status: experimental
description: Detects suspicious PowerShell invocation with a parameter substring
references:
    - http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier
tags:
    - attack.execution
    - attack.t1086 # an old one
    - attack.t1059.001
author: Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
date: 2019/01/16
modified: 2020/07/14
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\Powershell.exe'
        CommandLine|contains:
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





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\Powershell.exe") -and ($_.message -match "CommandLine.*.* -windowstyle h .*" -or $_.message -match "CommandLine.*.* -windowstyl h.*" -or $_.message -match "CommandLine.*.* -windowsty h.*" -or $_.message -match "CommandLine.*.* -windowst h.*" -or $_.message -match "CommandLine.*.* -windows h.*" -or $_.message -match "CommandLine.*.* -windo h.*" -or $_.message -match "CommandLine.*.* -wind h.*" -or $_.message -match "CommandLine.*.* -win h.*" -or $_.message -match "CommandLine.*.* -wi h.*" -or $_.message -match "CommandLine.*.* -win h .*" -or $_.message -match "CommandLine.*.* -win hi .*" -or $_.message -match "CommandLine.*.* -win hid .*" -or $_.message -match "CommandLine.*.* -win hidd .*" -or $_.message -match "CommandLine.*.* -win hidde .*" -or $_.message -match "CommandLine.*.* -NoPr .*" -or $_.message -match "CommandLine.*.* -NoPro .*" -or $_.message -match "CommandLine.*.* -NoProf .*" -or $_.message -match "CommandLine.*.* -NoProfi .*" -or $_.message -match "CommandLine.*.* -NoProfil .*" -or $_.message -match "CommandLine.*.* -nonin .*" -or $_.message -match "CommandLine.*.* -nonint .*" -or $_.message -match "CommandLine.*.* -noninte .*" -or $_.message -match "CommandLine.*.* -noninter .*" -or $_.message -match "CommandLine.*.* -nonintera .*" -or $_.message -match "CommandLine.*.* -noninterac .*" -or $_.message -match "CommandLine.*.* -noninteract .*" -or $_.message -match "CommandLine.*.* -noninteracti .*" -or $_.message -match "CommandLine.*.* -noninteractiv .*" -or $_.message -match "CommandLine.*.* -ec .*" -or $_.message -match "CommandLine.*.* -encodedComman .*" -or $_.message -match "CommandLine.*.* -encodedComma .*" -or $_.message -match "CommandLine.*.* -encodedComm .*" -or $_.message -match "CommandLine.*.* -encodedCom .*" -or $_.message -match "CommandLine.*.* -encodedCo .*" -or $_.message -match "CommandLine.*.* -encodedC .*" -or $_.message -match "CommandLine.*.* -encoded .*" -or $_.message -match "CommandLine.*.* -encode .*" -or $_.message -match "CommandLine.*.* -encod .*" -or $_.message -match "CommandLine.*.* -enco .*" -or $_.message -match "CommandLine.*.* -en .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\\\Powershell.exe) AND winlog.event_data.CommandLine.keyword:(*\\ \\-windowstyle\\ h\\ * OR *\\ \\-windowstyl\\ h* OR *\\ \\-windowsty\\ h* OR *\\ \\-windowst\\ h* OR *\\ \\-windows\\ h* OR *\\ \\-windo\\ h* OR *\\ \\-wind\\ h* OR *\\ \\-win\\ h* OR *\\ \\-wi\\ h* OR *\\ \\-win\\ h\\ * OR *\\ \\-win\\ hi\\ * OR *\\ \\-win\\ hid\\ * OR *\\ \\-win\\ hidd\\ * OR *\\ \\-win\\ hidde\\ * OR *\\ \\-NoPr\\ * OR *\\ \\-NoPro\\ * OR *\\ \\-NoProf\\ * OR *\\ \\-NoProfi\\ * OR *\\ \\-NoProfil\\ * OR *\\ \\-nonin\\ * OR *\\ \\-nonint\\ * OR *\\ \\-noninte\\ * OR *\\ \\-noninter\\ * OR *\\ \\-nonintera\\ * OR *\\ \\-noninterac\\ * OR *\\ \\-noninteract\\ * OR *\\ \\-noninteracti\\ * OR *\\ \\-noninteractiv\\ * OR *\\ \\-ec\\ * OR *\\ \\-encodedComman\\ * OR *\\ \\-encodedComma\\ * OR *\\ \\-encodedComm\\ * OR *\\ \\-encodedCom\\ * OR *\\ \\-encodedCo\\ * OR *\\ \\-encodedC\\ * OR *\\ \\-encoded\\ * OR *\\ \\-encode\\ * OR *\\ \\-encod\\ * OR *\\ \\-enco\\ * OR *\\ \\-en\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/36210e0d-5b19-485d-a087-c096088885f0 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PowerShell Parameter Substring",\n    "description": "Detects suspicious PowerShell invocation with a parameter substring",\n    "tags": [\n      "attack.execution",\n      "attack.t1086",\n      "attack.t1059.001"\n    ],\n    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\Powershell.exe) AND winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-windowstyle\\\\ h\\\\ * OR *\\\\ \\\\-windowstyl\\\\ h* OR *\\\\ \\\\-windowsty\\\\ h* OR *\\\\ \\\\-windowst\\\\ h* OR *\\\\ \\\\-windows\\\\ h* OR *\\\\ \\\\-windo\\\\ h* OR *\\\\ \\\\-wind\\\\ h* OR *\\\\ \\\\-win\\\\ h* OR *\\\\ \\\\-wi\\\\ h* OR *\\\\ \\\\-win\\\\ h\\\\ * OR *\\\\ \\\\-win\\\\ hi\\\\ * OR *\\\\ \\\\-win\\\\ hid\\\\ * OR *\\\\ \\\\-win\\\\ hidd\\\\ * OR *\\\\ \\\\-win\\\\ hidde\\\\ * OR *\\\\ \\\\-NoPr\\\\ * OR *\\\\ \\\\-NoPro\\\\ * OR *\\\\ \\\\-NoProf\\\\ * OR *\\\\ \\\\-NoProfi\\\\ * OR *\\\\ \\\\-NoProfil\\\\ * OR *\\\\ \\\\-nonin\\\\ * OR *\\\\ \\\\-nonint\\\\ * OR *\\\\ \\\\-noninte\\\\ * OR *\\\\ \\\\-noninter\\\\ * OR *\\\\ \\\\-nonintera\\\\ * OR *\\\\ \\\\-noninterac\\\\ * OR *\\\\ \\\\-noninteract\\\\ * OR *\\\\ \\\\-noninteracti\\\\ * OR *\\\\ \\\\-noninteractiv\\\\ * OR *\\\\ \\\\-ec\\\\ * OR *\\\\ \\\\-encodedComman\\\\ * OR *\\\\ \\\\-encodedComma\\\\ * OR *\\\\ \\\\-encodedComm\\\\ * OR *\\\\ \\\\-encodedCom\\\\ * OR *\\\\ \\\\-encodedCo\\\\ * OR *\\\\ \\\\-encodedC\\\\ * OR *\\\\ \\\\-encoded\\\\ * OR *\\\\ \\\\-encode\\\\ * OR *\\\\ \\\\-encod\\\\ * OR *\\\\ \\\\-enco\\\\ * OR *\\\\ \\\\-en\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\Powershell.exe) AND winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-windowstyle\\\\ h\\\\ * OR *\\\\ \\\\-windowstyl\\\\ h* OR *\\\\ \\\\-windowsty\\\\ h* OR *\\\\ \\\\-windowst\\\\ h* OR *\\\\ \\\\-windows\\\\ h* OR *\\\\ \\\\-windo\\\\ h* OR *\\\\ \\\\-wind\\\\ h* OR *\\\\ \\\\-win\\\\ h* OR *\\\\ \\\\-wi\\\\ h* OR *\\\\ \\\\-win\\\\ h\\\\ * OR *\\\\ \\\\-win\\\\ hi\\\\ * OR *\\\\ \\\\-win\\\\ hid\\\\ * OR *\\\\ \\\\-win\\\\ hidd\\\\ * OR *\\\\ \\\\-win\\\\ hidde\\\\ * OR *\\\\ \\\\-NoPr\\\\ * OR *\\\\ \\\\-NoPro\\\\ * OR *\\\\ \\\\-NoProf\\\\ * OR *\\\\ \\\\-NoProfi\\\\ * OR *\\\\ \\\\-NoProfil\\\\ * OR *\\\\ \\\\-nonin\\\\ * OR *\\\\ \\\\-nonint\\\\ * OR *\\\\ \\\\-noninte\\\\ * OR *\\\\ \\\\-noninter\\\\ * OR *\\\\ \\\\-nonintera\\\\ * OR *\\\\ \\\\-noninterac\\\\ * OR *\\\\ \\\\-noninteract\\\\ * OR *\\\\ \\\\-noninteracti\\\\ * OR *\\\\ \\\\-noninteractiv\\\\ * OR *\\\\ \\\\-ec\\\\ * OR *\\\\ \\\\-encodedComman\\\\ * OR *\\\\ \\\\-encodedComma\\\\ * OR *\\\\ \\\\-encodedComm\\\\ * OR *\\\\ \\\\-encodedCom\\\\ * OR *\\\\ \\\\-encodedCo\\\\ * OR *\\\\ \\\\-encodedC\\\\ * OR *\\\\ \\\\-encoded\\\\ * OR *\\\\ \\\\-encode\\\\ * OR *\\\\ \\\\-encod\\\\ * OR *\\\\ \\\\-enco\\\\ * OR *\\\\ \\\\-en\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PowerShell Parameter Substring\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\Powershell.exe) AND CommandLine.keyword:(* \\-windowstyle h * * \\-windowstyl h* * \\-windowsty h* * \\-windowst h* * \\-windows h* * \\-windo h* * \\-wind h* * \\-win h* * \\-wi h* * \\-win h * * \\-win hi * * \\-win hid * * \\-win hidd * * \\-win hidde * * \\-NoPr * * \\-NoPro * * \\-NoProf * * \\-NoProfi * * \\-NoProfil * * \\-nonin * * \\-nonint * * \\-noninte * * \\-noninter * * \\-nonintera * * \\-noninterac * * \\-noninteract * * \\-noninteracti * * \\-noninteractiv * * \\-ec * * \\-encodedComman * * \\-encodedComma * * \\-encodedComm * * \\-encodedCom * * \\-encodedCo * * \\-encodedC * * \\-encoded * * \\-encode * * \\-encod * * \\-enco * * \\-en *))
```


### splunk
    
```
((Image="*\\\\Powershell.exe") (CommandLine="* -windowstyle h *" OR CommandLine="* -windowstyl h*" OR CommandLine="* -windowsty h*" OR CommandLine="* -windowst h*" OR CommandLine="* -windows h*" OR CommandLine="* -windo h*" OR CommandLine="* -wind h*" OR CommandLine="* -win h*" OR CommandLine="* -wi h*" OR CommandLine="* -win h *" OR CommandLine="* -win hi *" OR CommandLine="* -win hid *" OR CommandLine="* -win hidd *" OR CommandLine="* -win hidde *" OR CommandLine="* -NoPr *" OR CommandLine="* -NoPro *" OR CommandLine="* -NoProf *" OR CommandLine="* -NoProfi *" OR CommandLine="* -NoProfil *" OR CommandLine="* -nonin *" OR CommandLine="* -nonint *" OR CommandLine="* -noninte *" OR CommandLine="* -noninter *" OR CommandLine="* -nonintera *" OR CommandLine="* -noninterac *" OR CommandLine="* -noninteract *" OR CommandLine="* -noninteracti *" OR CommandLine="* -noninteractiv *" OR CommandLine="* -ec *" OR CommandLine="* -encodedComman *" OR CommandLine="* -encodedComma *" OR CommandLine="* -encodedComm *" OR CommandLine="* -encodedCom *" OR CommandLine="* -encodedCo *" OR CommandLine="* -encodedC *" OR CommandLine="* -encoded *" OR CommandLine="* -encode *" OR CommandLine="* -encod *" OR CommandLine="* -enco *" OR CommandLine="* -en *"))
```


### logpoint
    
```
(Image IN ["*\\\\Powershell.exe"] CommandLine IN ["* -windowstyle h *", "* -windowstyl h*", "* -windowsty h*", "* -windowst h*", "* -windows h*", "* -windo h*", "* -wind h*", "* -win h*", "* -wi h*", "* -win h *", "* -win hi *", "* -win hid *", "* -win hidd *", "* -win hidde *", "* -NoPr *", "* -NoPro *", "* -NoProf *", "* -NoProfi *", "* -NoProfil *", "* -nonin *", "* -nonint *", "* -noninte *", "* -noninter *", "* -nonintera *", "* -noninterac *", "* -noninteract *", "* -noninteracti *", "* -noninteractiv *", "* -ec *", "* -encodedComman *", "* -encodedComma *", "* -encodedComm *", "* -encodedCom *", "* -encodedCo *", "* -encodedC *", "* -encoded *", "* -encode *", "* -encod *", "* -enco *", "* -en *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\Powershell\\.exe))(?=.*(?:.*.* -windowstyle h .*|.*.* -windowstyl h.*|.*.* -windowsty h.*|.*.* -windowst h.*|.*.* -windows h.*|.*.* -windo h.*|.*.* -wind h.*|.*.* -win h.*|.*.* -wi h.*|.*.* -win h .*|.*.* -win hi .*|.*.* -win hid .*|.*.* -win hidd .*|.*.* -win hidde .*|.*.* -NoPr .*|.*.* -NoPro .*|.*.* -NoProf .*|.*.* -NoProfi .*|.*.* -NoProfil .*|.*.* -nonin .*|.*.* -nonint .*|.*.* -noninte .*|.*.* -noninter .*|.*.* -nonintera .*|.*.* -noninterac .*|.*.* -noninteract .*|.*.* -noninteracti .*|.*.* -noninteractiv .*|.*.* -ec .*|.*.* -encodedComman .*|.*.* -encodedComma .*|.*.* -encodedComm .*|.*.* -encodedCom .*|.*.* -encodedCo .*|.*.* -encodedC .*|.*.* -encoded .*|.*.* -encode .*|.*.* -encod .*|.*.* -enco .*|.*.* -en .*)))'
```



