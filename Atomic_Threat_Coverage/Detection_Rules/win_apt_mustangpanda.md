| Title                    | Mustang Panda Dropper       |
|:-------------------------|:------------------|
| **Description**          | Detects specific process parameters as used by Mustang Panda droppers |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/](https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/)</li><li>[https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/](https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/)</li><li>[https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations](https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Mustang Panda Dropper
id: 2d87d610-d760-45ee-a7e6-7a6f2a65de00
status: experimental
description: Detects specific process parameters as used by Mustang Panda droppers
author: Florian Roth
date: 2019/10/30
references:
    - https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/
    - https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/
    - https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: 
            - '*Temp\wtask.exe /create*'
            - '*%windir:~-3,1%%PUBLIC:~-9,1%*'
            - '*/E:vbscript * C:\Users\*.txt" /F'
            - '*/tn "Security Script *'
            - '*%windir:~-1,1%*'
    selection2:
        Image:
            - '*Temp\winwsh.exe'
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unlikely
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*Temp\\\\wtask.exe /create.*" -or $_.message -match "CommandLine.*.*%windir:~-3,1%%PUBLIC:~-9,1%.*" -or $_.message -match "CommandLine.*.*/E:vbscript .* C:\\\\Users\\\\.*.txt\\" /F" -or $_.message -match "CommandLine.*.*/tn \\"Security Script .*" -or $_.message -match "CommandLine.*.*%windir:~-1,1%.*") -or ($_.message -match "Image.*.*Temp\\\\winwsh.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*Temp\\\\wtask.exe\\ \\/create* OR *%windir\\:\\~\\-3,1%%PUBLIC\\:\\~\\-9,1%* OR *\\/E\\:vbscript\\ *\\ C\\:\\\\Users\\*.txt\\"\\ \\/F OR *\\/tn\\ \\"Security\\ Script\\ * OR *%windir\\:\\~\\-1,1%*) OR winlog.event_data.Image.keyword:(*Temp\\\\winwsh.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/2d87d610-d760-45ee-a7e6-7a6f2a65de00 <<EOF\n{\n  "metadata": {\n    "title": "Mustang Panda Dropper",\n    "description": "Detects specific process parameters as used by Mustang Panda droppers",\n    "tags": "",\n    "query": "(winlog.event_data.CommandLine.keyword:(*Temp\\\\\\\\wtask.exe\\\\ \\\\/create* OR *%windir\\\\:\\\\~\\\\-3,1%%PUBLIC\\\\:\\\\~\\\\-9,1%* OR *\\\\/E\\\\:vbscript\\\\ *\\\\ C\\\\:\\\\\\\\Users\\\\*.txt\\\\\\"\\\\ \\\\/F OR *\\\\/tn\\\\ \\\\\\"Security\\\\ Script\\\\ * OR *%windir\\\\:\\\\~\\\\-1,1%*) OR winlog.event_data.Image.keyword:(*Temp\\\\\\\\winwsh.exe))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:(*Temp\\\\\\\\wtask.exe\\\\ \\\\/create* OR *%windir\\\\:\\\\~\\\\-3,1%%PUBLIC\\\\:\\\\~\\\\-9,1%* OR *\\\\/E\\\\:vbscript\\\\ *\\\\ C\\\\:\\\\\\\\Users\\\\*.txt\\\\\\"\\\\ \\\\/F OR *\\\\/tn\\\\ \\\\\\"Security\\\\ Script\\\\ * OR *%windir\\\\:\\\\~\\\\-1,1%*) OR winlog.event_data.Image.keyword:(*Temp\\\\\\\\winwsh.exe))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mustang Panda Dropper\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(*Temp\\\\wtask.exe \\/create* *%windir\\:\\~\\-3,1%%PUBLIC\\:\\~\\-9,1%* *\\/E\\:vbscript * C\\:\\\\Users\\*.txt\\" \\/F *\\/tn \\"Security Script * *%windir\\:\\~\\-1,1%*) OR Image.keyword:(*Temp\\\\winwsh.exe))
```


### splunk
    
```
((CommandLine="*Temp\\\\wtask.exe /create*" OR CommandLine="*%windir:~-3,1%%PUBLIC:~-9,1%*" OR CommandLine="*/E:vbscript * C:\\\\Users\\*.txt\\" /F" OR CommandLine="*/tn \\"Security Script *" OR CommandLine="*%windir:~-1,1%*") OR (Image="*Temp\\\\winwsh.exe")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(CommandLine IN ["*Temp\\\\wtask.exe /create*", "*%windir:~-3,1%%PUBLIC:~-9,1%*", "*/E:vbscript * C:\\\\Users\\*.txt\\" /F", "*/tn \\"Security Script *", "*%windir:~-1,1%*"] OR Image IN ["*Temp\\\\winwsh.exe"])
```


### grep
    
```
grep -P \'^(?:.*(?:.*(?:.*.*Temp\\wtask\\.exe /create.*|.*.*%windir:~-3,1%%PUBLIC:~-9,1%.*|.*.*/E:vbscript .* C:\\Users\\.*\\.txt" /F|.*.*/tn "Security Script .*|.*.*%windir:~-1,1%.*)|.*(?:.*.*Temp\\winwsh\\.exe)))\'
```



