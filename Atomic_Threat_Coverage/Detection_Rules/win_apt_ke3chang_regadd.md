| Title                    | Ke3chang Registry Key Modifications       |
|:-------------------------|:------------------|
| **Description**          | Detects Registry modifcations performaed by Ke3chang malware in campaigns running in 2019 and 2020 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1562.001: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562.001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1562.001: Disable or Modify Tools](../Triggers/T1562.001.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Will need to be looked for combinations of those processes</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.verfassungsschutz.de/embed/broschuere-2020-06-bfv-cyber-brief-2020-01.pdf](https://www.verfassungsschutz.de/embed/broschuere-2020-06-bfv-cyber-brief-2020-01.pdf)</li><li>[https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/](https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/)</li></ul>  |
| **Author**               | Markus Neis, Swisscom |
| Other Tags           | <ul><li>attack.g0004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Ke3chang Registry Key Modifications
id: 7b544661-69fc-419f-9a59-82ccc328f205
status: experimental
description: Detects Registry modifcations performaed by Ke3chang malware in campaigns running in 2019 and 2020
references:
    - https://www.verfassungsschutz.de/embed/broschuere-2020-06-bfv-cyber-brief-2020-01.pdf
    - https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
tags:
    - attack.g0004
    - attack.defense_evasion
    - attack.t1089 # an old one
    - attack.t1562.001
author: Markus Neis, Swisscom 
date: 2020/06/18
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        # Ke3chang and TidePool both modify the IEHarden registry key, as well as the following list of keys. 
        # Setting these registry keys is unique to the Ke3chang and TidePool malware families.
        # HKCU\Software\Microsoft\Internet Explorer\Main\Check_Associations
        # HKCU\Software\Microsoft\Internet Explorer\Main\DisableFirstRunCustomize
        # HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\IEharden
        CommandLine|contains:
            - '-Property DWORD -name DisableFirstRunCustomize -value 2 -Force'
            - '-Property String -name Check_Associations -value'
            - '-Property DWORD -name IEHarden -value 0 -Force'         
    condition: selection1
falsepositives:
    - Will need to be looked for combinations of those processes
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force.*" -or $_.message -match "CommandLine.*.*-Property String -name Check_Associations -value.*" -or $_.message -match "CommandLine.*.*-Property DWORD -name IEHarden -value 0 -Force.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\-Property\\ DWORD\\ \\-name\\ DisableFirstRunCustomize\\ \\-value\\ 2\\ \\-Force* OR *\\-Property\\ String\\ \\-name\\ Check_Associations\\ \\-value* OR *\\-Property\\ DWORD\\ \\-name\\ IEHarden\\ \\-value\\ 0\\ \\-Force*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/7b544661-69fc-419f-9a59-82ccc328f205 <<EOF\n{\n  "metadata": {\n    "title": "Ke3chang Registry Key Modifications",\n    "description": "Detects Registry modifcations performaed by Ke3chang malware in campaigns running in 2019 and 2020",\n    "tags": [\n      "attack.g0004",\n      "attack.defense_evasion",\n      "attack.t1089",\n      "attack.t1562.001"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*\\\\-Property\\\\ DWORD\\\\ \\\\-name\\\\ DisableFirstRunCustomize\\\\ \\\\-value\\\\ 2\\\\ \\\\-Force* OR *\\\\-Property\\\\ String\\\\ \\\\-name\\\\ Check_Associations\\\\ \\\\-value* OR *\\\\-Property\\\\ DWORD\\\\ \\\\-name\\\\ IEHarden\\\\ \\\\-value\\\\ 0\\\\ \\\\-Force*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\-Property\\\\ DWORD\\\\ \\\\-name\\\\ DisableFirstRunCustomize\\\\ \\\\-value\\\\ 2\\\\ \\\\-Force* OR *\\\\-Property\\\\ String\\\\ \\\\-name\\\\ Check_Associations\\\\ \\\\-value* OR *\\\\-Property\\\\ DWORD\\\\ \\\\-name\\\\ IEHarden\\\\ \\\\-value\\\\ 0\\\\ \\\\-Force*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Ke3chang Registry Key Modifications\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*\\-Property DWORD \\-name DisableFirstRunCustomize \\-value 2 \\-Force* *\\-Property String \\-name Check_Associations \\-value* *\\-Property DWORD \\-name IEHarden \\-value 0 \\-Force*)
```


### splunk
    
```
(CommandLine="*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force*" OR CommandLine="*-Property String -name Check_Associations -value*" OR CommandLine="*-Property DWORD -name IEHarden -value 0 -Force*")
```


### logpoint
    
```
CommandLine IN ["*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force*", "*-Property String -name Check_Associations -value*", "*-Property DWORD -name IEHarden -value 0 -Force*"]
```


### grep
    
```
grep -P '^(?:.*.*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force.*|.*.*-Property String -name Check_Associations -value.*|.*.*-Property DWORD -name IEHarden -value 0 -Force.*)'
```



