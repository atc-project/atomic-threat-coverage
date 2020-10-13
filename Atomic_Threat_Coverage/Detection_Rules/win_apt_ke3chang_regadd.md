| Title                    | Ke3chang Registry Key Modifications       |
|:-------------------------|:------------------|
| **Description**          | Detects Registry modifcations performaed by Ke3chang malware in campaigns running in 2019 and 2020 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li><li>[T1562.001: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001)</li></ul>  |
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
winlog.event_data.CommandLine.keyword:(*\-Property\ DWORD\ \-name\ DisableFirstRunCustomize\ \-value\ 2\ \-Force* OR *\-Property\ String\ \-name\ Check_Associations\ \-value* OR *\-Property\ DWORD\ \-name\ IEHarden\ \-value\ 0\ \-Force*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7b544661-69fc-419f-9a59-82ccc328f205 <<EOF
{
  "metadata": {
    "title": "Ke3chang Registry Key Modifications",
    "description": "Detects Registry modifcations performaed by Ke3chang malware in campaigns running in 2019 and 2020",
    "tags": [
      "attack.g0004",
      "attack.defense_evasion",
      "attack.t1089",
      "attack.t1562.001"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\-Property\\ DWORD\\ \\-name\\ DisableFirstRunCustomize\\ \\-value\\ 2\\ \\-Force* OR *\\-Property\\ String\\ \\-name\\ Check_Associations\\ \\-value* OR *\\-Property\\ DWORD\\ \\-name\\ IEHarden\\ \\-value\\ 0\\ \\-Force*)"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "winlog.event_data.CommandLine.keyword:(*\\-Property\\ DWORD\\ \\-name\\ DisableFirstRunCustomize\\ \\-value\\ 2\\ \\-Force* OR *\\-Property\\ String\\ \\-name\\ Check_Associations\\ \\-value* OR *\\-Property\\ DWORD\\ \\-name\\ IEHarden\\ \\-value\\ 0\\ \\-Force*)",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Ke3chang Registry Key Modifications'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
CommandLine.keyword:(*\-Property DWORD \-name DisableFirstRunCustomize \-value 2 \-Force* *\-Property String \-name Check_Associations \-value* *\-Property DWORD \-name IEHarden \-value 0 \-Force*)
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



