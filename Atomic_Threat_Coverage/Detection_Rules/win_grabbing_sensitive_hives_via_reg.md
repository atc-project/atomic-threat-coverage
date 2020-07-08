| Title                    | Grabbing Sensitive Hives via Reg Utility       |
|:-------------------------|:------------------|
| **Description**          | Dump sam, system or security hives using REG.exe utility |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Dumping hives for legitimate purpouse i.e. backup or forensic investigation</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/aed95fc6-5e3f-49dc-8b35-06508613f979.html](https://eqllib.readthedocs.io/en/latest/analytics/aed95fc6-5e3f-49dc-8b35-06508613f979.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, Endgame, JHasenbusch, Daniil Yugoslavskiy, oscd.community |
| Other Tags           | <ul><li>car.2013-07-001</li><li>attack.t1003.002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Grabbing Sensitive Hives via Reg Utility
id: fd877b94-9bb5-4191-bb25-d79cbd93c167
description: Dump sam, system or security hives using REG.exe utility
author: Teymur Kheirkhabarov, Endgame, JHasenbusch, Daniil Yugoslavskiy, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://eqllib.readthedocs.io/en/latest/analytics/aed95fc6-5e3f-49dc-8b35-06508613f979.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
tags:
    - attack.credential_access
    - attack.t1003
    - car.2013-07-001
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image: '*\reg.exe'
        CommandLine|contains:
            - 'save'
            - 'export'
    selection_2:
        CommandLine|contains:
            - 'hklm'
            - 'hkey_local_machine'
    selection_3:
        CommandLine|endswith:
            - '\system'
            - '\sam'
            - '\security'
    condition: selection_1 and selection_2 and selection_3
falsepositives:
    - Dumping hives for legitimate purpouse i.e. backup or forensic investigation
level: medium
status: experimental

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and ($_.message -match "CommandLine.*.*save.*" -or $_.message -match "CommandLine.*.*export.*") -and ($_.message -match "CommandLine.*.*hklm.*" -or $_.message -match "CommandLine.*.*hkey_local_machine.*") -and ($_.message -match "CommandLine.*.*\\system" -or $_.message -match "CommandLine.*.*\\sam" -or $_.message -match "CommandLine.*.*\\security")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\reg.exe AND winlog.event_data.CommandLine.keyword:(*save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*hklm* OR *hkey_local_machine*) AND winlog.event_data.CommandLine.keyword:(*\\system OR *\\sam OR *\\security))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fd877b94-9bb5-4191-bb25-d79cbd93c167 <<EOF
{
  "metadata": {
    "title": "Grabbing Sensitive Hives via Reg Utility",
    "description": "Dump sam, system or security hives using REG.exe utility",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "car.2013-07-001",
      "attack.t1003.002"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\reg.exe AND winlog.event_data.CommandLine.keyword:(*save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*hklm* OR *hkey_local_machine*) AND winlog.event_data.CommandLine.keyword:(*\\\\system OR *\\\\sam OR *\\\\security))"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\reg.exe AND winlog.event_data.CommandLine.keyword:(*save* OR *export*) AND winlog.event_data.CommandLine.keyword:(*hklm* OR *hkey_local_machine*) AND winlog.event_data.CommandLine.keyword:(*\\\\system OR *\\\\sam OR *\\\\security))",
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
        "subject": "Sigma Rule 'Grabbing Sensitive Hives via Reg Utility'",
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
(Image.keyword:*\\reg.exe AND CommandLine.keyword:(*save* *export*) AND CommandLine.keyword:(*hklm* *hkey_local_machine*) AND CommandLine.keyword:(*\\system *\\sam *\\security))
```


### splunk
    
```
(Image="*\\reg.exe" (CommandLine="*save*" OR CommandLine="*export*") (CommandLine="*hklm*" OR CommandLine="*hkey_local_machine*") (CommandLine="*\\system" OR CommandLine="*\\sam" OR CommandLine="*\\security"))
```


### logpoint
    
```
(event_id="1" Image="*\\reg.exe" CommandLine IN ["*save*", "*export*"] CommandLine IN ["*hklm*", "*hkey_local_machine*"] CommandLine IN ["*\\system", "*\\sam", "*\\security"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\reg\.exe)(?=.*(?:.*.*save.*|.*.*export.*))(?=.*(?:.*.*hklm.*|.*.*hkey_local_machine.*))(?=.*(?:.*.*\system|.*.*\sam|.*.*\security)))'
```



