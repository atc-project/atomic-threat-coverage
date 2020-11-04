| Title                    | Malicious Payload Download via Office Binaries       |
|:-------------------------|:------------------|
| **Description**          | Downloads payload from remote server |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Powerpnt.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Powerpnt.yml)</li><li>[https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191](https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191)</li><li>[Reegun J (OCBC Bank)](Reegun J (OCBC Bank))</li></ul>  |
| **Author**               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Malicious Payload Download via Office Binaries
id: 0c79148b-118e-472b-bdb7-9b57b444cc19
status: experimental
description: Downloads payload from remote server
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Powerpnt.yml
    - https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191
    - Reegun J (OCBC Bank)
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.command_and_control
    - attack.t1105
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powerpnt.exe'
            - '\winword.exe'
            - '\excel.exe'
        CommandLine|contains: 'http'
    condition: selection
falsepositives:
    - Unknown

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\winword.exe" -or $_.message -match "Image.*.*\\excel.exe") -and $_.message -match "CommandLine.*.*http.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\powerpnt.exe OR *\\winword.exe OR *\\excel.exe) AND winlog.event_data.CommandLine.keyword:*http*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/0c79148b-118e-472b-bdb7-9b57b444cc19 <<EOF
{
  "metadata": {
    "title": "Malicious Payload Download via Office Binaries",
    "description": "Downloads payload from remote server",
    "tags": [
      "attack.command_and_control",
      "attack.t1105"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\powerpnt.exe OR *\\\\winword.exe OR *\\\\excel.exe) AND winlog.event_data.CommandLine.keyword:*http*)"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\powerpnt.exe OR *\\\\winword.exe OR *\\\\excel.exe) AND winlog.event_data.CommandLine.keyword:*http*)",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Malicious Payload Download via Office Binaries'",
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
(Image.keyword:(*\\powerpnt.exe *\\winword.exe *\\excel.exe) AND CommandLine.keyword:*http*)
```


### splunk
    
```
((Image="*\\powerpnt.exe" OR Image="*\\winword.exe" OR Image="*\\excel.exe") CommandLine="*http*")
```


### logpoint
    
```
(Image IN ["*\\powerpnt.exe", "*\\winword.exe", "*\\excel.exe"] CommandLine="*http*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\powerpnt\.exe|.*.*\winword\.exe|.*.*\excel\.exe))(?=.*.*http.*))'
```



