| Title                    | Certutil Encode       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)</li><li>[https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/](https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Certutil Encode
id: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
status: experimental
description: Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
    - https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/
author: Florian Roth
date: 2019/02/24
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - certutil -f -encode *
            - certutil.exe -f -encode *
            - certutil -encode -f *
            - certutil.exe -encode -f *
    condition: selection
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*certutil -f -encode .*" -or $_.message -match "CommandLine.*certutil.exe -f -encode .*" -or $_.message -match "CommandLine.*certutil -encode -f .*" -or $_.message -match "CommandLine.*certutil.exe -encode -f .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(certutil\ \-f\ \-encode\ * OR certutil.exe\ \-f\ \-encode\ * OR certutil\ \-encode\ \-f\ * OR certutil.exe\ \-encode\ \-f\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a <<EOF
{
  "metadata": {
    "title": "Certutil Encode",
    "description": "Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration",
    "tags": "",
    "query": "winlog.event_data.CommandLine.keyword:(certutil\\ \\-f\\ \\-encode\\ * OR certutil.exe\\ \\-f\\ \\-encode\\ * OR certutil\\ \\-encode\\ \\-f\\ * OR certutil.exe\\ \\-encode\\ \\-f\\ *)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(certutil\\ \\-f\\ \\-encode\\ * OR certutil.exe\\ \\-f\\ \\-encode\\ * OR certutil\\ \\-encode\\ \\-f\\ * OR certutil.exe\\ \\-encode\\ \\-f\\ *)",
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
        "subject": "Sigma Rule 'Certutil Encode'",
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
CommandLine.keyword:(certutil \-f \-encode * certutil.exe \-f \-encode * certutil \-encode \-f * certutil.exe \-encode \-f *)
```


### splunk
    
```
(CommandLine="certutil -f -encode *" OR CommandLine="certutil.exe -f -encode *" OR CommandLine="certutil -encode -f *" OR CommandLine="certutil.exe -encode -f *")
```


### logpoint
    
```
(event_id="1" CommandLine IN ["certutil -f -encode *", "certutil.exe -f -encode *", "certutil -encode -f *", "certutil.exe -encode -f *"])
```


### grep
    
```
grep -P '^(?:.*certutil -f -encode .*|.*certutil\.exe -f -encode .*|.*certutil -encode -f .*|.*certutil\.exe -encode -f .*)'
```



