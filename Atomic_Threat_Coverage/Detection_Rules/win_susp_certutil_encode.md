| Title                | Certutil Encode                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | medium |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)</li><li>[https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/](https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Certutil Encode
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





### es-qs
    
```
CommandLine.keyword:(certutil\\ \\-f\\ \\-encode\\ * certutil.exe\\ \\-f\\ \\-encode\\ * certutil\\ \\-encode\\ \\-f\\ * certutil.exe\\ \\-encode\\ \\-f\\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Certutil-Encode <<EOF\n{\n  "metadata": {\n    "title": "Certutil Encode",\n    "description": "Detects suspicious a certutil command that used to encode files, which is sometimes used for data exfiltration",\n    "tags": "",\n    "query": "CommandLine.keyword:(certutil\\\\ \\\\-f\\\\ \\\\-encode\\\\ * certutil.exe\\\\ \\\\-f\\\\ \\\\-encode\\\\ * certutil\\\\ \\\\-encode\\\\ \\\\-f\\\\ * certutil.exe\\\\ \\\\-encode\\\\ \\\\-f\\\\ *)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:(certutil\\\\ \\\\-f\\\\ \\\\-encode\\\\ * certutil.exe\\\\ \\\\-f\\\\ \\\\-encode\\\\ * certutil\\\\ \\\\-encode\\\\ \\\\-f\\\\ * certutil.exe\\\\ \\\\-encode\\\\ \\\\-f\\\\ *)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Certutil Encode\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:("certutil \\-f \\-encode *" "certutil.exe \\-f \\-encode *" "certutil \\-encode \\-f *" "certutil.exe \\-encode \\-f *")
```


### splunk
    
```
(CommandLine="certutil -f -encode *" OR CommandLine="certutil.exe -f -encode *" OR CommandLine="certutil -encode -f *" OR CommandLine="certutil.exe -encode -f *")
```


### logpoint
    
```
CommandLine IN ["certutil -f -encode *", "certutil.exe -f -encode *", "certutil -encode -f *", "certutil.exe -encode -f *"]
```


### grep
    
```
grep -P '^(?:.*certutil -f -encode .*|.*certutil\\.exe -f -encode .*|.*certutil -encode -f .*|.*certutil\\.exe -encode -f .*)'
```



