| Title                | Malicious payload download via Office binaries                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Downloads payload from remote server                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1105: Remote File Copy](../Triggers/T1105.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Powerpnt.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Powerpnt.yml)</li><li>[https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191](https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191)</li><li>[Reegun J (OCBC Bank)](Reegun J (OCBC Bank))</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Malicious payload download via Office binaries
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





### es-qs
    
```
(Image.keyword:(*\\\\powerpnt.exe OR *\\\\winword.exe OR *\\\\excel.exe) AND CommandLine.keyword:*http*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Malicious-payload-download-via-Office-binaries <<EOF\n{\n  "metadata": {\n    "title": "Malicious payload download via Office binaries",\n    "description": "Downloads payload from remote server",\n    "tags": [\n      "attack.command_and_control",\n      "attack.t1105"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\powerpnt.exe OR *\\\\\\\\winword.exe OR *\\\\\\\\excel.exe) AND CommandLine.keyword:*http*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\powerpnt.exe OR *\\\\\\\\winword.exe OR *\\\\\\\\excel.exe) AND CommandLine.keyword:*http*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious payload download via Office binaries\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\powerpnt.exe *\\\\winword.exe *\\\\excel.exe) AND CommandLine.keyword:*http*)
```


### splunk
    
```
((Image="*\\\\powerpnt.exe" OR Image="*\\\\winword.exe" OR Image="*\\\\excel.exe") CommandLine="*http*")
```


### logpoint
    
```
(event_id="1" Image IN ["*\\\\powerpnt.exe", "*\\\\winword.exe", "*\\\\excel.exe"] CommandLine="*http*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\powerpnt\\.exe|.*.*\\winword\\.exe|.*.*\\excel\\.exe))(?=.*.*http.*))'
```



