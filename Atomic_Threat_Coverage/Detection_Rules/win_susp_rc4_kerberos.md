| Title                    | Suspicious Kerberos RC4 Ticket Encryption       |
|:-------------------------|:------------------|
| **Description**          | Detects service ticket requests using RC4 encryption type |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0077_4769_kerberos_service_ticket_was_requested](../Data_Needed/DN_0077_4769_kerberos_service_ticket_was_requested.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Service accounts used on legacy systems (e.g. NetApp)</li><li>Windows Domains with DFL 2003 and legacy systems</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://adsecurity.org/?p=3458](https://adsecurity.org/?p=3458)</li><li>[https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity](https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Kerberos RC4 Ticket Encryption
id: 496a0e47-0a33-4dca-b009-9e6ca3591f39
status: experimental
references:
    - https://adsecurity.org/?p=3458
    - https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity
tags:
    - attack.credential_access
    - attack.t1208
description: Detects service ticket requests using RC4 encryption type
author: Florian Roth
date: 2017/02/06
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryptionType: '0x17'
    reduction:
        - ServiceName: '$*'
    condition: selection and not reduction
falsepositives:
    - Service accounts used on legacy systems (e.g. NetApp)
    - Windows Domains with DFL 2003 and legacy systems
level: medium

```





### es-qs
    
```
((EventID:"4769" AND TicketOptions:"0x40810000" AND TicketEncryptionType:"0x17") AND (NOT (ServiceName.keyword:$*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/496a0e47-0a33-4dca-b009-9e6ca3591f39 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Kerberos RC4 Ticket Encryption",\n    "description": "Detects service ticket requests using RC4 encryption type",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1208"\n    ],\n    "query": "((EventID:\\"4769\\" AND TicketOptions:\\"0x40810000\\" AND TicketEncryptionType:\\"0x17\\") AND (NOT (ServiceName.keyword:$*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"4769\\" AND TicketOptions:\\"0x40810000\\" AND TicketEncryptionType:\\"0x17\\") AND (NOT (ServiceName.keyword:$*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Kerberos RC4 Ticket Encryption\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4769" AND TicketOptions:"0x40810000" AND TicketEncryptionType:"0x17") AND (NOT (ServiceName.keyword:$*)))
```


### splunk
    
```
((EventID="4769" TicketOptions="0x40810000" TicketEncryptionType="0x17") NOT (ServiceName="$*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4769" ticket_options="0x40810000" TicketEncryptionType="0x17")  -(service="$*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4769)(?=.*0x40810000)(?=.*0x17)))(?=.*(?!.*(?:.*(?:.*(?=.*\\$.*))))))'
```



