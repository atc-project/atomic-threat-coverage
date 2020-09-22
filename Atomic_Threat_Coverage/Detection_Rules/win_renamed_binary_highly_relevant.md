| Title                    | Highly Relevant Renamed Binary       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1036.003: Rename System Utilities](https://attack.mitre.org/techniques/T1036.003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1036.003: Rename System Utilities](../Triggers/T1036.003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)</li><li>[https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html](https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html)</li><li>[https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html](https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html)</li></ul>  |
| **Author**               | Matthew Green - @mgreen27, Florian Roth |


## Detection Rules

### Sigma rule

```
title: Highly Relevant Renamed Binary
id: 0ba1da6d-b6ce-4366-828c-18826c9de23e
status: experimental
description: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
author: Matthew Green - @mgreen27, Florian Roth
date: 2019/06/15
modified: 2020/09/06
references:
    - https://attack.mitre.org/techniques/T1036/
    - https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html
    - https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html
tags:
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - "powershell.exe"
            - "powershell_ise.exe"
            - "psexec.exe"
            - "psexec.c"  # old versions of psexec (2016 seen)
            - "cscript.exe"
            - "wscript.exe"
            - "mshta.exe"
            - "regsvr32.exe"
            - "wmic.exe"
            - "certutil.exe"
            - "rundll32.exe"
            - "cmstp.exe"
            - "msiexec.exe"
    filter:
        Image:
            - '*\powershell.exe'
            - '*\powershell_ise.exe'
            - '*\psexec.exe'
            - '*\psexec64.exe'
            - '*\cscript.exe'
            - '*\wscript.exe'
            - '*\mshta.exe'
            - '*\regsvr32.exe'
            - '*\wmic.exe'
            - '*\certutil.exe'
            - '*\rundll32.exe'
            - '*\cmstp.exe'
            - '*\msiexec.exe'
    condition: selection and not filter
falsepositives:
    - Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "powershell.exe" -or $_.message -match "powershell_ise.exe" -or $_.message -match "psexec.exe" -or $_.message -match "psexec.c" -or $_.message -match "cscript.exe" -or $_.message -match "wscript.exe" -or $_.message -match "mshta.exe" -or $_.message -match "regsvr32.exe" -or $_.message -match "wmic.exe" -or $_.message -match "certutil.exe" -or $_.message -match "rundll32.exe" -or $_.message -match "cmstp.exe" -or $_.message -match "msiexec.exe") -and  -not (($_.message -match "Image.*.*\\\\powershell.exe" -or $_.message -match "Image.*.*\\\\powershell_ise.exe" -or $_.message -match "Image.*.*\\\\psexec.exe" -or $_.message -match "Image.*.*\\\\psexec64.exe" -or $_.message -match "Image.*.*\\\\cscript.exe" -or $_.message -match "Image.*.*\\\\wscript.exe" -or $_.message -match "Image.*.*\\\\mshta.exe" -or $_.message -match "Image.*.*\\\\regsvr32.exe" -or $_.message -match "Image.*.*\\\\wmic.exe" -or $_.message -match "Image.*.*\\\\certutil.exe" -or $_.message -match "Image.*.*\\\\rundll32.exe" -or $_.message -match "Image.*.*\\\\cmstp.exe" -or $_.message -match "Image.*.*\\\\msiexec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(OriginalFileName:("powershell.exe" OR "powershell_ise.exe" OR "psexec.exe" OR "psexec.c" OR "cscript.exe" OR "wscript.exe" OR "mshta.exe" OR "regsvr32.exe" OR "wmic.exe" OR "certutil.exe" OR "rundll32.exe" OR "cmstp.exe" OR "msiexec.exe") AND (NOT (winlog.event_data.Image.keyword:(*\\\\powershell.exe OR *\\\\powershell_ise.exe OR *\\\\psexec.exe OR *\\\\psexec64.exe OR *\\\\cscript.exe OR *\\\\wscript.exe OR *\\\\mshta.exe OR *\\\\regsvr32.exe OR *\\\\wmic.exe OR *\\\\certutil.exe OR *\\\\rundll32.exe OR *\\\\cmstp.exe OR *\\\\msiexec.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/0ba1da6d-b6ce-4366-828c-18826c9de23e <<EOF\n{\n  "metadata": {\n    "title": "Highly Relevant Renamed Binary",\n    "description": "Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036",\n      "attack.t1036.003"\n    ],\n    "query": "(OriginalFileName:(\\"powershell.exe\\" OR \\"powershell_ise.exe\\" OR \\"psexec.exe\\" OR \\"psexec.c\\" OR \\"cscript.exe\\" OR \\"wscript.exe\\" OR \\"mshta.exe\\" OR \\"regsvr32.exe\\" OR \\"wmic.exe\\" OR \\"certutil.exe\\" OR \\"rundll32.exe\\" OR \\"cmstp.exe\\" OR \\"msiexec.exe\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\\\\\powershell.exe OR *\\\\\\\\powershell_ise.exe OR *\\\\\\\\psexec.exe OR *\\\\\\\\psexec64.exe OR *\\\\\\\\cscript.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\mshta.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\certutil.exe OR *\\\\\\\\rundll32.exe OR *\\\\\\\\cmstp.exe OR *\\\\\\\\msiexec.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(OriginalFileName:(\\"powershell.exe\\" OR \\"powershell_ise.exe\\" OR \\"psexec.exe\\" OR \\"psexec.c\\" OR \\"cscript.exe\\" OR \\"wscript.exe\\" OR \\"mshta.exe\\" OR \\"regsvr32.exe\\" OR \\"wmic.exe\\" OR \\"certutil.exe\\" OR \\"rundll32.exe\\" OR \\"cmstp.exe\\" OR \\"msiexec.exe\\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\\\\\powershell.exe OR *\\\\\\\\powershell_ise.exe OR *\\\\\\\\psexec.exe OR *\\\\\\\\psexec64.exe OR *\\\\\\\\cscript.exe OR *\\\\\\\\wscript.exe OR *\\\\\\\\mshta.exe OR *\\\\\\\\regsvr32.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\certutil.exe OR *\\\\\\\\rundll32.exe OR *\\\\\\\\cmstp.exe OR *\\\\\\\\msiexec.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Highly Relevant Renamed Binary\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(OriginalFileName:("powershell.exe" "powershell_ise.exe" "psexec.exe" "psexec.c" "cscript.exe" "wscript.exe" "mshta.exe" "regsvr32.exe" "wmic.exe" "certutil.exe" "rundll32.exe" "cmstp.exe" "msiexec.exe") AND (NOT (Image.keyword:(*\\\\powershell.exe *\\\\powershell_ise.exe *\\\\psexec.exe *\\\\psexec64.exe *\\\\cscript.exe *\\\\wscript.exe *\\\\mshta.exe *\\\\regsvr32.exe *\\\\wmic.exe *\\\\certutil.exe *\\\\rundll32.exe *\\\\cmstp.exe *\\\\msiexec.exe))))
```


### splunk
    
```
((OriginalFileName="powershell.exe" OR OriginalFileName="powershell_ise.exe" OR OriginalFileName="psexec.exe" OR OriginalFileName="psexec.c" OR OriginalFileName="cscript.exe" OR OriginalFileName="wscript.exe" OR OriginalFileName="mshta.exe" OR OriginalFileName="regsvr32.exe" OR OriginalFileName="wmic.exe" OR OriginalFileName="certutil.exe" OR OriginalFileName="rundll32.exe" OR OriginalFileName="cmstp.exe" OR OriginalFileName="msiexec.exe") NOT ((Image="*\\\\powershell.exe" OR Image="*\\\\powershell_ise.exe" OR Image="*\\\\psexec.exe" OR Image="*\\\\psexec64.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\regsvr32.exe" OR Image="*\\\\wmic.exe" OR Image="*\\\\certutil.exe" OR Image="*\\\\rundll32.exe" OR Image="*\\\\cmstp.exe" OR Image="*\\\\msiexec.exe")))
```


### logpoint
    
```
(OriginalFileName IN ["powershell.exe", "powershell_ise.exe", "psexec.exe", "psexec.c", "cscript.exe", "wscript.exe", "mshta.exe", "regsvr32.exe", "wmic.exe", "certutil.exe", "rundll32.exe", "cmstp.exe", "msiexec.exe"]  -(Image IN ["*\\\\powershell.exe", "*\\\\powershell_ise.exe", "*\\\\psexec.exe", "*\\\\psexec64.exe", "*\\\\cscript.exe", "*\\\\wscript.exe", "*\\\\mshta.exe", "*\\\\regsvr32.exe", "*\\\\wmic.exe", "*\\\\certutil.exe", "*\\\\rundll32.exe", "*\\\\cmstp.exe", "*\\\\msiexec.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*powershell\\.exe|.*powershell_ise\\.exe|.*psexec\\.exe|.*psexec\\.c|.*cscript\\.exe|.*wscript\\.exe|.*mshta\\.exe|.*regsvr32\\.exe|.*wmic\\.exe|.*certutil\\.exe|.*rundll32\\.exe|.*cmstp\\.exe|.*msiexec\\.exe))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\powershell\\.exe|.*.*\\powershell_ise\\.exe|.*.*\\psexec\\.exe|.*.*\\psexec64\\.exe|.*.*\\cscript\\.exe|.*.*\\wscript\\.exe|.*.*\\mshta\\.exe|.*.*\\regsvr32\\.exe|.*.*\\wmic\\.exe|.*.*\\certutil\\.exe|.*.*\\rundll32\\.exe|.*.*\\cmstp\\.exe|.*.*\\msiexec\\.exe))))))'
```



