| Title                | NTFS Alternate Data Stream                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1096: NTFS File Attributes](https://attack.mitre.org/techniques/T1096)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1096: NTFS File Attributes](../Triggers/T1096.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.powertheshell.com/ntfsstreams/](http://www.powertheshell.com/ntfsstreams/)</li></ul>  |
| Author               | Sami Ruohonen |


## Detection Rules

### Sigma rule

```
title: NTFS Alternate Data Stream
id: 8c521530-5169-495d-a199-0a3a881ad24e
status: experimental
description: Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.
references:
    - http://www.powertheshell.com/ntfsstreams/
tags:
    - attack.defense_evasion
    - attack.t1096
author: Sami Ruohonen
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keyword1:
        - "set-content"
    keyword2:
        - "-stream"
    condition: keyword1 and keyword2
falsepositives:
    - unknown
level: high

```





### splunk
    
```
("set-content" "-stream")
```



