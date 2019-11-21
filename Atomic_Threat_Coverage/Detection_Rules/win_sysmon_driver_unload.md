| Title                | Sysmon driver unload                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect possible Sysmon driver unload                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>U</li><li>n</li><li>k</li><li>n</li><li>o</li><li>w</li><li>n</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon](https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon)</li></ul>  |
| Author               | Kirill Kiryanov, oscd.community |


## Detection Rules

### Sigma rule

```
title: Sysmon driver unload
id: 4d7cda18-1b12-4e52-b45c-d28653210df8
status: experimental
author: Kirill Kiryanov, oscd.community
description: Detect possible Sysmon driver unload
date: 2019/10/23
modified: 2019/11/07
references:
    - https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\fltmc.exe'
        CommandLine|contains|all:
            - 'unload'
            - 'sys'
    condition: selection
falsepositives: Unknown
level: high
fields:
    - CommandLine
    - Details

```





### splunk
    
```
(Image="*\\\\fltmc.exe" CommandLine="*unload*" CommandLine="*sys*") | table CommandLine,Details
```



