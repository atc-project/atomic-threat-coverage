| Title                | Malicious payload download via Office binaries                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Downloads payload from remote server                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
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





### splunk
    
```
((Image="*\\\\powerpnt.exe" OR Image="*\\\\winword.exe" OR Image="*\\\\excel.exe") CommandLine="*http*")
```



