| Title                | Service Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects manual service execution (start) via system utilities                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Legitimate administrator or user executes a service for legitimate reason</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Service Execution
id: 2a072a96-a086-49fa-bcb5-15cc5a619093
status: experimental
description: Detects manual service execution (start) via system utilities
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1035/T1035.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: 
            - '\net.exe'
            - '\net1.exe'
        CommandLine|re: '.*start.*[a-zA-Z0-9]' # search for a service name after 'net start', avoiding intersection with "service discovery" technique detection rules
    condition: selection
falsepositives:
    - Legitimate administrator or user executes a service for legitimate reason
level: low
tags:
    - attack.execution
    - attack.t1035

```





### splunk
    
```

```






### Saved Search for Splunk

```
Failure converting the Sigma File: ../detection_rules/sigma/rules/windows/process_creation/win_service_execution.yml
```
