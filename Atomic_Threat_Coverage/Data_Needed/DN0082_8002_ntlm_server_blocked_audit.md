| Title              | DN0082_8002_ntlm_server_blocked_audit       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | NTLM server blocked audit: Audit Incoming NTLM Traffic that would be blocked. Actually it's just event about NTLM authentication, it doesn't necessary supposed to be blocked. Blocked NTLM auth is the same provider but Event ID 4002 |
| **Logging Policy** | <ul><li>[LP0044_windows_ntlm_audit](../Logging_Policies/LP0044_windows_ntlm_audit.md)</li></ul> |
| **References**     | <ul><li>[https://twitter.com/JohnLaTwC/status/1004895902010507266](https://twitter.com/JohnLaTwC/status/1004895902010507266)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-NTLM/Operational     |
| **Provider**       | Microsoft-Windows-NTLM    |
| **Fields**         | <ul><li>EventID</li><li>Hostname</li><li>Computer</li><li>CallerPID</li><li>ProcessName</li><li>ClientLUID</li><li>ClientUserName</li><li>ClientDomainName</li><li>MechanismOID</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
      <Provider Name="Microsoft-Windows-NTLM" Guid="{AC43300D-5FCC-4800-8E99-1BD3F85F0320}" /> 
      <EventID>8002</EventID> 
      <Version>0</Version> 
      <Level>4</Level> 
      <Task>2</Task> 
      <Opcode>0</Opcode> 
      <Keywords>0x8000000000000000</Keywords> 
      <TimeCreated SystemTime="2019-03-02T23:00:00.746139000Z" /> 
      <EventRecordID>12</EventRecordID> 
      <Correlation /> 
      <Execution ProcessID="468" ThreadID="2660" /> 
      <Channel>Microsoft-Windows-NTLM/Operational</Channel> 
      <Computer>dc.yugoslavskiy.local</Computer> 
      <Security UserID="S-1-5-18" /> 
    </System>
  - <EventData>
      <Data Name="CallerPID">4</Data> 
      <Data Name="ProcessName" /> 
      <Data Name="ClientLUID">0x3e7</Data> 
      <Data Name="ClientUserName">DC$</Data> 
      <Data Name="ClientDomainName">atc</Data> 
    <Data Name="MechanismOID">1.3.6.1.4.1.311.2.2.10</Data> 
    </EventData>
  </Event>
```




