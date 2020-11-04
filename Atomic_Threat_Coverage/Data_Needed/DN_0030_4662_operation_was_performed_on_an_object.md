| Title              | DN_0030_4662_operation_was_performed_on_an_object       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | An operation was performed on an Active Directory object |
| **Logging Policy** | <ul><li>[LP_0027_windows_audit_directory_service_access](../Logging_Policies/LP_0027_windows_audit_directory_service_access.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4662.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4662.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectServer</li><li>ObjectType</li><li>ObjectName</li><li>OperationType</li><li>HandleId</li><li>AccessList</li><li>AccessMask</li><li>Properties</li><li>AdditionalInfo</li><li>AdditionalInfo2</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4662</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>14080</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-08-28T01:58:36.894922400Z" /> 
    <EventRecordID>407230</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="520" ThreadID="600" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x35867</Data> 
    <Data Name="ObjectServer">DS</Data> 
    <Data Name="ObjectType">%{bf967a86-0de6-11d0-a285-00aa003049e2}</Data> 
    <Data Name="ObjectName">%{38b3d2e6-9948-4dc1-ae90-1605d5eab9a2}</Data> 
    <Data Name="OperationType">Object Access</Data> 
    <Data Name="HandleId">0x0</Data> 
    <Data Name="AccessList">%%1537</Data> 
    <Data Name="AccessMask">0x10000</Data> 
    <Data Name="Properties">%%1537 {bf967a86-0de6-11d0-a285-00aa003049e2}</Data> 
    <Data Name="AdditionalInfo">-</Data> 
    <Data Name="AdditionalInfo2" /> 
  </EventData>
</Event>

```




