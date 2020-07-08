| Title              | DN0026_5136_windows_directory_service_object_was_modified       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | A directory service object was modified |
| **Logging Policy** | <ul><li>[LP0025_windows_audit_directory_service_changes](../Logging_Policies/LP0025_windows_audit_directory_service_changes.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-5136.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-5136.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>OpCorrelationID</li><li>AppCorrelationID</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>DSName</li><li>DSType</li><li>ObjectDN</li><li>ObjectGUID</li><li>ObjectClass</li><li>AttributeLDAPDisplayName</li><li>AttributeSyntaxOID</li><li>AttributeValue</li><li>OperationType</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>5136</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>14081</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-08-28T17:36:04.129472600Z" /> 
    <EventRecordID>410204</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="516" ThreadID="4020" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="OpCorrelationID">{02647639-8626-43CE-AFE6-7AA1AD657739}</Data> 
    <Data Name="AppCorrelationID">-</Data> 
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x32004</Data> 
    <Data Name="DSName">contoso.local</Data> 
    <Data Name="DSType">%%14676</Data> 
    <Data Name="ObjectDN">CN=Sergey,CN=Builtin,DC=contoso,DC=local</Data> 
    <Data Name="ObjectGUID">{4FE80A66-5F93-4F73-B215-68678058E613}</Data> 
    <Data Name="ObjectClass">user</Data> 
    <Data Name="AttributeLDAPDisplayName">userAccountControl</Data> 
    <Data Name="AttributeSyntaxOID">2.5.5.9</Data> 
    <Data Name="AttributeValue">512</Data> 
    <Data Name="OperationType">%%14675</Data> 
  </EventData>
</Event>

```




