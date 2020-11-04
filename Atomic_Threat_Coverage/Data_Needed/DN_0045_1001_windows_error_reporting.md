| Title              | DN_0045_1001_windows_error_reporting       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | When application fails, the result is recorded as an informational event in the Application log by Windows Error Reporting as event 1001. |
| **Logging Policy** | <ul><li>[none](../Logging_Policies/none.md)</li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754364(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754364(v=ws.11))</li><li>[https://social.technet.microsoft.com/wiki/contents/articles/3116.event-id-1001-windows-error-reporting.aspx?Sort=MostRecent&PageIndex=1](https://social.technet.microsoft.com/wiki/contents/articles/3116.event-id-1001-windows-error-reporting.aspx?Sort=MostRecent&PageIndex=1)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Application     |
| **Provider**       | Windows Error Reporting    |
| **Fields**         | <ul><li>EventID</li><li>Hostname</li><li>Computer</li><li>EventName</li><li>Response</li><li>CabId</li><li>ProblemSignature</li><li>AttachedFiles</li><li>Thesefilesmaybeavailablehere</li><li>AnalysisSymbol</li><li>RecheckingForSolution</li><li>ReportId</li><li>ReportStatus</li><li>HashedBucket</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Windows Error Reporting" /> 
    <EventID Qualifiers="0">1001</EventID> 
    <Level>4</Level> 
    <Task>0</Task> 
    <Keywords>0x80000000000000</Keywords> 
    <TimeCreated SystemTime="2019-01-08T14:01:18.909425000Z" /> 
    <EventRecordID>11279</EventRecordID> 
    <Channel>Application</Channel> 
    <Computer>WD00000.eu.windows.com</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data>2005798148961969216</Data> 
    <Data>5</Data> 
    <Data>StoreAgentScanForUpdatesFailure0</Data> 
    <Data>Not available</Data> 
    <Data>0</Data> 
    <Data>Update;</Data> 
    <Data>8024402c</Data> 
    <Data>16299</Data> 
    <Data>847</Data> 
    <Data>Windows.Desktop</Data> 
    <Data /> 
    <Data /> 
    <Data /> 
    <Data /> 
    <Data /> 
    <Data>\\?\C:\ProgramData\Microsoft\Windows\WER\Temp\WER81F.tmp.WERInternalMetadata.xml</Data> 
    <Data>C:\ProgramData\Microsoft\Windows\WER\ReportArchive\NonCritical_Update;_ba86f388d190af6963dbd95b33715448fcb6fd5_00000000_27442451</Data> 
    <Data /> 
    <Data>0</Data> 
    <Data>0885fc8a-5383-4c50-b209-7c570832b8bf</Data> 
    <Data>268435556</Data> 
    <Data>e7b725b96c0bab97abd606ca1003a440</Data> 
  </EventData>
</Event>

```




