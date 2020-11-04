| Title              | DN_0044_1000_application_crashed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This is a very generic error and it doesn't tell much about what caused it. Some applications may fail with this error when the system is left unstable by another faulty program. |
| **Logging Policy** | <ul><li>[none](../Logging_Policies/none.md)</li></ul> |
| **References**     | <ul><li>[https://www.morgantechspace.com/2014/12/event-id-1000-application-error.html](https://www.morgantechspace.com/2014/12/event-id-1000-application-error.html)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Application     |
| **Provider**       | Application Error    |
| **Fields**         | <ul><li>EventID</li><li>Hostname</li><li>Computer</li><li>FaultingApplicationName</li><li>FaultingModuleName</li><li>ExceptionCode</li><li>FaultOffset</li><li>FaultingProcessId</li><li>FaultingApplicationStartTime</li><li>FaultingApplicationPath</li><li>FaultingModulePath</li><li>ReportId</li><li>FaultingPackageFullName</li><li>FaultingPackage-relativeApplicationID</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System> 
    <Provider Name="Application Error" /> 
    <EventID Qualifiers="0">1000</EventID> 
    <Level>2</Level> 
    <Task>100</Task> 
    <Keywords>0x80000000000000</Keywords> 
    <TimeCreated SystemTime="2019-01-01T15:49:38.973342200Z" /> 
    <EventRecordID>6724</EventRecordID> 
    <Channel>Application</Channel> 
    <Computer>WD0000.eu.windows.com</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data>IntelAudioService.exe</Data> 
    <Data>1.0.46.0</Data> 
    <Data>59afa72c</Data> 
    <Data>KERNELBASE.dll</Data> 
    <Data>10.0.17134.441</Data> 
    <Data>428de48c</Data> 
    <Data>e06d7363</Data> 
    <Data>000000000003a388</Data> 
    <Data>1240</Data> 
    <Data>01d49e823bbf0b3b</Data> 
    <Data>C:\WINDOWS\system32\cAVS\Intel(R) Audio Service\IntelAudioService.exe</Data> 
    <Data>C:\WINDOWS\System32\KERNELBASE.dll</Data> 
    <Data>6220b181-a7a0-4c44-9046-d8ce090d3a86</Data> 
    <Data /> 
    <Data />
  </EventData>
</Event>

```




