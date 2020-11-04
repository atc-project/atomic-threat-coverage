| Title              | EN_0001_cache_sysmon_event_id_1_info |
|:-------------------|:-----------------------------------------------------------------------------------------------------------------|
| **Description**    | Cache Sysmon Event ID 1 (Process Create) data for further enrichments. |
| **Data Needed**    |<ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul> |
| **Data to enrich** | None |
| **References**     |<ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li></ul> |
| **Author**         | Teymur Kheirkhabarov           |
| **Requirements**   | None |
| **New fields**     | None |


### Config

We can use Logstash to cache data in Memcached. 
Here is the config example:

```
filter {
  # Building information block for caching:
  if [source_name] == "Microsoft-Windows-Sysmon" and [event_id] == 1 {
    mutate {
      add_field => {
        "[@metadata][processinfo]" => "IntegrityLevel=%{[event_data][IntegrityLevel]},User=%{[event_data][User]},CommandLine=${[event_data][CommandLine]},ParentImage=%{[event_data][ParentImage]}"
      }
    }
    # Saving previously built information block in cache (key is concatenation of ProcessGuid and computer_name):
    memcached {
      hosts => ["127.0.0.1:11211"]
      set => {
        "[@metadata][processinfo]" => "%{computer_name}_{[event_data][ProcessGuid]}"
      }
      ttl => 86400 # 24 hours
    }
  }
}
```
