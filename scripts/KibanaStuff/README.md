# General workflow - metrics

1. From the kibana WebUI create metric visualisation (we already have this implemented and that's why we can easily observe what's changing)
2. Export JSON file
3. Create metric visualisation using script, export JSON file and do diff
    ```
    from visualisation import MetricVisualisation

    t = MetricVisualisation("Metric vis")
    t.set_index_search(index_name="logstash*")

    with open("test.json", "w+") as f:
        f.write(t.json_export())
    ```
4. Depending on the metric, use according agg and param series (for Max metric, use MaxAgg and MaxParamSeries, etc)
5. You only should overwrite `__init__` method
6. Once implemented, test your metric. Use `metric_id` when providing `id` metric param. When adding metric, add other required attributes accordingly (in the below example, only id is required).
    ```
    from visualisation import MetricVisualisation
    from metrics import YourMetric

    t = MetricVisualisation("Metric vis")
    t.set_index_search(index_name="logstash*")
    t.add_metric(YourMetric(t.metric_id))
    # Or this way
    # t.add_metric(YourMetric(id=t.metric_id))

    with open("test.json", "w+") as f:
        f.write(t.json_export())
    ```

# General workflow - visualisation

This is kinda similar to metrics but one layer above and has no general instructions, sorry.

1. Generate visualisation from Kibana WebUI
2. Export JSON file
3. Investigate what's that and what we are missing from base class (if it requires axis, we have already basic `default_axis` method inside `BaseKibanaVisualizationDoc` - look how it's done in `AreaVisualisation`)
4. Implement it))
5. Test it
6. Not only import the JSON file but **open** the visualisation itself. Successful import doesn't mean that it will show anything in the visualisation!

---

# Useful table

| Aggs                                      | Params Series                                              |
| ----------------------------------------- | ---------------------------------------------------------- |
| class AverageAgg(BaseKibanaAgg)           | class AverageParamSeries(BaseKibanaSeriesParams)           |
| class CountAgg(BaseKibanaAgg)             | class CountParamSeries(BaseKibanaSeriesParams)             |
| class MaxAgg(BaseKibanaAgg)               | class MaxParamSeries(BaseKibanaSeriesParams)               |
| class MedianAgg(BaseKibanaAgg)            | class MedianParamSeries(BaseKibanaSeriesParams)            |
| class MinAgg(BaseKibanaAgg)               | class MinParamSeries(BaseKibanaSeriesParams)               |
| class PercentileRanksAgg(BaseKibanaAgg)   | class PercentileRanksParamSeries(BaseKibanaSeriesParams)   |
| class PercentilesAgg(BaseKibanaAgg)       | class PercentilesParamSeries(BaseKibanaSeriesParams)       |
| class StandardDeviationAgg(BaseKibanaAgg) | class StandardDeviationParamSeries(BaseKibanaSeriesParams) |
| class SumAgg(BaseKibanaAgg)               | class SumParamSeries(BaseKibanaSeriesParams)               |
| class TopHitsAgg(BaseKibanaAgg)           | class TopHitsParamSeries(BaseKibanaSeriesParams)           |
| class UniqueCountAgg(BaseKibanaAgg)       | class UniqueCountParamSeries(BaseKibanaSeriesParams)       |
| class DotSizeAgg(BaseKibanaAgg)           | -                                                          |

---

# Metrics

| Metric name           | Implemented? |
| --------------------- | ------------ |
| Average               | Yes          |
| Count                 | Yes          |
| Max                   |              |
| Median                |              |
| Min                   |              |
| PercentileRanks       |              |
| Percentiles           |              |
| StandardDeviation     |              |
| Sum                   |              |
| TopHits               |              |
| UniqueCount           |              |
| DotSize (kind of)     |              |

> | DotSize (kind of)     |              |
> DotSize is specific. I didn't dig into it but it doesn't required series params. Maybe it's the only difference, I don't know at the moment

---

# Visualisations

> Priority by the order

| Name                  | Implemented? |
| --------------------- | ------------ |
| Metric                | Yes          |
| Horizontal Bar        |              |
| Vertical Bar          |              |
| Pie                   |              |
| Line                  |              |
| Data Table            |              |
| Goal                  |              |
| Gauge                 |              |
| Area                  | Yes          |
| Heat Map              |              |
| Markdown              |              |
| Tag Cloud             |              |
| Region Map            |              |
| Timelion              |              |
| Coordinate Map        |              |
| Visual Builder        |              |
| Controls (E)          |              |
| Vega (E)              |              |