from visualisation import *
from metrics import *

t = PieVisualisation("First metric visualisation")
# t.set_saved_search(saved_search_name="Host_save_query_1")
# t.set_saved_search(saved_search_id="Saved-Qeury-1")
t.set_index_search(index_name="adsda*")

t.add_metric(CountMetric(t.metric_id))
t.add_metric(AverageMetric(t.metric_id, "port"))
t.add_metric(MaxMetric(t.metric_id, "port"))
t.add_metric(MinMetric(t.metric_id, "port"))
t.add_metric(MedianMetric(t.metric_id, "port"))
t.add_metric(PercentileRanksMetric(t.metric_id, "port", [1, 2, 3, 4, 5]))
t.add_metric(PercentilesMetric(t.metric_id, "port"))
t.add_metric(StandardDeviationMetric(t.metric_id, "port"))
t.add_metric(SumMetric(t.metric_id, "port"))
t.add_metric(TopHitsMetric(t.metric_id, "port", "average", 1, "asc", "port"))
t.add_metric(UniqueCountMetric(t.metric_id, "port"))


with open("test.json", "w+") as f:
    f.write(t.json_export())
