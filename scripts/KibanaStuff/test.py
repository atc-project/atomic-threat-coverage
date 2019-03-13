from visualisation import KibanaVisualizationDoc
from metrics import AreaMetric

t = KibanaVisualizationDoc("First ever script created visualisation", "logstash")
t.type = "visualization"
t.add_metric(AreaMetric(t.metric_id, "port"))
with open("test.json", "w+") as f:
    f.write(t.json_export())
print(t())
