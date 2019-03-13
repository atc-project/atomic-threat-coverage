#!/usr/bin/env python3

import base
import json
import uuid

from metrics import BaseMetric
from ast import literal_eval


class KibanaVisualizationDoc(base.BaseKibanaDoc):
    """Kibana Visualization Doc"""

    def __init__(self, title, index_name):

        super().__init__()  # Init Base Class
        self.metric_id = 1
        self.type = "visualization"
        self.visualization = base.BaseKibanaVisualizationObject(title=title)
        self.visualization.visState = base.BaseKibanaVisState(
            title=title, type="line")
        self.visualization.visState.params = base.BaseKibanaParams()
        self.visualization.kibanaSavedObjectMeta["searchSourceJSON"] = \
            "{\"index\":\"%s-*\",\"query\":{\"query_string\":{" % index_name +\
            "\"analyze_wildcard\":true,\"query\":\"*\"}},\"filter\":[]}"
        self.some_defaults()

    def some_defaults(self):

        # TODO: Make class for that
        self.visualization.visState.params.valueAxes.append({
            "id": "ValueAxis-1",
            "labels": {
                "filter": False,
                "rotate": 0,
                "show": True,
                "truncate": 100
            }})

        # TODO: Make class for that
        self.visualization.visState.params.categoryAxes.append(
            {
                "id": "CategoryAxis-1",
                "labels": {
                    "show": True,
                    "truncate": 100
                },
                "position": "bottom",
                "scale": {
                    "type": "linear"
                },
                "show": True,
                "style": {},
                "title": {},
                "type": "category"
            }
        )

    def add_metric(self, metric):
        if not issubclass(metric.__class__, BaseMetric):
            raise Exception("Are you trying to add non-metric?")
        self.visualization.visState.aggs.append(metric.agg())
        self.visualization.visState.params.seriesParams.append(metric.param())
        self.metric_id += 1

    def json_export(self):
        """visState has to be a string with escaped doublequotes"""
        if self.validate():
            # self.updated_at = datetime.datetime.today().isoformat() + "Z"
            # TODO: Find proper way to do below line :))
            tmp_dictionary = literal_eval(str(self.__dict__))
            tmp_dictionary["_id"] = str(uuid.uuid4())
            tmp_dictionary["_type"] = tmp_dictionary.pop("type")
            tmp_dictionary["visualization"]["visState"] = json.dumps(
                tmp_dictionary["visualization"]["visState"]
            )
            tmp_dictionary.pop("metric_id", None)
            tmp_dictionary.pop("updated_at", None)
            tmp_dictionary["_source"] = tmp_dictionary.pop("visualization")
            return json.dumps([tmp_dictionary])
        else:
            raise Exception("Data validation failed")
