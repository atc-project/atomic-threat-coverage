#!/usr/bin/env python3

import base
from metrics import BaseMetric


class KibanaVisualizationDoc(base.BaseKibanaDoc):
    """Kibana Visualization Doc"""

    def __init__(self):

        super().__init__()  # Init Base Class
        self._id = 1
        self.type = "visualization"
        self.visualization = base.BaseKibanaVisualizationObject()
        self.visualization.visState = base.BaseKibanaVisState()
        self.visualization.visState.params = base.BaseKibanaParams()

    def add_metric(self, metric):
        # if not issubclass(metric, BaseMetric):
        #     raise Exception("Are you trying to add non-metric?")

        self.visualization.visState.aggs.append(metric.agg())
        self.visualization.visState.params.seriesParams.append(metric.param())
        self._id += 1
