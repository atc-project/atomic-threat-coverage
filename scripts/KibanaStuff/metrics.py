#!/bin/env python3

# ########################################################################### #
# ############################ Base Classes ################################# #
# ########################################################################### #

import json


class BaseKibanaAgg:
    """Base Kibana Agg"""

    def __init__(self):

        self.id = str()
        self.enabled = str()
        self.type = str()
        self.schema = str()
        self.params = {
            "field": "",
            "customLabel": "",
        }

    def __call__(self):

        return self.__dict__


class BaseKibanaVisState:
    """Base Kibana visState"""

    def __init__(self):

        self.title = str()
        self.type = str()
        self.params = dict()
        self.aggs = list()

    def __call__(self):

        return json.dumps(self.__dict__)


class BaseKibanaParams:
    """Base Kibana Params"""

    def __init__(self):

        self.type = str()
        self.grid = dict()
        self.categoryAxes = list()
        self.valueAxes = list()
        self.seriesParams = list()
        self.addTooltip = bool()
        self.addLegend = bool()
        self.legendPosition = str()
        self.times = list()
        self.addTimeMarker = bool()

    def __call__(self):

        return self.__dict__


class BaseKibanaVisualizationObject:
    """Base Kibana VisualizationObject"""

    def __init__(self):

        self.description = str()
        self.kibanaSavedObjectMeta = dict()
        self.title = str()
        self.uiStateJSON = str()
        self.version = int()
        self.visState = str()  # '{ some valid JSON }'

    def __call__(self):

        return self.__dict__


class BaseKibanaDoc:
    """Base Kibana Doc"""

    def __init__(self):

        self.type = str()
        self.updated_at = str()

    def __call__(self):

        return self.__dict__


class KibanaVisualizationDoc(BaseKibanaDoc):
    """Kibana Visualization Doc"""

    def __init__(self):

        super().__init__()  # Init Base Class
        self.type = "visualization"
        self.visualization = dict()
