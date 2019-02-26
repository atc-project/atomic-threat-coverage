#!/bin/env python3

# ########################################################################### #
# ############################ Base Classes ################################# #
# ########################################################################### #


class BaseKibanaAggs:
    """Base Kibana Aggs"""

    id = str
    enabled = str
    type = str
    schema = str
    params = {
        "field": "",
        "customLabel": "",
    }

    def __call__(self):

        return self.__dict__


class BaseKibanaVisState:
    """Base Kibana visState"""

    title = str
    type = str
    params = {}
    aggs = []

    def __call__(self):

        return str(self.__dict__)


class BaseKibanaParams:
    """Base Kibana Params"""

    type = str
    grid = {}
    categoryAxes = []
    valueAxes = []
    seriesParams = []
    addTooltip = bool
    addLegend = bool
    legendPosition = str
    times = []
    addTimeMarker = bool

    def __call__(self):

        return self.__dict__


class BaseKibanaVisualization:
    """Base Kibana Visualization"""

    description = str
    kibanaSavedObjectMeta = {}
    title = str
    uiStateJSON = str
    version = int
    visState = str  # '{ some valid JSON }'

    def __call__(self):

        return self.__dict__

