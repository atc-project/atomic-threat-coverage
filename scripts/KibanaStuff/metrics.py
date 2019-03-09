#!/usr/bin/env python3

# ########################################################################### #
# ############################ Base Classes ################################# #
# ########################################################################### #

import json
import datetime


class BaseKibanaAgg:
    """Base Kibana Agg"""

    def __init__(self, id=None, enabled=None, type=None, schema=None,
                 params=None):

        self.id = str()
        self.enabled = True  # By default agg is enabled
        self.type = str()
        self.schema = str()
        self.params = dict()

        if id:
            self.id = id

        if enabled:
            self.enabled = enabled

        if type:
            self.type = type

        if schema:
            self.schema = schema  # propably 'metric'

        if params:
            self.params = params

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__


class BaseKibanaVisState:
    """Base Kibana visState"""

    def __init__(self, title=None, type=None, params=None, aggs=None):

        self.title = str()
        self.type = str()
        self.params = dict()
        self.aggs = list()

        if title:
            self.title = title

        if type:
            self.type = type

        if params:
            self.params = params

        if aggs:
            self.aggs = aggs

    def __call__(self):

        return json.dumps(self.__dict__)


class BaseKibanaParams:
    """Base Kibana Params"""

    def __init__(self, type=None, grid=None, categoryAxes=None, valueAxes=None,
                 seriesParams=None, addTooltip=None, addLegend=None,
                 legendPosition=None, times=None, addTimeMarker=None):

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

        if type:
            self.type = type

        if grid:
            self.grid = grid

        if categoryAxes:
            self.categoryAxes = categoryAxes

        if valueAxes:
            self.valueAxes = valueAxes

        if seriesParams:
            self.seriesParams = seriesParams

        if addTooltip:
            self.addTooltip = addTooltip

        if addLegend:
            self.addLegend = addLegend

        if legendPosition:
            self.legendPosition = legendPosition

        if times:
            self.times = times

        if addTimeMarker:
            self.addTimeMarker = addTimeMarker

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
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

        self.updated_at = datetime.datetime.today().isoformat() + "Z"
        return self.__dict__


class KibanaVisualizationDoc(BaseKibanaDoc):
    """Kibana Visualization Doc"""

    def __init__(self):

        super().__init__()  # Init Base Class
        self.type = "visualization"
        self.visualization = dict()


class KibanaDashboardDoc(BaseKibanaDoc):
    """Kibana Visualization Doc"""

    def __init__(self):

        super().__init__()  # Init Base Class
        self.type = "dashboard"
        self.dashboard = dict()
