#!/usr/bin/env python3

# ########################################################################### #
# ############################ Base Classes ################################# #
# ########################################################################### #

import json
import datetime
import getpass
import requests


class BaseKibana:
    """kibana_url - link to Kibana main page"""

    username = str()
    password = str()
    _kibana_auth = None
    kibana_url = str()
    kibana_usage = None

    @classmethod
    def init_kibana_api(cls):
        # TODO: Do some checks, test connection, etc
        pass

    @classmethod
    def omit_kibana(cls):
        cls.kibana_usage = False

    @classmethod
    def init_credentials(cls):
        if cls.omit_kibana:
            _ = "n"
        else:
            _ = ""
        while _ not in ["y", "n"]:
            _ = input("Can I use Kibana? [y/n]: ")[0].lower()
        if _ == "n":
            cls.kibana_usage = False
            return False
        _ = ""
        while _ not in ["y", "n"]:
            _ = input("Does your Kibana instance requires " +
                      "auth? [y/n]: ")[0].lower()
        if _ == "y":
            cls._kibana_auth = True
            cls.username = input("Username [%s]: " % cls.username)
            cls.password = getpass.getpass(
                "Password [%s]: " % "".join(["*" for val in cls.password])
            )
        elif _ == "n":
            cls._kibana_auth = False

        cls.kibana_url = input("Provide Kibana URL (main page, for instance" +
                               " http://localhost:5601/): ")
        while True:
            print("KIBANA_URL: %s" % cls.kibana_url)
            _ = input("Is this correct? [y/n]: ")[0].lower()
            if _ == "y":
                break
            else:
                cls.kibana_url = input("Provide Kibana URL " +
                                       "(main page, for instance" +
                                       " http://localhost:5601/): ")
        cls.kibana_url = cls.kibana_url if cls.kibana_url.endswith("/") else \
            cls.kibana_url + "/"
        cls.kibana_usage = True
        return True

    @classmethod
    def check_kibana_vars(cls):
        if not isinstance(cls.kibana_usage, bool):
            return cls.init_credentials()
        if isinstance(cls._kibana_auth, bool):
            if cls._kibana_auth:
                if not cls.username or not cls.password:
                    return cls.init_credentials
            if not cls.kibana_url:
                return cls.init_credentials
        else:
            return cls.init_credentials
        return True

    @classmethod
    def search_id_of_title_by_type(cls, search_type, search_title):
        """Returns an ID (string) of an object searched using object title
search_type - string in ["index-pattern", "search"]
search_title - string
"""
        search_type = search_type.lower()
        if search_type not in ["index-pattern", "search"]:
            raise Exception("Search type (%s) not supported" % search_type)
        if cls.check_kibana_vars():
            result_dict = {}
            total_pages = int()
            current_page = 1
            suffix = "api/saved_objects/_find?" + \
                     "type=%s&fields=title&fields=id" % search_type

            r = requests.get(cls.kibana_url + suffix)

            if r.json().get("total"):
                total_pages = r.json().get("total")

            while current_page <= total_pages:
                if r.json().get("saved_objects"):
                    for item in r.json().get("saved_objects"):
                        if item.get("attributes"):
                            result_dict[item.get("attributes").get("title")] = \
                                item.get('id')
                if search_title in result_dict.keys():
                    return result_dict[search_title]
                else:
                    current_page += 1
                    r = requests.get(
                        cls.kibana_url + suffix + "&pages=%s" % current_page
                    )
            del (result_dict)
            return None


class BaseKibanaAgg(BaseKibana):
    """Base Kibana Agg"""

    def __init__(self, id=None, enabled=None, type=None, schema=None,
                 params=None):

        self.id = str()
        self.enabled = True  # By default agg is enabled
        self.type = str()
        self.schema = str()
        self.params = dict()

        if id is not None:
            self.id = id

        if enabled is not None:
            self.enabled = enabled

        if type is not None:
            self.type = type

        if schema is not None:
            self.schema = schema  # propably 'metric'

        if params is not None:
            self.params = params

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())


class BaseKibanaSeriesParams(BaseKibana):
    """Base Kibana Series Params"""

    def __init__(self, id, data=None, drawLinesBetweenPoints=None,
                 mode=None, show=None, showCircles=None, type=None,
                 valueAxis=None, interpolate=None):

        self.data = dict()
        self.drawLinesBetweenPoints = bool()
        self.mode = str()
        self.show = bool()
        self.showCircles = bool()
        self.p_type = str()
        self.valueAxis = str()
        self.interpolate = str()

        if data is not None:
            self.data = data

        if drawLinesBetweenPoints is not None:
            self.drawLinesBetweenPoints = drawLinesBetweenPoints

        if mode is not None:
            self.mode = mode

        if show is not None:
            self.show = show

        if showCircles is not None:
            self.showCircles = showCircles

        if type is not None:
            self.type = type

        if valueAxis is not None:
            self.valueAxis = valueAxis

        if interpolate is not None:
            self.interpolate = interpolate

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())


class BaseKibanaVisState(BaseKibana):
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

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return json.dumps(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

    def __iter__(self):
        return iter(self.__dict__)


class BaseKibanaParams(BaseKibana):
    """Base Kibana Params"""

    def __init__(self, type=None, grid=None, categoryAxes=None, valueAxes=None,
                 seriesParams=None, addTooltip=None, addLegend=None,
                 legendPosition=None, times=None, addTimeMarker=None):

        self.type = str()
        self.grid = dict()
        self.categoryAxes = list()
        self.valueAxes = list()  # This isn't a mistake (not confuse with Axis)
        self.seriesParams = list()
        self.addTooltip = True
        self.addLegend = True
        self.legendPosition = str()
        self.times = list()
        self.addTimeMarker = False

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

    def __repr__(self):
        return str(self.__call__())


class BaseKibanaVisualizationObject(BaseKibana):
    """Base Kibana VisualizationObject"""

    def __init__(self, title=None):

        self.description = str()
        self.kibanaSavedObjectMeta = dict()
        self.title = str()
        self.uiStateJSON = str()
        self.version = 1
        self.visState = str()  # '{ some valid JSON }'

        if title:
            self.title = title

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())


class BaseGridData(BaseKibana):
    """Base gridData"""

    def __init__(self, x=0, y=0, w=0, h=0, vid=1):
        self.w = w
        self.h = h
        self.x = x
        self.y = y
        self.i = str(vid)

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())


class BasePanelsJson(BaseKibana):
    """Base panelsJSON"""

    def __init__(self, vis_uuid=None, vis_id=None, version="6.6.2",
                 type="visualization"):
        self.embeddableConfig = dict()
        self.gridData = BaseGridData()
        self.id = str()
        self.panelIndex = str()
        self.type = type
        self.version = version

        if vis_uuid:
            self.id = vis_uuid

        if vis_id:
            self.panelIndex = str(vis_id)
            self.gridData.i = str(vis_id)

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())


class BaseOptionsJson(BaseKibana):
    """Base optionsJSON"""

    def __init__(self):
        self.darkTheme = bool()
        self.hidePanelTitles = bool()
        self.useMargins = bool()

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())


class BaseKibanaDoc(BaseKibana):
    """Base Kibana Doc"""

    def __init__(self):
        self.type = str()
        self.updated_at = str()

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            self.updated_at = datetime.datetime.today().isoformat() + "Z"
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())


class KibanaDashboardDoc(BaseKibanaDoc):
    """Kibana Visualization Doc"""

    def __init__(self):
        super().__init__()  # Init Base Class
        self.type = "dashboard"
        self.dashboard = dict()
