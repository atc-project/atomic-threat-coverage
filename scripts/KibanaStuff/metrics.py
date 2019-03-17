#!/usr/bin/env python3

import aggs
import params

# ########################################################################### #
# ############################ Metrics ###################################### #
# ########################################################################### #


class BaseMetric:

    def __init__(self, id):
        self.agg_var = None
        self.param_var = None

    def agg(self):
        return self.agg_var()

    def param(self):
        return self.param_var()

# ########################################################################### #
# ############################ Area ######################################### #
# ########################################################################### #


class AverageMetric(BaseMetric):

    def __init__(self, id, field, enabled=None, type=None, label=None,
                 valueAxis=None, interpolate=None, mode=None,
                 showCircles=None):
        self.agg_var = aggs.AverageAgg(id=str(id), field=field,
                                       enabled=enabled)
        self.param_var = params.AverageParamSeries(
            id=str(id), enabled=enabled, field=field, type=type, label=label,
            valueAxis=valueAxis, interpolate=interpolate, mode=mode,
            showCircles=showCircles
        )

# ########################################################################### #
# ############################ Count ######################################## #
# ########################################################################### #


class CountMetric(BaseMetric):

    def __init__(self, id, enabled=None, type=None, label=None,
                 valueAxis=None, interpolate=None, mode=None,
                 showCircles=None):
        self.agg_var = aggs.CountAgg(id=str(id), enabled=enabled)
        self.param_var = params.CountParamSeries(
            id=str(id), enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )
