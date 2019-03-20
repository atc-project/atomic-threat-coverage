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
                 showCircles=None, args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'interpolate' in args:
                interpolate = args['interpolate']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

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
                 valueAxis=None, mode=None, showCircles=None, args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.CountAgg(id=str(id), enabled=enabled)
        self.param_var = params.CountParamSeries(
            id=str(id), enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Max ########################################## #
# ########################################################################### #


class MaxMetric(BaseMetric):

    def __init__(self, id, field, enabled=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None, args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.MaxAgg(id=str(id), field=field, enabled=enabled)
        self.param_var = params.MaxParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Median ####################################### #
# ########################################################################### #


class MedianMetric(BaseMetric):

    def __init__(self, id, field, enabled=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None, args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.MedianAgg(id=str(id), field=field, enabled=enabled)
        self.param_var = params.MedianParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Min ########################################## #
# ########################################################################### #


class MinMetric(BaseMetric):

    def __init__(self, id, field, enabled=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None, args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.MinAgg(id=str(id), field=field, enabled=enabled)
        self.param_var = params.MinParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Percentile Ranks ############################# #
# ########################################################################### #


class PercentileRanksMetric(BaseMetric):

    def __init__(self, id, field, percentile_ranks, enabled=None, type=None,
                 label=None, valueAxis=None, mode=None, showCircles=None,
                 args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']
            if 'percentile_ranks' in args:
                percentile_ranks = args['percentile_ranks']

        self.agg_var = aggs.PercentileRanksAgg(
            id=str(id), field=field, percentile_ranks=percentile_ranks,
            enabled=enabled
        )
        self.param_var = params.PercentileRanksParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Percentiles ################################## #
# ########################################################################### #


class PercentilesMetric(BaseMetric):

    def __init__(self, id, field, percents=None, enabled=None, type=None,
                 label=None, valueAxis=None, mode=None, showCircles=None,
                 args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'percents' in args:
                percents = args['percents']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.PercentilesAgg(
            id=str(id), field=field, percents=percents, enabled=enabled
        )
        self.param_var = params.PercentilesParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Standard Deviation ########################### #
# ########################################################################### #


class StandardDeviationMetric(BaseMetric):

    def __init__(self, id, field, enabled=None, type=None,
                 label=None, valueAxis=None, mode=None, showCircles=None,
                 args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.StandardDeviationAgg(
            id=str(id), field=field, enabled=enabled
        )
        self.param_var = params.StandardDeviationParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Sum ########################################## #
# ########################################################################### #


class SumMetric(BaseMetric):

    def __init__(self, id, field, enabled=None, type=None,
                 label=None, valueAxis=None, mode=None, showCircles=None,
                 args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.SumAgg(
            id=str(id), field=field, enabled=enabled
        )
        self.param_var = params.SumParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Top Hits ##################################### #
# ########################################################################### #


class TopHitsMetric(BaseMetric):

    def __init__(self, id, field, aggregate_with, size, sort_order, sort_field,
                 enabled=None, type=None, label=None, valueAxis=None,
                 mode=None, showCircles=None, args=None):

        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.TopHitsAgg(
            id=str(id), field=field, aggregate_with=aggregate_with, size=size,
            sort_order=sort_order, sort_field=sort_field, enabled=enabled
        )
        self.param_var = params.TopHitsParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )

# ########################################################################### #
# ############################ Unique Count ################################# #
# ########################################################################### #


class UniqueCountMetric(BaseMetric):

    def __init__(self, id, field, enabled=None, type=None,
                 label=None, valueAxis=None, mode=None, showCircles=None,
                 args=None):
        if args:
            if 'enabled' in args:
                enabled = args['enabled']
            if 'type' in args:
                type = args['type']
            if 'label' in args:
                label = args['label']
            if 'valueAxis' in args:
                valueAxis = args['valueAxis']
            if 'mode' in args:
                mode = args['mode']
            if 'showCircles' in args:
                showCircles = args['showCircles']

        self.agg_var = aggs.UniqueCountAgg(
            id=str(id), field=field, enabled=enabled
        )
        self.param_var = params.UniqueCountParamSeries(
            id=str(id), field=field, enabled=enabled, type=type, label=label,
            valueAxis=valueAxis, mode=mode, showCircles=showCircles
        )
