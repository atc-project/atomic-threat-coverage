#!/usr/bin/env python3

from atc_visualizations.base import BaseKibanaSeriesParams

# ########################################################################### #
# ############################ Params ####################################### #
# ########################################################################### #


class AverageParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, interpolate=None, mode=None,
                 showCircles=None):

        if not label and field:
            label = "Average %s" % field
        elif not label and not field:
            label = "Average"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not interpolate:
            interpolate = "linear"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles,
            interpolate=interpolate
        )


class CountParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label:
            label = "Count"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class MaxParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Max %s" % field
        elif not label and not field:
            label = "Max"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class MedianParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Median %s" % field
        elif not label and not field:
            label = "Median"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class MinParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Min %s" % field
        elif not label and not field:
            label = "Min"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class PercentileRanksParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Percentiles ranks of %s" % field
        elif not label and not field:
            label = "Percentiles ranks"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class PercentilesParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Percentiles of %s" % field
        elif not label and not field:
            label = "Percentiles"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class StandardDeviationParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Standard Deviation of %s" % field
        elif not label and not field:
            label = "Standard Deviation"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class SumParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Sum of %s" % field
        elif not label and not field:
            label = "Sum"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class TopHitsParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Top Hits of %s" % field
        elif not label and not field:
            label = "Top Hits"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )


class UniqueCountParamSeries(BaseKibanaSeriesParams):

    def __init__(self, id, enabled=None, field=None, type=None, label=None,
                 valueAxis=None, mode=None, showCircles=None):

        if not label and field:
            label = "Unique count of %s" % field
        elif not label and not field:
            label = "Unique count"

        if not type:
            type = "line"

        if not valueAxis:
            valueAxis = "ValueAxis-1"

        if not mode:
            mode = "normal"

        if not enabled:
            enabled = True

        if not showCircles:
            showCircles = True

        super().__init__(
            id=id, data={
                "id": id, "label": label
            }, drawLinesBetweenPoints=True, mode=mode, show=enabled,
            type=type, valueAxis=valueAxis, showCircles=showCircles
        )

# Apparently, no such thing
# class DotSizeParamSeries(BaseKibanaSeriesParams):

#     def __init__(self):
#         pass
