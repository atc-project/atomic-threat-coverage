#!/usr/bin/env python3

from metrics import BaseKibanaAgg

# ########################################################################### #
# ############################ Aggs ######################################### #
# ########################################################################### #


class AverageAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):
        """field - field name which should be averaged"""

        super().__init__(
            id=id, enabled=enabled, type="avg", schema="metric", params={
                "field": field
            }
        )


class CountAgg(BaseKibanaAgg):

    def __init__(self, id, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={}, schema="metric", type="count"
        )


class MaxAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None, ):

        super().__init__(
            id=id, enabled=enabled, params={"field": field}, schema="metric",
            type="max"
        )


class MedianAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field, "percents": [50]
            }, schema="metric", type="median"
        )


class MinAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={"field": field}, schema="metric",
            type="min"
        )


class PercentileRanksAgg(BaseKibanaAgg):

    def __init__(self, id, field, percentile_ranks, enabled=None):
        """percentile_ranks is a list"""

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field, "values": percentile_ranks
            }, schema="metric", type="percentile_ranks"
        )


class PercentilesAgg(BaseKibanaAgg):

    def __init__(self, id, field, percents=None, enabled=None):

        if not percents:
            percents = [1, 5, 25, 50, 75, 95, 99]

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field, "percents": percents
            }, schema="metric", type="percentiles"
        )


class StandardDeviationAgg(BaseKibanaAgg):

    def __init__(self, id, enabled=None):

        super().__init__()


class SumAgg(BaseKibanaAgg):

    def __init__(self, id, enabled=None):

        super().__init__()


class TopHitsAgg(BaseKibanaAgg):

    def __init__(self, id, enabled=None):

        super().__init__()


class UniqueCountAgg(BaseKibanaAgg):

    def __init__(self, id, enabled=None):

        super().__init__()

