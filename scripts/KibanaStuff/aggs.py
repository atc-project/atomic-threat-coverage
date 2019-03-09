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

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field
            }, schema="metric", type="std_dev"
        )


class SumAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field
            }, schema="metric", type="sum"
        )


class TopHitsAgg(BaseKibanaAgg):

    def __init__(self, id, field, aggregate_with, size, sort_order, sort_field,
                 enabled=None):
        """aggregate_with - can be average, max, min or sum
size - integer
sort_order - can be asc or dsc
"""
        super().__init__(
            id=id, enabled=enabled, params={
                "aggregate": aggregate_with, "field": field,
                "size": size, "sortField": sort_field, "sortOrder": sort_order
            }, schema="metric", type="top_hits"
        )


class UniqueCountAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field
            }, schema="metric", type="cardinality"
        )


class DotSizeAgg(BaseKibanaAgg):

    def __init__(
        self, id, aggregation_type, field=None, aggregate_with=None, size=None,
        enabled=None, order=None
    ):

        if aggregation_type in ["avg", "max", "min", "sum", "cardinality"]\
                and not field:
            raise Exception("Field 'field' required for given aggregation " +
                            "type")

        if aggregation_type == "top_hits" and not field and not aggregate_with\
                and not size and not order:
            raise Exception("""For Top Hits following fields are also required:
* field - valid field for given index/search
* aggregate_with - avg/min/max/sum
* size - integer
* order - asc/dsc
""")

        super().__init__(
            id=id, enabled=enabled, type=aggregation_type, schema="radius",
            params={
                "field": field
            }
        )
