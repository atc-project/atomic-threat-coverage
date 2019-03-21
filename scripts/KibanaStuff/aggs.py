#!/usr/bin/env python3

from base import BaseKibanaAgg

# ########################################################################### #
# ############################ Aggs ######################################### #
# ########################################################################### #

#
# 1. Metrics
# 2. Buckets
#

# ########################################################################### #
# ############################ Metrics ###################################### #
# ########################################################################### #


class AverageAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):
        """field - field name which should be averaged"""

        super().__init__(
            id=id, enabled=enabled, type="avg", schema="metric", params={
                "field": field
            }
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()


class CountAgg(BaseKibanaAgg):

    def __init__(self, id, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={}, schema="metric", type="count"
        )


class MaxAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={"field": field}, schema="metric",
            type="max"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()


class MedianAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field, "percents": [50]
            }, schema="metric", type="median"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()


class MinAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={"field": field}, schema="metric",
            type="min"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()


class PercentileRanksAgg(BaseKibanaAgg):

    def __init__(self, id, field, percentile_ranks, enabled=None):
        """percentile_ranks is a list"""

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field, "values": percentile_ranks
            }, schema="metric", type="percentile_ranks"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        # TODO: Write custom validate (check if percentile_rank is valid list)
        return super().validate()


class PercentilesAgg(BaseKibanaAgg):

    def __init__(self, id, field, percents=None, enabled=None):

        if not percents:
            percents = [1, 5, 25, 50, 75, 95, 99]

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field, "percents": percents
            }, schema="metric", type="percentiles"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        # TODO: Write custom validate (check if percents is valid list)
        return super().validate()


class StandardDeviationAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field
            }, schema="metric", type="std_dev"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()


class SumAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field
            }, schema="metric", type="sum"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()


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

    def validate(self):
        # TODO: Write custom validate (validate every required field)
        """
        sort_order - either `asc` or `desc`
        size - int positive number
        aggregate_with - ["average", "concat", "min", "max", "sum"]
"""
        return super().validate()


class UniqueCountAgg(BaseKibanaAgg):

    def __init__(self, id, field, enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field
            }, schema="metric", type="cardinality"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()


class DotSizeAgg(BaseKibanaAgg):
    # TODO: Develop it further
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

    def validate(self):
        # TODO: Write custom validate
        # (validate field based on given aggregation type)
        return super().validate()


class SplitSlicesTermsAgg(BaseKibanaAgg):

    def __init__(self, id, field, size, order=None, order_by=None,
                 other_bucket=None, other_bucket_label=None,
                 missing_bucket=None, missing_bucket_label=None,
                 enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field
            }, schema="metric", type="cardinality"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()

# ########################################################################### #
# ############################ Buckets ###################################### #
# ########################################################################### #


class DateHistogramAgg(BaseKibanaAgg):

    def __init__(self, id, field, time_range_from, time_range_to,
                 time_range_mode, drop_partial_buckets=False,
                 time_zone="America/Los_Angeles", enabled=None):

        super().__init__(
            id=id, enabled=enabled, params={
                "field": field,
                "timeRange": {
                    "from": time_range_from,
                    "to": time_range_to,
                    "mode": time_range_mode
                },
                "useNormalizedEsInterval": True,
                "interval": "auto",
                "time_zone": time_zone,
                "drop_partials": drop_partial_buckets,
                "customInterval": "2h",
                "min_doc_count": 1,
                "extended_bounds": {}
            }, schema="segment", type="date_histogram"
        )

    def validate(self):
        # TODO: Write custom validate (check if field exists in elastic)
        return super().validate()
