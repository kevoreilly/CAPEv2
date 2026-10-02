"""Hunt aggregation builder — per-category $group (NO $facet, so it runs on
Amazon DocumentDB, which rejects $facet). Extracted from web/analysis/views.py
so it's unit-testable without importing the full web module graph; views.py
imports build_hunt_facets() and passes its mongo_aggregate in.

Returns the same shape the old $facet pipeline produced:
    {cat_id: [{"_id": <group key>, "count": <int>, "task_ids": [<int>...]}, ...]}
so the downstream clean_facets/validator loop is unchanged.
"""


def build_hunt_facets(mongo_aggregate, match, hunt_map, categories, min_count):
    facets = {}
    for cat_id, cat_config in hunt_map.items():
        if not categories.get(cat_id):
            continue
        stages = [{"$match": match}]
        if cat_config.get("db_unwind"):
            stages.append({"$unwind": cat_config["db_unwind"]})
        stages.extend([
            {"$group": {"_id": cat_config["db_group"], "count": {"$sum": 1}, "task_ids": {"$addToSet": "$info.id"}}},
            {"$match": cat_config.get("db_match", {"count": {"$gte": min_count}})},
            {"$sort": {"count": -1}},
            {"$limit": 100},
        ])
        facets[cat_id] = list(mongo_aggregate("analysis", stages))
    return facets
