from datetime import timedelta

from tiled.adapters.mapping import MapAdapter


def test_new_variation_uses_given_metadata():
    adapter = MapAdapter({}, metadata={"a": 1})
    assert adapter.new_variation(metadata={"b": 2}).metadata() == {"b": 2}
    assert adapter.new_variation().metadata() == {"a": 1}


def test_new_variation_keeps_metadata_stale_after():
    adapter = MapAdapter(
        {},
        entries_stale_after=timedelta(seconds=1),
        metadata_stale_after=timedelta(seconds=2),
    )
    variation = adapter.new_variation()
    assert variation.entries_stale_after == timedelta(seconds=1)
    assert variation.metadata_stale_after == timedelta(seconds=2)
