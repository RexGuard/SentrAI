from sentrai_ui import shaping as sh


def test_plural_reads_naturally():
    assert sh.plural(1, "action") == "1 action"
    assert sh.plural(2, "action") == "2 actions"
    assert sh.plural(0, "address", "addresses") == "0 addresses"
    assert sh.plural("?", "time") == "? times"
