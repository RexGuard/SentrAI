"""The notifier keeps its last fingerprint in notifier/ in the data root."""
import notifier


def test_witness_lives_in_the_data_root(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_HOME", str(tmp_path))
    monkeypatch.delenv("NOTIFIER_WITNESS_FILE", raising=False)
    store = notifier.WitnessStore()
    assert store.path == tmp_path / "notifier" / "last_witness.txt"
    store.save("abc")
    assert store.path.exists()
    monkeypatch.setenv("NOTIFIER_WITNESS_FILE", str(tmp_path / "w.txt"))
    assert notifier.WitnessStore().path == tmp_path / "w.txt"
