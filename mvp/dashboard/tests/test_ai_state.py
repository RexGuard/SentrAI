from sentrai_ui import shaping as sh


def test_ai_tile_never_claims_on_without_word_from_the_core():
    assert sh.ai_classifier_state("enabled") == ("On", "asked when the rules are unsure")
    assert sh.ai_classifier_state("disabled: TYPESAFE_API_KEY not set (fallback classifier in use)") == \
        ("Off", "TYPESAFE_API_KEY not set")
    assert sh.ai_classifier_state("disabled") == ("Off", "keyword fallback in use")
    assert sh.ai_classifier_state(None) == ("Unknown", "the core did not report it")
