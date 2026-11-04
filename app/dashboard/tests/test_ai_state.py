from sentrai_ui import shaping as sh


def test_ai_tile_never_claims_on_without_word_from_the_core():
    assert sh.ai_classifier_state("enabled") == ("On", "asked when the rules are unsure")
    assert sh.ai_classifier_state("disabled: TYPESAFE_API_KEY not set (fallback classifier in use)") == \
        ("Off", "TYPESAFE_API_KEY not set")
    assert sh.ai_classifier_state("disabled") == ("Off", "keyword fallback in use")
    assert sh.ai_classifier_state(None) == ("Unknown", "the core did not report it")


def test_without_a_jev_agent_the_typesafe_extension_row_says_why():
    assert sh.ai_classifier_state(None, {"added": False}) == ("Off", "TypeSafe extension not added")
    assert sh.ai_classifier_state(None, {"added": True, "configured": False}) == ("Off", "no TypeSafe key saved")
    assert sh.ai_classifier_state(None, {"added": True, "configured": True, "last_error": "timed out"}) == \
        ("Off", "timed out")
    assert sh.ai_classifier_state(None, {"added": True, "configured": True})[0] == "On"
    assert sh.ai_classifier_state("disabled: no key", {"added": True})[1] == "no key"  # the agent's word first
