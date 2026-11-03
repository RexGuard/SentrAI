"""`sentrai mcp`: your own Claude sees SentrAI's blocks and keeps or undoes them (mvp/sentrai_mcp.py)."""
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import sentrai_mcp as mcp  # noqa: E402

from .conftest import brute_force  # noqa: E402


def through(client):
    """The core API through the test client, failing the way the CLI's call does (as a ToolError)."""
    def call(method, path, body=None):
        r = client.request(method, path, json=body)
        if r.status_code >= 400:
            raise mcp.ToolError(f"{r.status_code}: {r.json().get('detail')}")
        return r.json()
    return call


def session(client, *messages):
    """Run the server over a whole stdin and return its answers by id."""
    inp = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    out = io.StringIO()
    mcp.serve(through(client), "claude:erick", inp, out)
    return {a["id"]: a for a in map(json.loads, out.getvalue().splitlines())}


def tool(client, name, **args):
    answer = session(client, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": name, "arguments": args}})[1]["result"]
    return answer["content"][0]["text"], answer["isError"]


def blocked(client):
    brute_force(client)
    iid = client.get("/incidents").json()[0]["id"]
    client.post(f"/incidents/{iid}/decision", json={"operator": "erick", "decision": "approve"})
    return iid


def test_handshake_and_tool_list(client):
    out = session(client,
                  {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}},
                  {"jsonrpc": "2.0", "method": "notifications/initialized"},
                  {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                  {"jsonrpc": "2.0", "id": 3, "method": "nope"})
    assert out[1]["result"]["protocolVersion"] == "2025-06-18" and "tools" in out[1]["result"]["capabilities"]
    tools = {t["name"]: t for t in out[2]["result"]["tools"]}
    assert set(tools) == {"list_blocks", "undo_block", "keep_block"}
    # Claude asks the person before anything that changes a block.
    assert tools["list_blocks"]["annotations"]["readOnlyHint"]
    assert tools["undo_block"]["annotations"]["destructiveHint"] and tools["keep_block"]["annotations"]["destructiveHint"]
    assert out[3]["error"]["code"] == -32601 and len(out) == 3  # the notification gets no answer


def test_list_shows_blocks_and_whether_they_are_real(client):
    assert tool(client, "list_blocks")[0].startswith("SentrAI is not blocking anything")
    iid = blocked(client)
    text, err = tool(client, "list_blocks")
    assert not err and iid in text and "203.0.113.45" in text
    assert "TEST ONLY" in text and "on the block list" in text  # the rate limit is only simulated in the lab


def test_undo_lifts_the_blocks_and_is_logged_as_claude(client):
    iid = blocked(client)
    text, err = tool(client, "undo_block", incident=iid, reason="that was our office")
    assert not err and text.startswith(f"Undid the blocks on {iid}") and "(undone)" in text
    inc = client.get(f"/incidents/{iid}").json()
    assert all(a["status"] != "active" for a in inc["actions"])
    assert inc["decisions"][-1] == {**inc["decisions"][-1], "operator": "claude:erick", "decision": "rollback",
                                    "justification": "that was our office"}
    assert tool(client, "list_blocks")[0].startswith("SentrAI is not blocking anything")


def test_keep_makes_the_blocks_permanent(client):
    iid = blocked(client)
    text, err = tool(client, "keep_block", incident=iid, reason="they keep coming back")
    assert not err and "kept for good" in text
    inc = client.get(f"/incidents/{iid}").json()
    assert inc["status"] == "resolved" and {a["status"] for a in inc["actions"]} == {"permanent"}
    assert "SentrAI is not blocking" in tool(client, "list_blocks")[0]
    assert iid in tool(client, "list_blocks", include_kept=True)[0]


def test_mistakes_come_back_as_plain_tool_errors(client):
    iid = blocked(client)
    assert tool(client, "undo_block", incident=iid, reason="")[1]
    text, err = tool(client, "undo_block", incident="RSK-2099-999", reason="x")
    assert err and "404" in text
    tool(client, "undo_block", incident=iid, reason="ours")
    text, err = tool(client, "undo_block", incident=iid, reason="again")
    assert err and "no active containment" in text


def test_the_cli_starts_it(client, monkeypatch):
    import sentrai_cli as cli
    blocked(client)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "list_blocks", "arguments": {}}}) + "\n"))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)

    def call(method, path, body=None):
        r = client.request(method, path, json=body)
        return r.json()
    assert cli.main(["mcp"], call=call) == 0
    assert "203.0.113.45" in json.loads(out.getvalue())["result"]["content"][0]["text"]
