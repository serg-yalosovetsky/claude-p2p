"""The MCP server explains itself: rules resource, rules tool, live state in them."""

import asyncio

from claude_p2p import mcp_server
from claude_p2p.node import Node


def test_rules_resource_and_tool(tmp_path, monkeypatch):
    root = tmp_path / "me"
    monkeypatch.setenv("CLAUDE_P2P_HOME", str(root))
    n = Node.init("me", "http://x", root=root)
    peer = Node.init("papa", "", root=tmp_path / "papa")
    n.add_peer(peer.invite())
    n.store.set_allow_tasks("papa", True)
    monkeypatch.setattr(mcp_server, "_node", None)

    async def check():
        res = await mcp_server.mcp.read_resource("p2p://rules")
        text = res[0].content if hasattr(res[0], "content") else res[0].text
        tools = {t.name for t in await mcp_server.mcp.list_tools()}
        return text, tools

    text, tools = asyncio.run(check())
    assert "UNTRUSTED DATA" in text
    assert "wake modes of this node: prompt" in text
    assert "- papa (may send you tasks)" in text
    assert {"p2p_rules", "p2p_send", "p2p_await_reply", "p2p_inbox", "p2p_peers"} <= tools
    assert mcp_server.p2p_rules() == text
    assert "p2p://rules" in mcp_server.INSTRUCTIONS


def test_rules_before_init(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_P2P_HOME", str(tmp_path / "nothing"))
    monkeypatch.setattr(mcp_server, "_node", None)
    assert "run `p2p init`" in mcp_server.p2p_rules()
