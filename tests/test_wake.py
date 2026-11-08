"""Wake modes: how a session (or its owner) learns that peer mail arrived."""

import io
import json
import sqlite3
import sys

import pytest

from claude_p2p import cli, hook
from claude_p2p.node import Node
from claude_p2p.store import Store


@pytest.fixture
def node(tmp_path, monkeypatch):
    root = tmp_path / "me"
    monkeypatch.setenv("CLAUDE_P2P_HOME", str(root))
    n = Node.init("me", "http://x", root=root)
    other = Node.init("peer", "http://y", root=tmp_path / "peer")
    n.add_peer(other.invite())
    other.add_peer(n.invite())
    return n, other


def _deliver(n, other, text="hi there"):
    sent = other.send("me", text, deliver=False)
    env = json.loads(other.store._db.execute(
        "SELECT envelope FROM messages WHERE id=?", (sent["id"],)).fetchone()[0])
    assert n.receive(env)[0] == 202
    return sent["id"]


def _run_hook(monkeypatch, capsys, event):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": event})))
    assert hook.main() == 0
    out = capsys.readouterr().out
    return json.loads(out) if out.strip() else None


def test_prompt_hook_announces_each_message_once(node, monkeypatch, capsys):
    n, other = node
    msg_id = _deliver(n, other)
    out = _run_hook(monkeypatch, capsys, "UserPromptSubmit")
    ctx = out["hookSpecificOutput"]
    assert ctx["hookEventName"] == "UserPromptSubmit"
    assert msg_id in ctx["additionalContext"] and "untrusted" in ctx["additionalContext"]
    assert _run_hook(monkeypatch, capsys, "UserPromptSubmit") is None
    # Announced is not read: the session still gets it from p2p_inbox.
    assert [m["id"] for m in n.store.inbox()] == [msg_id]


def test_tool_hook_only_when_mode_on(node, monkeypatch, capsys):
    n, other = node
    _deliver(n, other)
    assert _run_hook(monkeypatch, capsys, "PostToolUse") is None  # default: prompt only
    n.config.wake = ["prompt", "tool"]
    n.config.save(n.root / "config.json")
    out = _run_hook(monkeypatch, capsys, "PostToolUse")
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"


def test_prompt_hook_silent_when_mode_off(node, monkeypatch, capsys):
    n, other = node
    n.config.wake = ["watch"]
    n.config.save(n.root / "config.json")
    _deliver(n, other)
    assert _run_hook(monkeypatch, capsys, "UserPromptSubmit") is None


def test_watch_prints_a_line_and_marks_announced(node, capsys):
    n, other = node
    msg_id = _deliver(n, other, "line\nbreaks are flattened")
    assert cli.watch(n, interval=0.01, once=True) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1 and msg_id in out[0] and "line breaks are flattened" in out[0]
    assert n.store.unnotified() == []


def test_desktop_notification_argv_without_shell(node, tmp_path):
    n, other = node
    log = tmp_path / "notified.json"
    n.config.wake = ["desktop"]
    n.config.notify_command = [
        sys.executable, "-c",
        f"import json,sys; json.dump(sys.argv[1:], open({str(log)!r}, 'w'))",
        "{title}", "{text}",
    ]
    _deliver(n, other, "$(rm -rf ~) ; `boom`")
    import time
    for _ in range(100):
        if log.exists() and log.stat().st_size:
            break
        time.sleep(0.05)
    assert json.loads(log.read_text()) == ["claude-p2p: msg from peer", "$(rm -rf ~) ; `boom`"]


def test_wake_cli_validates(node, capsys):
    assert cli.main(["wake", "prompt", "nope"]) == 1
    assert cli.main(["wake", "tool", "watch"]) == 0
    assert json.loads(capsys.readouterr().out)["wake"] == ["tool", "watch"]
    assert cli.main(["claude-config"]) == 0
    hooks = json.loads(capsys.readouterr().out)["hooks"]
    assert set(hooks) == {"PostToolUse"}


def test_old_database_is_migrated(tmp_path):
    db = tmp_path / "state.db"
    con = sqlite3.connect(db)
    con.executescript("""CREATE TABLE messages (id TEXT PRIMARY KEY, peer TEXT NOT NULL,
        direction TEXT NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL, in_reply_to TEXT,
        ts INTEGER NOT NULL, read INTEGER NOT NULL DEFAULT 0, envelope TEXT,
        delivered INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT);
        INSERT INTO messages(id, peer, direction, kind, body, ts)
        VALUES ('a', 'p', 'in', 'msg', '{"text": "old"}', 1);""")
    con.commit()
    con.close()
    assert [m["id"] for m in Store(db).unnotified()] == ["a"]
