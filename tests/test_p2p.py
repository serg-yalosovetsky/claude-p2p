import json
import sys
import threading
import time

import pytest

from claude_p2p import crypto
from claude_p2p.node import Node


def _free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def pair(tmp_path):
    """Two nodes, each pinned in the other, both serving on localhost."""
    nodes, servers = [], []
    for name in ("alice", "bob"):
        port = _free_port()
        n = Node.init(name, f"http://127.0.0.1:{port}", root=tmp_path / name)
        n.config.listen = f"127.0.0.1:{port}"
        nodes.append(n)
    a, b = nodes
    a.add_peer(b.invite())
    b.add_peer(a.invite())
    for n in nodes:
        srv = n.make_server()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    yield a, b
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _wait(pred, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        r = pred()
        if r:
            return r
        time.sleep(0.05)
    return None


# ---- envelopes --------------------------------------------------------------

def _ids():
    return crypto.Identity.generate("a"), crypto.Identity.generate("b")


def test_envelope_roundtrip():
    a, b = _ids()
    env = crypto.seal(a, b.sign_pub, b.box_pub, "msg", {"text": "привет"})
    header, body = crypto.open_envelope(b, env, lambda k: a.box_pub if k == a.sign_pub else None)
    assert body == {"text": "привет"}
    assert header["from"] == a.sign_pub and header["kind"] == "msg"
    assert "привет" not in json.dumps(env, ensure_ascii=False)  # body is encrypted


@pytest.mark.parametrize("field,value", [
    ("kind", "task"), ("in_reply_to", "x"), ("ts", 1), ("ct", "AAAA"),
])
def test_tampered_envelope_rejected(field, value):
    a, b = _ids()
    env = crypto.seal(a, b.sign_pub, b.box_pub, "msg", {"text": "hi"})
    env[field] = value
    with pytest.raises(crypto.EnvelopeError):
        crypto.open_envelope(b, env, lambda k: a.box_pub)


def test_unknown_sender_and_wrong_recipient_rejected():
    a, b = _ids()
    c = crypto.Identity.generate("c")
    env = crypto.seal(a, b.sign_pub, b.box_pub, "msg", {"text": "hi"})
    with pytest.raises(crypto.EnvelopeError, match="unknown peer"):
        crypto.open_envelope(b, env, lambda k: None)
    with pytest.raises(crypto.EnvelopeError, match="not addressed"):
        crypto.open_envelope(c, env, lambda k: a.box_pub)


def test_forged_signature_with_pinned_name_rejected():
    """A stranger who copies a peer's public key into `from` cannot sign as it."""
    a, b = _ids()
    mallory = crypto.Identity.generate("m")
    env = crypto.seal(mallory, b.sign_pub, b.box_pub, "msg", {"text": "hi"})
    env["from"] = a.sign_pub
    with pytest.raises(crypto.EnvelopeError):
        crypto.open_envelope(b, env, lambda k: a.box_pub if k == a.sign_pub else None)


def test_future_and_stale_timestamps_rejected():
    a, b = _ids()
    env = crypto.seal(a, b.sign_pub, b.box_pub, "msg", {"text": "hi"})
    box = lambda k: a.box_pub  # noqa: E731
    with pytest.raises(crypto.EnvelopeError, match="window"):
        crypto.open_envelope(b, env, box, now=env["ts"] - crypto.MAX_SKEW_S - 5)
    with pytest.raises(crypto.EnvelopeError, match="window"):
        crypto.open_envelope(b, env, box, now=env["ts"] + crypto.MAX_AGE_S + 5)


def test_invite_rejects_garbage_and_self(tmp_path):
    n = Node.init("me", "http://x", root=tmp_path / "me")
    with pytest.raises(ValueError):
        n.parse_invite("hello")
    with pytest.raises(ValueError, match="own invite"):
        n.add_peer(n.invite())


def test_identity_file_private(tmp_path):
    n = Node.init("me", "http://x", root=tmp_path / "me")
    assert (n.root / "identity.json").stat().st_mode & 0o077 == 0


# ---- live nodes ---------------------------------------------------------------

def test_message_and_reply_over_http(pair):
    a, b = pair
    sent = a.send("bob", "сколько будет 2+2?")
    assert sent["delivered"] is True
    got = _wait(lambda: b.store.inbox())
    assert got[0]["body"]["text"] == "сколько будет 2+2?" and got[0]["peer"] == "alice"
    b.send("alice", "4", in_reply_to=got[0]["id"])
    reply = _wait(lambda: a.store.reply_to(sent["id"]))
    assert reply["body"]["text"] == "4"


def test_replay_is_idempotent(pair):
    a, b = pair
    sent = a.send("bob", "once")
    env = json.loads(a.store._db.execute(
        "SELECT envelope FROM messages WHERE id=?", (sent["id"],)).fetchone()[0])
    status, body = b.receive(env)
    assert status == 200 and body["duplicate"] is True
    assert len(b.store.inbox(unread_only=False)) == 1


def test_offline_peer_queued_then_flushed(tmp_path):
    a = Node.init("alice", "http://127.0.0.1:1", root=tmp_path / "a")
    port = _free_port()
    b = Node.init("bob", f"http://127.0.0.1:{port}", root=tmp_path / "b")
    b.config.listen = f"127.0.0.1:{port}"
    a.add_peer(b.invite())
    b.add_peer(a.invite())
    sent = a.send("bob", "are you there?")
    assert sent["delivered"] is False
    assert len(a.store.pending_outbox(100)) == 1
    srv = b.make_server()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert a.flush_outbox() == 1
        assert b.store.inbox()[0]["body"]["text"] == "are you there?"
        assert a.store.pending_outbox(100) == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_task_refused_unless_both_switches_on(pair):
    a, b = pair
    sent = a.send("bob", "do something", kind="task")
    reply = _wait(lambda: a.store.reply_to(sent["id"]))
    assert "does not run tasks" in reply["body"]["text"]
    # Only the node switch on: still refused, the peer itself is not allowed.
    b.config.tasks_enabled = True
    sent = a.send("bob", "again", kind="task")
    reply = _wait(lambda: a.store.reply_to(sent["id"]))
    assert "does not run tasks" in reply["body"]["text"]


def test_task_runs_when_allowed(pair):
    a, b = pair
    b.config.tasks_enabled = True
    b.config.task_command = [sys.executable, "-c",
                             "import sys; t=sys.stdin.read(); print('ANSWER', len(t) > 0, "
                             "'<peer_request>' in t)"]
    b.store.set_allow_tasks("alice", True)
    sent = a.send("bob", "what time is it?", kind="task")
    reply = _wait(lambda: a.store.reply_to(sent["id"]))
    assert reply["body"]["text"] == "ANSWER True True"
    assert reply["kind"] == "result"


def test_unpinned_node_cannot_post(pair, tmp_path):
    _, b = pair
    stranger = Node.init("eve", "http://x", root=tmp_path / "eve")
    stranger.add_peer(b.invite())  # eve knows bob, bob never pinned eve
    sent = stranger.send("bob", "let me in")
    assert sent["delivered"] is False
    assert "403" in stranger.store.pending_outbox(100)[0]["last_error"]
    assert b.store.inbox() == []


# ---- pull mode (a peer behind NAT) ------------------------------------------

@pytest.fixture
def hub_and_nat(tmp_path):
    """`hub` is reachable; `home` has no address and collects mail by pulling."""
    port = _free_port()
    hub = Node.init("hub", f"http://127.0.0.1:{port}", root=tmp_path / "hub")
    hub.config.listen = f"127.0.0.1:{port}"
    nat = Node.init("home", "", root=tmp_path / "home")
    nat.config.listen = ""
    hub.add_peer(nat.invite())
    nat.add_peer(hub.invite())
    srv = hub.make_server()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield hub, nat
    srv.shutdown()
    srv.server_close()


def test_nat_peer_pulls_its_mail(hub_and_nat):
    hub, nat = hub_and_nat
    sent = hub.send("home", "hello behind NAT")
    assert sent == {"id": sent["id"], "peer": "home", "delivered": False,
                    "queued_for_pull": True}
    nat.tick()
    assert nat.store.inbox()[0]["body"]["text"] == "hello behind NAT"
    # Not acknowledged yet: still queued on the hub until the next pull carries the ack.
    assert len(hub.store.queued_for("home")) == 1
    nat.tick()
    assert hub.store.queued_for("home") == []
    # The NAT side answers by pushing; the hub is reachable.
    r = nat.send("hub", "got it", in_reply_to=sent["id"])
    assert r["delivered"] is True
    assert hub.store.reply_to(sent["id"])["body"]["text"] == "got it"


def test_redelivery_after_lost_ack_is_harmless(hub_and_nat):
    hub, nat = hub_and_nat
    hub.send("home", "once")
    nat.tick()
    nat._acks.clear()  # e.g. the NAT node restarted before acknowledging
    nat.tick()
    assert len(nat.store.inbox(unread_only=False)) == 1


def test_pull_replay_rejected(hub_and_nat):
    hub, nat = hub_and_nat
    peer = nat.store.peer("hub")
    env = crypto.seal(nat.identity, peer["sign_pub"], peer["box_pub"], "pull", {"ack": []})
    assert hub.receive(env)[0] == 200
    assert hub.receive(env) == (403, {"error": "replayed pull"})


def test_stranger_cannot_pull(hub_and_nat, tmp_path):
    hub, _ = hub_and_nat
    hub.send("home", "secret for home")
    eve = Node.init("eve", "", root=tmp_path / "eve")
    eve.add_peer(hub.invite())
    assert eve.pull_from("hub") == 0
    assert len(hub.store.queued_for("home")) == 1


def test_outbox_lists_mail_waiting_for_pull(hub_and_nat):
    hub, _ = hub_and_nat
    hub.send("home", "waiting")
    assert [r["peer"] for r in hub.store.undelivered()] == ["home"]
