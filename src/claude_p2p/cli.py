"""`p2p` command line: set up a node, exchange invites, run the endpoint."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .node import Config, Node, home


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="p2p", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create this node's identity")
    p.add_argument("--name", required=True, help="how peers will call this node")
    p.add_argument("--url", default="",
                   help="URL peers use to reach this node; omit behind NAT (pull-only)")
    p.add_argument("--listen", default=None,
                   help="host:port to bind (default 127.0.0.1:8765, none if --url is empty)")

    sub.add_parser("whoami", help="name, URL and fingerprint of this node")
    sub.add_parser("invite", help="print the invite to hand to a peer")

    p = sub.add_parser("add", help="pin a peer from its invite")
    p.add_argument("invite")
    p.add_argument("--name", help="local name for the peer (default: its own)")

    p = sub.add_parser("remove", help="forget a peer")
    p.add_argument("name")

    p = sub.add_parser("allow-tasks", help="let a peer run tasks on this node's Claude")
    p.add_argument("name")
    p.add_argument("--off", action="store_true")

    sub.add_parser("peers", help="list pinned peers")

    p = sub.add_parser("send", help="send a message")
    p.add_argument("peer")
    p.add_argument("text")
    p.add_argument("--task", action="store_true", help="ask the peer's Claude to answer")
    p.add_argument("--reply-to")

    p = sub.add_parser("inbox", help="show received messages")
    p.add_argument("--all", action="store_true", help="include already read")

    sub.add_parser("outbox", help="show undelivered messages")
    sub.add_parser("flush", help="retry undelivered messages now")
    sub.add_parser("serve", help="run the HTTP endpoint")

    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        if a.cmd == "init":
            node = Node.init(a.name, a.url)
            node.config.listen = a.listen if a.listen is not None else (
                "127.0.0.1:8765" if a.url else "")
            node.config.save(node.root / "config.json")
            _print({"home": str(node.root), "name": a.name,
                    "fingerprint": node.identity.fingerprint})
            return 0

        node = Node()
        if a.cmd == "whoami":
            _print({**node.hello(), "url": node.config.url, "home": str(home())})
        elif a.cmd == "invite":
            print(node.invite())
            print(f"fingerprint: {node.identity.fingerprint}  "
                  "(read it to the peer over the phone)", file=sys.stderr)
        elif a.cmd == "add":
            info = node.add_peer(a.invite, a.name)
            _print(info)
            print("Compare the fingerprint with the peer by voice before trusting it.",
                  file=sys.stderr)
        elif a.cmd == "remove":
            _print({"removed": node.store.remove_peer(a.name)})
        elif a.cmd == "allow-tasks":
            ok = node.store.set_allow_tasks(a.name, not a.off)
            _print({"peer": a.name, "allow_tasks": not a.off, "found": ok,
                    "tasks_enabled_on_node": node.config.tasks_enabled})
        elif a.cmd == "peers":
            _print([{k: p[k] for k in ("name", "url", "allow_tasks")} |
                    {"fingerprint": _fp(p["sign_pub"])} for p in node.store.peers()])
        elif a.cmd == "send":
            kind = "task" if a.task else "msg"
            _print(node.send(a.peer, a.text, kind=kind, in_reply_to=a.reply_to))
        elif a.cmd == "inbox":
            _print(node.store.inbox(unread_only=not a.all, mark_read=True))
        elif a.cmd == "outbox":
            _print([{k: r[k] for k in ("id", "peer", "kind", "attempts", "last_error")}
                    for r in node.store.undelivered()])
        elif a.cmd == "flush":
            _print({"delivered": node.flush_outbox()})
        elif a.cmd == "serve":
            node.serve_forever()
    except (KeyError, ValueError, FileExistsError, FileNotFoundError) as e:
        print(f"p2p: {e}", file=sys.stderr)
        return 1
    return 0


def _fp(sign_pub: str) -> str:
    from .crypto import fingerprint
    return fingerprint(sign_pub)


__all__ = ["main", "Config"]

if __name__ == "__main__":
    raise SystemExit(main())
