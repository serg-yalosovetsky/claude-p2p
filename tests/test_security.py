import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_p2p import crypto, node


@pytest.fixture
def peers(tmp_path):
    a = node.Node.init('a', 'http://a', tmp_path / 'a')
    b = node.Node.init('b', 'http://b', tmp_path / 'b')
    a.add_peer(b.invite())
    a.config.tasks_enabled = True
    a.store.set_allow_tasks('b', True)
    return a, b


def test_task_isolation(peers, monkeypatch):
    a, _ = peers
    calls = []
    monkeypatch.setenv('OWNER_PRIVATE', 'synthetic-marker')

    def run(argv, **kw):
        calls.append(kw['cwd'])
        assert not Path(kw['cwd']).is_relative_to(a.root)
        assert set(kw['env']) <= {'PATH', 'HOME'}
        assert argv[argv.index('--allowedTools') + 1] == ''
        assert '--disallowedTools' in argv
        assert '--strict-mcp-config' in argv
        assert argv[argv.index('--mcp-config') + 1] == '{"mcpServers":{}}'
        assert argv[argv.index('--setting-sources') + 1] == ''
        return SimpleNamespace(stdout='я' * node.MAX_TEXT, returncode=0)

    monkeypatch.setattr(node.subprocess, 'run', run)
    monkeypatch.setattr(a, '_deliver', lambda *args: False)
    a._run_task(a.store.peer('b'), {'id': 'task'}, 'hello')
    assert calls and not Path(calls[0]).exists()
    assert len(a.store.undelivered()[0]['body'].encode()) < node.MAX_TEXT * 7


@pytest.mark.parametrize('revoke', ['remove', 'permission', 'node'])
def test_task_rechecks_permission(peers, monkeypatch, revoke):
    a, _ = peers
    peer = a.store.peer('b')
    if revoke == 'remove':
        a.store.remove_peer('b')
    elif revoke == 'permission':
        a.store.set_allow_tasks('b', False)
    else:
        a.config.tasks_enabled = False
    monkeypatch.setattr(node.subprocess, 'run', lambda *a, **k: pytest.fail('ran revoked task'))
    a._run_task(peer, {'id': 'task'}, 'hello')


@pytest.mark.parametrize('field', ['name', 'url', 'sign', 'box'])
def test_invite_signature(peers, field):
    _, b = peers
    token = b.invite()
    data = json.loads(crypto.b64d(token.split('.', 1)[1]))
    data[field] = {'name': 'other', 'url': 'https://other',
                   'sign': crypto.Identity.generate('x').sign_pub,
                   'box': crypto.Identity.generate('x').box_pub}[field]
    with pytest.raises(ValueError):
        node.Node.parse_invite(token.split('.')[0] + '.' + crypto.b64e(crypto.canonical(data)))


def test_invite_version_and_fingerprint(peers):
    _, b = peers
    assert b.invite().startswith('p2p2.')
    with pytest.raises(ValueError, match='p2p1'):
        node.Node.parse_invite('p2p1.e30')
    other = crypto.Identity.generate('x')
    assert crypto.fingerprint(b.identity.sign_pub, b.identity.box_pub) != crypto.fingerprint(
        b.identity.sign_pub, other.box_pub)
    assert len(b.identity.fingerprint.split('-')) == 4


@pytest.mark.parametrize('collision', ['name', 'sign'])
def test_peer_keys_pinned(peers, collision):
    a, b = peers
    other = crypto.Identity.generate('x')
    with pytest.raises(ValueError, match='already pinned with other keys; remove it first'):
        a.store.add_peer('b' if collision == 'name' else 'alias',
                         other.sign_pub if collision == 'name' else b.identity.sign_pub,
                         other.box_pub, 'http://new')
    assert a.store.peer('b')['allow_tasks'] == 1
    a.add_peer(b.invite())
    a.store.remove_peer('b')
    a.add_peer(b.invite())
    assert a.store.peer('b')['allow_tasks'] == 0


@pytest.mark.parametrize('url', ['file:///etc/passwd', 'ftp://host', 'http://', 'javascript:x'])
def test_invite_url(peers, url):
    _, b = peers
    b.config.url = url
    with pytest.raises(ValueError, match='URL'):
        node.Node.parse_invite(b.invite())


@pytest.mark.parametrize('payload', [[], {'envelopes': {}}, {'envelopes': [1]},
                                    {'envelopes': []}, 'oversized'])
def test_pull_bounded_and_typed(peers, monkeypatch, caplog, payload):
    a, _ = peers
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size=-1):
            assert 0 < size <= 4 * 1024 * 1024
            if payload == 'oversized':
                return b' ' * size
            return json.dumps(payload).encode()

    monkeypatch.setattr(node.urllib.request, 'urlopen', lambda *a, **k: Response())
    monkeypatch.setattr(node.urllib.request.OpenerDirector, 'open', lambda *a, **k: Response())
    assert a.pull_from('b') == 0
    if payload != {'envelopes': []}:
        assert 'pull from b failed' in caplog.text


def test_rate_buckets_bounded(peers):
    a, _ = peers
    for i in range(5000):
        a._rate_ok(str(i))
    assert len(a._buckets) <= 1024


def test_http_limits(peers):
    a, _ = peers
    a.config.listen = '127.0.0.1:0'
    with a.make_server() as server:
        assert server.RequestHandlerClass.timeout == 10
        assert hasattr(server, '_handler_slots')
        assert hasattr(a, '_ip_buckets')


def test_task_queue_bounded(peers, monkeypatch):
    a, _ = peers
    starts, replies = [], []
    monkeypatch.setattr(node.threading.Thread, 'start', lambda self: starts.append(self))
    monkeypatch.setattr(a, 'send', lambda *args, **kw: replies.append(args))
    for i in range(10):
        a._maybe_run_task(a.store.peer('b'), {'id': str(i)}, 'hi')
    assert len(starts) <= 4
    assert len(replies) == 6 and all('busy' in r[1].lower() for r in replies)


@pytest.mark.parametrize('name', ['', '../x', 'a b', 'ю', 'a' * 65, 'a\n'])
def test_peer_name_validation(peers, name):
    a, b = peers
    with pytest.raises(ValueError, match='name'):
        a.store.add_peer(name, b.identity.sign_pub, b.identity.box_pub, 'http://b')


def test_redirects_refused(peers):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    a, _ = peers
    redirected = []

    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.send_response(302)
            self.send_header('Location', '/stolen')
            self.end_headers()

        def do_GET(self):  # noqa: N802
            redirected.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"envelopes":[]}')

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(('127.0.0.1', 0), Redirect) as srv:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            peer = a.store.peer('b')
            a.store.add_peer('b', peer['sign_pub'], peer['box_pub'],
                             f'http://127.0.0.1:{srv.server_port}')
            assert not a.send('b', 'hello')['delivered']
            assert a.pull_from('b') == 0
            assert not redirected
        finally:
            srv.shutdown()


def test_http_ip_limit_and_thread_capacity(peers):
    import http.client
    import socket
    import threading

    a, _ = peers
    a.config.listen = '127.0.0.1:0'
    with a.make_server() as srv:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            for i in range(121):
                conn = http.client.HTTPConnection('127.0.0.1', srv.server_port, timeout=2)
                conn.request('POST', '/v1/msg', json.dumps({'from': str(i)}))
                response = conn.getresponse()
                response.read()
                conn.close()
            assert response.status == 429
            assert len(a._buckets) == 120
            for _ in range(32):
                assert srv._handler_slots.acquire(timeout=2)
            try:
                with socket.create_connection(('127.0.0.1', srv.server_port), timeout=2) as sock:
                    assert b'503' in sock.recv(1024)
            finally:
                for _ in range(32):
                    srv._handler_slots.release()
        finally:
            srv.shutdown()
