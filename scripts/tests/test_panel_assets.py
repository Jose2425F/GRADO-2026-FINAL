"""Automatic interface versions, exercised through an isolated HTTP server."""
import hashlib
import os
import re
import shutil
from urllib.parse import parse_qs, urlsplit

import pytest

from test_centinela_accounts import call, login, service
import dualstack_panel


@pytest.fixture
def asset_service(tmp_path, monkeypatch):
    assets = tmp_path / 'ui'
    shutil.copytree(dualstack_panel.ASSETS, assets)
    monkeypatch.setattr(dualstack_panel, 'ASSETS', assets)
    # Resolve the service fixture only after installing the isolated assets.
    return assets


@pytest.fixture
def running_assets(asset_service, request):
    return request.getfixturevalue('service'), asset_service


def references(body):
    return re.findall(r'(?:src|href)="(/[^"\s]+\.(?:js|css|webp)(?:\?[^"\s]*)?)"', body.decode())


def test_all_account_pages_use_content_versions_and_keep_access_controls(running_assets):
    server, assets = running_assets
    admin, _ = login(server, 'admin')
    company, _ = login(server, 'alice')
    for page, token in (('/login', None), ('/', admin), ('/', company), ('/account', company), ('/admin', admin)):
        status, headers, body = call(server, page, token)
        assert status == 200
        assert headers['Cache-Control'] == 'no-store'
        links = references(body)
        assert links, page
        for link in links:
            url = urlsplit(link)
            file = assets / url.path.lstrip('/')
            assert parse_qs(url.query)['v'] == [hashlib.sha256(file.read_bytes()).hexdigest()[:16]]
            status, headers, content = call(server, link, token)
            assert status == 200
            assert headers['Cache-Control'] == 'no-store'
            assert content == file.read_bytes()
            if url.path not in ('/login.css', '/login.js'):
                assert call(server, link)[0] == 303


def test_edits_change_only_the_modified_asset_without_server_restart(running_assets):
    server, assets = running_assets
    original = references(call(server, '/login')[2])
    assert references(call(server, '/login')[2]) == original
    script = assets / 'login.js'
    before = script.stat()
    content = script.read_bytes()
    # Same length and mtime: the version must follow the contents, not the clock.
    updated = content.replace(b"'use strict'", b'"use strict"', 1)
    assert updated != content and len(updated) == len(content)
    script.write_bytes(updated)
    os.utime(script, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = references(call(server, '/login')[2])
    old_js = next(link for link in original if link.startswith('/login.js?'))
    new_js = next(link for link in after if link.startswith('/login.js?'))
    assert old_js != new_js
    assert [link for link in original if '.css?' in link] == [link for link in after if '.css?' in link]
    assert call(server, new_js)[2] == updated
    assert references(call(server, '/login')[2]) == after
    # Reverting the file restores the original stable URL.
    script.write_bytes(content)
    assert references(call(server, '/login')[2]) == original


def test_template_edits_and_archive_assets_are_detected_without_restart(running_assets):
    server, assets = running_assets
    template = assets / 'login.html'
    assert b'asset-reload-test' not in call(server, '/login')[2]
    template.write_text(template.read_text() + '<!-- asset-reload-test -->')
    assert b'asset-reload-test' in call(server, '/login')[2]
    html = server[1].environment.get_template('archive.html').render(runs=[], archive_id='fixture').encode()
    for link in references(html):
        url = urlsplit(link)
        assert parse_qs(url.query)['v'] == [hashlib.sha256((assets / url.path.lstrip('/')).read_bytes()).hexdigest()[:16]]
