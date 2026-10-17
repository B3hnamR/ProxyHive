"""The Windows system-proxy switch, against an in-memory fake registry (the real one is never touched)."""
import json
import os

import pytest

from proxyhive import gateway as gw

pytestmark = pytest.mark.skipif(os.name != "nt", reason="the Windows system proxy only exists on Windows")

ORIGINAL = {"ProxyEnable": [0, 4], "ProxyServer": ["127.0.0.1:10808", 1], "ProxyOverride": None}   # e.g. set by a VPN app


@pytest.fixture
def reg(tmp_path, monkeypatch):
    values = {k: (list(v) if v else None) for k, v in ORIGINAL.items()}
    monkeypatch.setattr(gw, "_read_values", lambda: {k: (list(v) if v else None) for k, v in values.items()})
    monkeypatch.setattr(gw, "_write_values", lambda new: values.update({k: (list(v) if v else None) for k, v in new.items()}))
    monkeypatch.setattr(gw, "_refresh", lambda: None)
    monkeypatch.setattr(gw, "BACKUP", str(tmp_path / "a.json"))
    monkeypatch.setattr(gw, "BACKUP_PROFILE", str(tmp_path / "profile" / "b.json"))
    return values


def test_enable_then_restore_puts_everything_back(reg):
    gw.enable_system_proxy(8082)
    assert reg["ProxyEnable"] == [1, 4] and reg["ProxyServer"][0] == "127.0.0.1:8082"
    assert os.path.exists(gw.BACKUP) and os.path.exists(gw.BACKUP_PROFILE)
    assert gw.restore_system_proxy() is True
    assert reg == ORIGINAL
    assert not os.path.exists(gw.BACKUP) and not os.path.exists(gw.BACKUP_PROFILE)


def test_restore_never_overwrites_a_change_made_by_another_program(reg):
    gw.enable_system_proxy(8082)
    reg["ProxyServer"], reg["ProxyEnable"] = ["127.0.0.1:10808", 1], [1, 4]      # a VPN app took over in the meantime
    assert gw.restore_system_proxy() is False
    assert reg["ProxyServer"][0] == "127.0.0.1:10808" and reg["ProxyEnable"] == [1, 4], "their setting is left alone"
    assert not os.path.exists(gw.BACKUP) and not os.path.exists(gw.BACKUP_PROFILE), "our stale marker is forgotten"


def test_a_marker_from_an_older_version_is_never_trusted(reg):
    with open(gw.BACKUP, "w", encoding="utf-8") as f:                              # old flat format: no owner recorded
        json.dump(ORIGINAL, f)
    reg["ProxyEnable"], reg["ProxyServer"] = [1, 4], ["127.0.0.1:10808", 1]
    assert gw.restore_system_proxy() is False
    assert reg["ProxyEnable"] == [1, 4], "the registry is untouched"
    assert not os.path.exists(gw.BACKUP)


def test_enabling_twice_still_restores_the_very_first_state(reg):
    gw.enable_system_proxy(8081)
    gw.enable_system_proxy(8082)
    assert gw.restore_system_proxy() is True
    assert reg == ORIGINAL


def test_if_the_marker_cannot_be_saved_windows_is_not_changed(reg, tmp_path, monkeypatch):
    blocker = tmp_path / "file.txt"
    blocker.write_text("x")
    monkeypatch.setattr(gw, "BACKUP", str(blocker / "a.json"))               # a file where a folder is needed
    monkeypatch.setattr(gw, "BACKUP_PROFILE", str(blocker / "b.json"))
    with pytest.raises(OSError):
        gw.enable_system_proxy(8082)
    assert reg == ORIGINAL


def test_nothing_to_restore_is_a_no_op(reg):
    assert gw.restore_system_proxy() is False and reg == ORIGINAL


def test_the_outside_check_looks_for_our_exact_address():
    shown = "HKEY_CURRENT_USER\\...\\Internet Settings\n    ProxyServer    REG_SZ    127.0.0.1:10808\n"
    assert gw._server_line_has(shown, 10808) and not gw._server_line_has(shown, 8081)
