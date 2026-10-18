"""Offline tests: subprocess/mount/PHY boundaries are never executed on this host."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def test_utility_is_available_for_offline_contract_tests():
    assert (Path(__file__).resolve().parents[2] / "tools/mt7922-isolated.py").is_file(), (
        "isolation utility missing"
    )


@pytest.fixture
def utility():
    path = Path(__file__).resolve().parents[2] / "tools/mt7922-isolated.py"
    if not path.exists():
        pytest.skip("implementation not present yet")
    spec = importlib.util.spec_from_file_location("mt7922_isolated", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def pci(root, bdf, device, driver, phy, iface):
    p = root / "bus/pci/devices" / bdf
    p.mkdir(parents=True)
    (p / "vendor").write_text("0x14c3\n")
    (p / "device").write_text(device)
    target = root / "bus/pci/drivers" / driver
    target.mkdir(parents=True, exist_ok=True)
    (p / "driver").symlink_to(target)
    (p / "ieee80211" / phy).mkdir(parents=True)
    (p / "net" / iface).mkdir(parents=True)
    return p


@pytest.fixture
def sysroot(tmp_path):
    root = tmp_path / "sys"
    pci(root, "0000:0b:00.0", "0x0616", "mt7921e_git", "phy8", "renamed22")
    pci(root, "0000:07:00.0", "0x7927", "mt7925e_git", "phy9", "protected27")
    return root


def test_dynamic_identity_does_not_use_old_iface_or_phy(utility, sysroot):
    selected, protected = utility.discover(sysroot)
    assert selected == {"bdf": "0000:0b:00.0", "driver": "mt7921e_git", "phy": "phy8", "iface": "renamed22"}
    assert protected[0]["iface"] == "protected27"


def test_multiple_mt7922_devices_abort(utility, sysroot):
    pci(sysroot, "0000:0c:00.0", "0x0616", "mt7921e", "phy10", "other22")
    with pytest.raises(utility.Gap):
        utility.discover(sysroot)


def test_wrong_driver_or_multiple_ifaces_abort(utility, sysroot):
    p = sysroot / "bus/pci/devices/0000:0b:00.0"
    (p / "net/extra").mkdir()
    with pytest.raises(utility.Gap):
        utility.discover(sysroot)
    (p / "net/extra").rmdir()
    (p / "driver").unlink()
    (p / "driver").symlink_to(sysroot / "bus/pci/drivers/mt7925e_git")
    with pytest.raises(utility.Gap):
        utility.discover(sysroot)


PROFILE = """[connection]
type=wifi
interface-name=protected27
[wifi]
mode=infrastructure
ssid=Example\\sSSID
[wifi-security]
key-mgmt=sae
psk=offline-test-password
psk-flags=0
"""


def test_sae_profile_keeps_ssid_and_password_not_interface_binding(utility):
    config = utility.clone_profile(PROFILE)
    assert "ssid=4578616d706c652053534944" in config
    assert "key_mgmt=SAE" in config
    assert 'sae_password="offline-test-password"' in config
    assert "protected27" not in config
    assert "update_config=0" in config


@pytest.mark.parametrize(
    "change",
    [
        ("key-mgmt=sae", "key-mgmt=wpa-eap"),
        ("psk-flags=0", "psk-flags=1"),
        ("ssid=Example\\sSSID", "ssid="),
        ("[wifi-security]", "[wifi-security]\nwep-key0=secret"),
        ("psk=offline-test-password", "psk=bad\\npassword"),
    ],
)
def test_unsupported_credentials_fail_without_echo(utility, change):
    with pytest.raises(utility.Gap) as error:
        utility.clone_profile(PROFILE.replace(*change))
    assert "secret" not in str(error.value)
    assert "password" not in str(error.value)


def test_psk_hex_is_not_reinterpreted_as_passphrase(utility):
    config = utility.clone_profile(
        PROFILE.replace("key-mgmt=sae", "key-mgmt=wpa-psk").replace("offline-test-password", "a" * 64)
    )
    assert "psk=" + "a" * 64 + "\n" in config


@pytest.mark.parametrize("name", ["../bad", "-bad", "a;echo", "", "space name"])
def test_namespace_argv_injection_is_rejected(utility, name):
    with pytest.raises(utility.Gap):
        utility.validate_namespace(name)


def test_missing_address_is_gap_not_guessed(utility):
    with pytest.raises(utility.Gap, match="IPv4 CIDR"):
        utility.validate_address(None)
    assert utility.validate_address("192.0.2.20/24") == "192.0.2.20/24"


def test_secure_file_rejects_symlink_and_world_readable(utility, tmp_path):
    p = tmp_path / "profile"
    p.write_text(PROFILE)
    p.chmod(0o644)
    with pytest.raises(utility.Gap):
        utility.read_private(p, owner=p.stat().st_uid)
    p.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(p)
    with pytest.raises(utility.Gap):
        utility.read_private(link, owner=p.stat().st_uid)
    assert utility.read_private(p, owner=p.stat().st_uid) == PROFILE


class FakeSystem:
    """Only external OS actions are substituted, not utility orchestration."""

    def __init__(self):
        self.calls = []
        self.namespaces = []
        self.fail_on = None
        self.running = True

    def run(self, argv):
        self.calls.append(argv)
        if self.fail_on and self.fail_on in argv:
            raise RuntimeError("subprocess could have printed secret")
        if argv[-2:] == ["netns", "list"]:
            return "\n".join(self.namespaces)
        if argv[:3] == ["/usr/bin/ip", "netns", "add"]:
            self.namespaces.append(argv[3])
        if argv[:3] == ["/usr/bin/ip", "netns", "delete"]:
            self.namespaces.remove(argv[3])
        if argv[-1] == "ping":
            return "PONG\n"
        if argv[-1] == "status":
            return "wpa_state=COMPLETED\nssid=DO-NOT-RECORD\nip_address=192.0.2.20\n"
        return ""

    def spawn(self, argv):
        self.calls.append(argv)
        return {"pid": 12345, "start": "777"}

    def alive(self, process):
        return self.running

    def terminate(self, process):
        self.running = False

    def host_identity(self):
        return {"boot": "testboot", "netns": 100}

    def tools(self):
        return {
            "ip": "/usr/bin/ip",
            "iw": "/usr/sbin/iw",
            "wpa_supplicant": "/usr/sbin/wpa_supplicant",
            "wpa_cli": "/usr/sbin/wpa_cli",
            "mount": "/usr/bin/mount",
            "umount": "/usr/bin/umount",
            "dhclient": None,
            "udhcpc": None,
        }

    def tmpfs(self, path):
        return True

    def namespace_identity(self, name):
        return 222


@pytest.fixture
def environment(utility, sysroot, tmp_path, monkeypatch):
    # NM radio inspection and protected snapshot are read-only OS boundaries.
    monkeypatch.setattr(utility, "radio_disabled", lambda: True)
    monkeypatch.setattr(utility, "validate_output", lambda out, runtime: None)
    p = tmp_path / "profile"
    p.write_text(PROFILE)
    p.chmod(0o600)
    system = FakeSystem()
    env = utility.Environment(system, sysroot, tmp_path / "runtime")
    monkeypatch.setattr(utility, "PROFILE_OWNER", p.stat().st_uid)
    return env, system, p, tmp_path / "evidence.json"


def test_prepare_only_moves_selected_phy_and_removes_loaded_credentials(utility, environment):
    env, system, profile, out = environment
    env.prepare("isolated22", profile, "192.0.2.20/24", out)
    assert ["/usr/sbin/iw", "phy", "phy8", "set", "netns", "name", "isolated22"] in system.calls
    assert not any("phy9" in c or "protected27" in c for c in system.calls)
    assert not (env.runtime / "wpa.conf").exists()
    assert "offline-test-password" not in out.read_text()
    assert "DO-NOT-RECORD" not in out.read_text()
    assert json.loads(out.read_text())["phase"] == "prepared"
    assert out.stat().st_mode & 0o777 == 0o600
    with pytest.raises(utility.Gap):
        env.prepare("isolated22", profile, "192.0.2.20/24", out)
    env.verify(out)
    assert json.loads(out.read_text())["wpa_state"] == "COMPLETED"
    env.cleanup(out)
    assert not env.runtime.exists()
    assert not system.namespaces


def test_collision_and_missing_address_abort_before_mutation(utility, environment):
    env, system, profile, out = environment
    system.namespaces = ["isolated22"]
    with pytest.raises(utility.Gap):
        env.prepare("isolated22", profile, "192.0.2.20/24", out)
    assert not env.runtime.exists()
    assert not out.exists()
    with pytest.raises(utility.Gap):
        env.prepare("new22", profile, None, out)
    assert not any("add" in c or "set" in c for c in system.calls)


def test_failure_retains_recoverable_state_without_secrets(utility, environment):
    env, system, profile, out = environment
    system.fail_on = "wpa_supplicant"
    # Match executable rather than unrelated substrings.
    system.fail_on = "/usr/sbin/wpa_cli"
    with pytest.raises(utility.Gap) as error:
        env.prepare("isolated22", profile, "192.0.2.20/24", out)
    assert "secret" not in str(error.value)
    assert "offline-test-password" not in out.read_text()
    assert not (env.runtime / "wpa.conf").exists()
    system.fail_on = None
    env.cleanup(out)
    assert not system.namespaces


def test_cleanup_rejects_wrong_host_namespace_without_mutation(utility, environment):
    env, system, profile, out = environment
    env.prepare("isolated22", profile, "192.0.2.20/24", out)
    system.host_identity = lambda: {"boot": "different", "netns": 101}
    before = len(system.calls)
    with pytest.raises(utility.Gap):
        env.cleanup(out)
    assert len(system.calls) == before


def test_atomic_state_write_failure_preserves_previous_evidence(utility, tmp_path, monkeypatch):
    path = tmp_path / "evidence"
    utility.write_private(path, "previous")

    def fail_replace(*args):
        raise OSError("simulated crash boundary")

    monkeypatch.setattr(utility.os, "replace", fail_replace)
    with pytest.raises(OSError):
        utility.write_private(path, "next", exclusive=False)
    assert path.read_text() == "previous"


def test_cleanup_rejects_namespace_with_unowned_process_before_phy_move(utility, environment):
    env, system, profile, out = environment
    env.prepare("isolated22", profile, "192.0.2.20/24", out)
    original = system.run

    def run(argv):
        if "pids" in argv:
            return "99999\n"
        return original(argv)

    system.run = run
    before = len(system.calls)
    with pytest.raises(utility.Gap):
        env.cleanup(out)
    assert not any("set" in c and "netns" in c for c in system.calls[before:])


def test_protected_identity_change_aborts_cleanup_before_commands(utility, environment):
    env, system, profile, out = environment
    env.prepare("isolated22", profile, "192.0.2.20/24", out)
    (env.sysroot / "bus/pci/devices/0000:07:00.0/net/another27").mkdir()
    before = len(system.calls)
    with pytest.raises(utility.Gap):
        env.cleanup(out)
    assert len(system.calls) == before


def test_changed_namespace_inode_aborts_without_commands(utility, environment):
    env, system, profile, out = environment
    env.prepare("isolated22", profile, "192.0.2.20/24", out)
    system.namespace_identity = lambda name: 333
    before = len(system.calls)
    with pytest.raises(utility.Gap):
        env.cleanup(out)
    assert len(system.calls) == before


def test_nm_enabled_or_required_tool_missing_aborts_before_mutation(utility, environment, monkeypatch):
    env, system, profile, out = environment
    monkeypatch.setattr(utility, "radio_disabled", lambda: False)
    with pytest.raises(utility.Gap):
        env.prepare("isolated22", profile, "192.0.2.20/24", out)
    assert not system.calls
    monkeypatch.setattr(utility, "radio_disabled", lambda: True)
    tools = system.tools()
    tools["wpa_supplicant"] = None
    system.tools = lambda: tools
    with pytest.raises(utility.Gap):
        env.prepare("isolated22", profile, "192.0.2.20/24", out)
    assert not system.calls


def test_real_process_boundary_uses_pidfd_and_refuses_reused_pid(utility, monkeypatch):
    system = utility.System()
    monkeypatch.setattr(utility.os, "pidfd_open", lambda pid: 999)
    monkeypatch.setattr(utility.os, "close", lambda fd: None)
    monkeypatch.setattr(system, "alive", lambda process: False)

    def forbidden_signal(*args):
        pytest.fail("reused PID must never be signalled")

    monkeypatch.setattr(utility.signal, "pidfd_send_signal", forbidden_signal)
    with pytest.raises(utility.Gap):
        system.terminate({"pid": 123, "start": "original"})


def test_association_only_does_not_guess_or_assign_ip(utility, environment):
    env, system, profile, out = environment
    env.prepare("isolated22", profile, None, out, association_only=True)
    assert not any("address" in c or "route" in c for c in system.calls)
    assert json.loads(out.read_text())["address_mode"] == "association_only"
    assert "offline-test-password" not in out.read_text()
    env.cleanup(out)


def test_association_only_and_address_are_mutually_exclusive(utility, environment):
    env, system, profile, out = environment
    with pytest.raises(utility.Gap):
        env.prepare("isolated22", profile, "192.0.2.20/24", out, association_only=True)
    assert not system.calls


def test_dangling_foreign_rfkill_does_not_block_guard_or_cleanup(utility, environment):
    env, system, profile, out = environment
    protected = env.sysroot / "class/rfkill/rfkill1"
    protected.mkdir(parents=True)
    for name, value in {"name": "phy9", "soft": "0", "hard": "0"}.items():
        (protected / name).write_text(value)
    env.prepare("isolated22", profile, None, out, association_only=True)
    baseline = env.state["protected"]
    # Moving the foreign MT7922 leaves a visible class symlink with no target.
    (protected.parent / "rfkill2").symlink_to(env.sysroot / "disappeared-mt7922-rfkill")
    assert utility.protected_snapshot(env.sysroot) == baseline
    env.guard()
    env.cleanup(out)
    assert not env.runtime.exists()
    assert not system.namespaces


def test_missing_recorded_protected_rfkill_still_blocks_cleanup(utility, environment):
    env, system, profile, out = environment
    protected = env.sysroot / "class/rfkill/rfkill1"
    protected.mkdir(parents=True)
    for name, value in {"name": "phy9", "soft": "0", "hard": "0"}.items():
        (protected / name).write_text(value)
    env.prepare("isolated22", profile, None, out, association_only=True)
    (protected / "name").unlink()
    before = len(system.calls)
    with pytest.raises(utility.Gap):
        env.cleanup(out)
    assert len(system.calls) == before
    assert system.running
