#!/usr/bin/env python3
"""Root-only, opt-in MT7922 association sandbox. NEVER invoked by WHD collectors.

prepare --namespace NAME --profile /etc/NetworkManager/system-connections/PROFILE \
        (--association-only | --address EXPLICIT_IPV4_CIDR) \
        --out /persistent/private/evidence.json
verify --out /persistent/private/evidence.json
cleanup --out /persistent/private/evidence.json

No DHCP guessing, gateway, DNS, forwarding, monitor, traffic generator, server,
tracefs, NM changes, rfkill writes or module operations. Manual IPv4 only; discover
DHCP executables but report that this minimal utility does not launch them.
Use --association-only for parent-managed bounded DHCP inside this namespace;
the parent owns its DHCP process/hook, lease validation and route evidence.
Profile support: stored SAE/WPA-PSK only. Unsupported settings fail closed.
Credentials exist only in memory and root-private tmpfs; wpa.conf is unlinked
after the supplicant control socket answers PING, and also on setup failure.
The supplicant retains credentials in memory until cleanup. Disabling swap is
NOT attempted; tmpfs can be swapped by the host. No credential output or logs.

Only a dedicated netns and the dynamically selected MT7922 PHY are changed.
Failures retain redacted recovery state: run cleanup before retrying. SIGKILL
or a crash may leave wpa.conf in tmpfs until cleanup/reboot. Existing resources
are never adopted. Cleanup requires the original boot/host namespace and exact
namespace inode/process lifetime. Review before root execution.
"""

from __future__ import annotations

import argparse
import configparser
import fcntl
import ipaddress
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path

PROFILE_OWNER = 0
RUNTIME = Path("/run/whd-mt7922")


class Gap(Exception):
    """A deliberately non-sensitive refusal or recoverable limitation."""


def validate_namespace(name):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", name):
        raise Gap("invalid namespace name")
    return name


def validate_address(address):
    try:
        if not address or "/" not in address:
            raise ValueError
        addr = ipaddress.IPv4Interface(address)
        if addr.ip.is_multicast or addr.ip.is_unspecified or addr.ip.is_loopback:
            raise ValueError
        if addr.network.prefixlen < 31 and addr.ip in (
            addr.network.network_address,
            addr.network.broadcast_address,
        ):
            raise ValueError
        return str(addr)
    except ValueError:
        raise Gap(
            "explicit usable IPv4 CIDR required; DHCP is not implemented"
        ) from None


def discover(root=Path("/sys")):
    selected, protected = [], []
    for p in sorted((root / "bus/pci/devices").iterdir()):
        if (p / "vendor").read_text().strip().lower() != "0x14c3":
            continue
        device = (p / "device").read_text().strip().lower()
        if device not in ("0x0616", "0x7927"):
            continue
        driver = (p / "driver").resolve().name if (p / "driver").exists() else None
        phys = sorted(x.name for x in (p / "ieee80211").glob("*"))
        interfaces = sorted(x.name for x in (p / "net").glob("*"))
        if device == "0x0616":
            if (
                driver not in ("mt7921e", "mt7921e_git")
                or len(phys) != 1
                or len(interfaces) != 1
            ):
                raise Gap("MT7922 driver/PHY/interface identity is ambiguous")
            phy, iface = phys[0], interfaces[0]
            if not re.fullmatch(r"phy[0-9]+", phy) or not re.fullmatch(
                r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", iface
            ):
                raise Gap("unsafe discovered PHY/interface name")
            selected.append(
                {"bdf": p.name, "driver": driver, "phy": phy, "iface": iface}
            )
        else:
            protected.append(
                {
                    "bdf": p.name,
                    "driver": driver,
                    "phys": phys,
                    "iface": interfaces[0] if len(interfaces) == 1 else None,
                    "interfaces": interfaces,
                }
            )
    if len(selected) != 1:
        raise Gap("exactly one dynamically discovered MT7922 is required")
    if any(
        selected[0]["phy"] in p["phys"] or selected[0]["iface"] in p["interfaces"]
        for p in protected
    ):
        raise Gap("selected and protected device identity overlaps")
    return selected[0], protected


def read_private(path, owner=0):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Gap("private input unavailable or linked") from None
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != owner
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_nlink != 1
        ):
            raise Gap("private input must be an owned 0600 regular file without links")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise Gap("private input too large")
        return data
    finally:
        os.close(fd)


def unescape(value):
    escapes = {"s": " ", "n": "\n", "t": "\t", "r": "\r", "\\": "\\", ";": ";"}
    return re.sub(
        r"\\(.)", lambda m: escapes[m[1]] if m[1] in escapes else fail_profile(), value
    )


def fail_profile():
    raise Gap("unsupported or incomplete stored Wi-Fi profile")


def quote(value):
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        fail_profile()
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def clone_profile(text):
    """Translate supported NM keyfile values without persisting the original."""
    try:
        cp = configparser.ConfigParser(interpolation=None, strict=True)
        cp.read_string(text)
        if cp.defaults() or cp.get("connection", "type") not in (
            "wifi",
            "802-11-wireless",
        ):
            fail_profile()
        ws = "wifi" if "wifi" in cp else "802-11-wireless"
        ss = "wifi-security" if "wifi-security" in cp else "802-11-wireless-security"
        wifi, sec = cp[ws], cp[ss]
        if "802-1x" in cp or set(wifi) - {
            "ssid",
            "mode",
            "hidden",
            "mac-address",
            "seen-bssids",
        }:
            fail_profile()
        if wifi.get("mode", "infrastructure") != "infrastructure":
            fail_profile()
        if set(sec) - {
            "key-mgmt",
            "psk",
            "psk-flags",
            "pmf",
            "auth-alg",
            "proto",
            "pairwise",
            "group",
        }:
            fail_profile()
        km = {"sae": "SAE", "wpa-psk": "WPA-PSK"}.get(sec.get("key-mgmt"))
        if (
            km is None
            or sec.get("psk-flags", "0") != "0"
            or sec.get("auth-alg", "open") != "open"
        ):
            fail_profile()
        raw_ssid = wifi["ssid"]
        if re.fullmatch(r"(?:[0-9]{1,3};)+", raw_ssid):
            ssid = bytes(int(x) for x in raw_ssid.split(";")[:-1])
        else:
            ssid = unescape(raw_ssid).encode("utf-8")
        if not 1 <= len(ssid) <= 32:
            fail_profile()
        credential = unescape(sec["psk"])
        # Never allow line injection, even for SAE.
        quoted = quote(credential)
        if not credential or (
            km == "WPA-PSK"
            and not (
                8 <= len(credential.encode()) <= 63
                or re.fullmatch(r"[0-9a-fA-F]{64}", credential)
            )
        ):
            fail_profile()
        pmf = sec.get("pmf", "0")
        if pmf not in ("0", "1", "2", "3") or (km == "SAE" and pmf == "1"):
            fail_profile()
        # NM's default means required for SAE, optional for WPA-PSK.
        pmf_value = {"0": "2" if km == "SAE" else "1", "1": "0", "2": "1", "3": "2"}[
            pmf
        ]
        hidden = wifi.get("hidden", "false")
        if hidden not in ("true", "false", "1", "0"):
            fail_profile()
        lines = [
            "update_config=0",
            "network={",
            "ssid=" + ssid.hex(),
            "key_mgmt=" + km,
            "ieee80211w=" + pmf_value,
            "scan_ssid=" + ("1" if hidden in ("true", "1") else "0"),
        ]
        lines.append(
            ("sae_password=" + quoted)
            if km == "SAE"
            else "psk="
            + (credential if re.fullmatch(r"[0-9a-fA-F]{64}", credential) else quoted)
        )
        for option, allowed in {
            "proto": {"wpa", "rsn"},
            "pairwise": {"tkip", "ccmp"},
            "group": {"wep40", "wep104", "tkip", "ccmp"},
        }.items():
            if option in sec:
                values = sec[option].strip(";").split(";")
                if not values or any(v not in allowed for v in values):
                    fail_profile()
                lines.append(option + "=" + " ".join(v.upper() for v in values))
        return "\n".join(lines + ["}", ""])
    except (configparser.Error, KeyError, ValueError, UnicodeError):
        fail_profile()


def radio_disabled():
    # No NM mutations, scans, station queries, or secret retrieval.
    result = subprocess.run(
        ["/usr/bin/nmcli", "-g", "WIFI", "general"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=10,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "disabled"


def protected_snapshot(root):
    devices = []
    for p in sorted((root / "bus/pci/devices").iterdir()):
        if (p / "vendor").read_text().strip() == "0x14c3" and (
            p / "device"
        ).read_text().strip() == "0x7927":
            devices.append(
                {
                    "bdf": p.name,
                    "driver": (p / "driver").resolve().name,
                    "phys": sorted(x.name for x in (p / "ieee80211").glob("*")),
                    "interfaces": sorted(x.name for x in (p / "net").glob("*")),
                }
            )
    modules = {}
    for p in sorted((root / "module").glob("mt*")):
        if p.name.startswith(("mt76", "mt792")):
            modules[p.name] = {
                name: (p / name).read_text().strip()
                for name in ("version", "srcversion")
                if (p / name).exists()
            }
            modules[p.name]["holders"] = sorted(
                x.name for x in (p / "holders").glob("*")
            )
    rfkill = {}
    protected_phys = {phy for d in devices for phy in d["phys"]}
    for p in (root / "class/rfkill").glob("*"):
        try:
            name = (p / "name").read_text().strip()
        except FileNotFoundError:
            # Namespace moves can leave dangling foreign class entries. A
            # missing recorded protected entry still changes the snapshot.
            continue
        if name in protected_phys:
            rfkill[p.name] = {
                n: (p / n).read_text().strip() for n in ("name", "soft", "hard")
            }
    return {"devices": devices, "modules": modules, "rfkill": rfkill}


def write_private(path, data, exclusive=True):
    if not exclusive:
        read_private(path, owner=os.geteuid())
        fd, name = tempfile.mkstemp(prefix=".mt7922-state-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    flags |= os.O_EXCL if exclusive else os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def validate_output(out, runtime):
    if (
        runtime == out
        or runtime in out.parents
        or str(out).startswith(("/run/", "/tmp/", "/dev/", "/sys/", "/proc/"))
    ):
        raise Gap("output must be a persistent path outside runtime/system filesystems")
    parent = out.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
        raise Gap("output directory must be owned and not writable by others")


class System:
    def namespace_identity(self, name):
        return (Path("/run/netns") / name).stat().st_ino

    def tools(self):
        return {
            n: shutil.which(n, path="/usr/sbin:/usr/bin:/sbin:/bin")
            for n in (
                "ip",
                "iw",
                "wpa_supplicant",
                "wpa_cli",
                "mount",
                "umount",
                "dhclient",
                "udhcpc",
            )
        }

    def run(self, argv):
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode:
            raise Gap("OS command failed; output suppressed; use cleanup")
        return result.stdout

    def host_identity(self):
        return {
            "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "netns": os.stat("/proc/self/ns/net").st_ino,
        }

    def spawn(self, argv):
        child = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"pid": child.pid, "start": self.start(child.pid)}

    def start(self, pid):
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]

    def alive(self, process):
        try:
            return self.start(process["pid"]) == process["start"]
        except FileNotFoundError:
            return False

    def terminate(self, process):
        pid = process["pid"]
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            if not self.alive(process):
                raise Gap("supplicant PID lifetime changed; refusing signal")
            signal.pidfd_send_signal(fd, signal.SIGTERM)
            for _ in range(50):
                if not self.alive(process):
                    return
                # Reap if still our child, so a zombie does not block cleanup.
                try:
                    if os.waitpid(pid, os.WNOHANG)[0]:
                        return
                except ChildProcessError:
                    pass
                time.sleep(0.1)
            raise Gap("supplicant did not exit; cleanup stopped")
        finally:
            os.close(fd)

    def tmpfs(self, path):
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            left, right = line.split(" - ", 1)
            if left.split()[4] == str(path) and right.split()[0] == "tmpfs":
                return True
        return False


class Environment:
    def __init__(self, system=None, sysroot=Path("/sys"), runtime=RUNTIME):
        self.system = system or System()
        self.sysroot, self.runtime = sysroot, runtime
        self.state = None

    def save(self, out):
        # State/evidence contain only identities, argv without credentials, PIDs,
        # and fixed status codes. Never copy profile/config/stdout/error text.
        for path in (self.runtime / "state.json", out):
            if path.exists():
                read_private(path, owner=os.geteuid())
            write_private(
                path,
                json.dumps(self.state, indent=2) + "\n",
                exclusive=not path.exists(),
            )

    def command(self, *argv):
        self.state["commands"].append(list(argv))
        self.save(Path(self.state["out"]))
        return self.system.run(list(argv))

    def ns_command(self, *argv):
        return self.command(
            self.state["tools"]["ip"], "netns", "exec", self.state["namespace"], *argv
        )

    def guard(self):
        if self.system.host_identity() != self.state["host"]:
            raise Gap("boot/host network namespace changed")
        if (
            protected_snapshot(self.sysroot) != self.state["protected"]
            or not radio_disabled()
        ):
            raise Gap("protected identity/modules/rfkill or NM radio policy changed")
        p = self.sysroot / "bus/pci/devices" / self.state["selected"]["bdf"]
        if (
            (p / "vendor").read_text().strip() != "0x14c3"
            or (p / "device").read_text().strip() != "0x0616"
            or (p / "driver").resolve().name != self.state["selected"]["driver"]
        ):
            raise Gap("MT7922 PCI/driver identity changed")

    def prepare(self, namespace, profile, address, out, association_only=False):
        namespace = validate_namespace(namespace)
        if association_only and address is not None:
            raise Gap("--association-only and --address are mutually exclusive")
        if not association_only:
            address = validate_address(address)
        selected, _ = discover(self.sysroot)
        tools = self.system.tools()
        if any(
            not tools[n]
            for n in ("ip", "iw", "wpa_supplicant", "wpa_cli", "mount", "umount")
        ):
            raise Gap("required isolation/supplicant tool missing")
        if not radio_disabled():
            raise Gap("NM global Wi-Fi must already be disabled")
        if (
            self.runtime.exists()
            or self.runtime.is_symlink()
            or out.exists()
            or out.is_symlink()
        ):
            raise Gap("runtime/output collision; cleanup or use a new output")
        existing = self.system.run([tools["ip"], "netns", "list"])
        if namespace in [
            line.split()[0] for line in existing.splitlines() if line.strip()
        ]:
            raise Gap("namespace collision")
        config = clone_profile(read_private(profile, owner=PROFILE_OWNER))
        out = out.absolute()
        validate_output(out, self.runtime)
        self.runtime.mkdir(mode=0o700)
        self.state = {
            "phase": "initializing",
            "namespace": namespace,
            "selected": selected,
            "host": self.system.host_identity(),
            "protected": protected_snapshot(self.sysroot),
            "tools": tools,
            "out": str(out),
            "commands": [],
            "process": None,
            "namespace_created": False,
            "move_attempted": False,
            "address_mode": "association_only"
            if association_only
            else "explicit_manual_ipv4",
            "dhcp": "not launched",
        }
        # Reserve evidence before any kernel mutation.
        write_private(out, json.dumps(self.state, indent=2) + "\n")
        try:
            self.system.run(
                [
                    tools["mount"],
                    "-t",
                    "tmpfs",
                    "-o",
                    "mode=0700,nosuid,nodev,noexec,size=1m",
                    "whd-mt7922",
                    str(self.runtime),
                ]
            )
            self.system.run([tools["mount"], "--make-private", str(self.runtime)])
            if not self.system.tmpfs(self.runtime):
                raise Gap("private tmpfs mount not verified")
            self.save(out)
            self.command(tools["ip"], "netns", "add", namespace)
            self.state["namespace_created"] = True
            self.state["namespace_inode"] = self.system.namespace_identity(namespace)
            self.save(out)
            self.guard()
            # Save intent before move; cleanup probes whether it actually moved.
            self.state["move_attempted"] = True
            self.save(out)
            self.command(
                tools["iw"], "phy", selected["phy"], "set", "netns", "name", namespace
            )
            self.ns_command(tools["ip"], "link", "set", "dev", selected["iface"], "up")
            if not association_only:
                self.ns_command(
                    tools["ip"], "address", "add", address, "dev", selected["iface"]
                )
            cfg = self.runtime / "wpa.conf"
            write_private(cfg, config)
            config = None
            argv = [
                tools["ip"],
                "netns",
                "exec",
                namespace,
                tools["wpa_supplicant"],
                "-D",
                "nl80211",
                "-i",
                selected["iface"],
                "-c",
                str(cfg),
                "-C",
                str(self.runtime),
            ]
            self.state["commands"].append(argv)
            self.state["process"] = self.system.spawn(argv)
            self.save(out)
            loaded = False
            for _ in range(30):
                if not self.system.alive(self.state["process"]):
                    break
                try:
                    response = self.ns_command(
                        tools["wpa_cli"],
                        "-p",
                        str(self.runtime),
                        "-i",
                        selected["iface"],
                        "ping",
                    )
                    if response.strip() == "PONG":
                        loaded = True
                        break
                except Gap:
                    pass
                time.sleep(0.1)
            if not loaded:
                raise Gap("supplicant control socket unavailable; use cleanup")
            cfg.unlink()
            self.guard()
            self.state["phase"] = "prepared"
            self.save(out)
        except BaseException:  # noqa: BLE001 -- redact all failures including interrupts
            (self.runtime / "wpa.conf").unlink(missing_ok=True)
            self.state["phase"] = "failed_cleanup_required"
            # Even a mount failure leaves redacted evidence recoverable.
            self.save(out)
            raise Gap(
                "prepare failed; credentials unlinked; run cleanup with the same --out"
            ) from None

    def load(self, out):
        if self.runtime.is_symlink() or not self.runtime.is_dir():
            raise Gap("no owned runtime; cleanup cannot adopt resources")
        st = self.runtime.stat()
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise Gap("runtime is not private and owned")
        self.state = json.loads(
            read_private(self.runtime / "state.json", owner=os.geteuid())
        )
        if Path(self.state["out"]) != out.absolute():
            raise Gap("output does not match owned session")
        self.guard()
        if (
            self.state["namespace_created"]
            and self.system.namespace_identity(self.state["namespace"])
            != self.state["namespace_inode"]
        ):
            raise Gap("namespace lifetime changed")

    def verify(self, out):
        self.load(out)
        process = self.state["process"]
        if not process or not self.system.alive(process):
            raise Gap("owned supplicant is not running")
        response = self.ns_command(
            self.state["tools"]["wpa_cli"],
            "-p",
            str(self.runtime),
            "-i",
            self.state["selected"]["iface"],
            "status",
        )
        values = dict(
            line.split("=", 1) for line in response.splitlines() if "=" in line
        )
        value = values.get("wpa_state", "UNKNOWN")
        self.state["wpa_state"] = (
            value
            if value
            in {
                "DISCONNECTED",
                "INACTIVE",
                "SCANNING",
                "AUTHENTICATING",
                "ASSOCIATING",
                "ASSOCIATED",
                "4WAY_HANDSHAKE",
                "GROUP_HANDSHAKE",
                "COMPLETED",
            }
            else "UNKNOWN"
        )
        self.guard()
        self.save(out)
        return self.state["wpa_state"]

    def cleanup(self, out):
        self.load(out)
        tools = self.state["tools"]
        if self.state["process"]:
            self.system.terminate(self.state["process"])
            self.state["process"] = None
            self.save(out)
        (self.runtime / "wpa.conf").unlink(missing_ok=True)
        if (
            self.state["namespace_created"]
            and self.system.run(
                [tools["ip"], "netns", "pids", self.state["namespace"]]
            ).strip()
        ):
            raise Gap("namespace still has processes; refusing PHY move/removal")
        if self.state["move_attempted"]:
            phy = self.state["selected"]["phy"]
            # Probe namespace ownership first; never move a host/protected PHY.
            try:
                info = self.ns_command(tools["iw"], "phy", phy, "info")
            except Gap:
                info = None
            if info is not None:
                self.ns_command(
                    tools["iw"], "phy", phy, "set", "netns", str(os.getpid())
                )
            elif not (self.sysroot / "class/ieee80211" / phy).exists():
                raise Gap("MT7922 PHY location unknown; refusing namespace removal")
            self.state["move_attempted"] = False
            self.save(out)
        if self.state["namespace_created"]:
            # Do not kill/adopt other namespace processes.
            if self.system.run(
                [tools["ip"], "netns", "pids", self.state["namespace"]]
            ).strip():
                raise Gap("namespace still has processes; refusing removal")
            self.command(tools["ip"], "netns", "delete", self.state["namespace"])
            self.state["namespace_created"] = False
            self.save(out)
        self.guard()
        self.state["phase"] = "cleaned"
        self.save(out)
        for p in self.runtime.iterdir():
            if p.is_dir():
                raise Gap("unexpected runtime directory; refusing recursive cleanup")
            if p.name != "state.json":
                p.unlink()
        if self.system.tmpfs(self.runtime):
            self.system.run([tools["umount"], str(self.runtime)])
        # On real tmpfs this file vanished at unmount; retain it on umount
        # failure, allowing another cleanup. Also handles a failed initial mount.
        (self.runtime / "state.json").unlink(missing_ok=True)
        self.runtime.rmdir()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("action", choices=("prepare", "verify", "cleanup"))
    parser.add_argument("--namespace")
    parser.add_argument("--profile", type=Path)
    addressing = parser.add_mutually_exclusive_group()
    addressing.add_argument("--address")
    addressing.add_argument(
        "--association-only",
        action="store_true",
        help="skip IP configuration; parent owns namespace-local DHCP",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "root execution required\n")
    os.umask(0o077)
    # Serialize all entry points; never overwrite an existing namespace/session.
    fd = os.open(
        "/run/whd-mt7922.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != 0
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_nlink != 1
        ):
            raise Gap("unsafe lock file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        env = Environment()
        if args.action == "prepare":
            if not args.namespace or not args.profile:
                raise Gap("prepare requires --namespace and --profile")
            env.prepare(
                args.namespace,
                args.profile,
                args.address,
                args.out,
                association_only=args.association_only,
            )
        elif args.action == "verify":
            env.verify(args.out)
        else:
            env.cleanup(args.out)
        print(
            "MT7922 isolated "
            + args.action
            + ": complete; redacted status in selected output"
        )
    except Gap as error:
        parser.exit(1, str(error) + "\n")
    except Exception:  # noqa: BLE001 -- never echo sensitive OS/parser exceptions
        # Config parsing/subprocess/path exceptions must never echo secrets.
        parser.exit(
            1,
            "operation failed; details suppressed; inspect redacted state and use cleanup\n",
        )
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
