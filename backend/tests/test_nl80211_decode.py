"""Decoder tests against nl80211 messages recorded from a real MT7927 (fixture mt7927-pcie-host)."""

from conftest import fixture_host
from whd.platform.nl80211.decode import decode_cap_word, freq_to_channel


def test_recorded_mt7927_wiphy() -> None:
    nl = fixture_host("mt7927-pcie-host").nl80211()
    assert nl is not None
    (w,) = nl.wiphys()
    assert w.name == "phy1"
    assert [b.name for b in w.bands] == ["2GHZ", "5GHZ", "6GHZ"]
    six = w.bands[2]
    assert {x.width for x in six.widths} >= {"20", "80", "160", "320"}
    assert six.eht, "MT7927 advertises EHT capabilities"
    assert six.ht is None and six.vht is None  # no HT/VHT in 6 GHz
    assert all(c.channel is not None for c in six.channels)
    assert "STATION" in w.supported_iftypes and "MONITOR" in w.supported_iftypes
    assert "GCMP_256" in w.cipher_suites
    assert w.mlo_support
    assert any(m.iftype == "STATION" for m in w.mld)
    assert "AUTHENTICATE" in w.supported_commands


def test_recorded_interface_and_reg() -> None:
    nl = fixture_host("mt7927-pcie-host").nl80211()
    assert nl is not None
    (i,) = nl.interfaces()
    assert i.name == "wlp7s0" and i.iftype == "STATION" and i.wiphy == 1
    assert i.mac and i.mac.startswith("02:00:5e")  # scrubbed placeholder
    assert nl.power_save(i.ifindex) in ("ENABLED", "DISABLED")
    regs = nl.regdomains()
    assert regs and regs[0].alpha2 and regs[0].rules


def test_cap_word_mask_semantics() -> None:
    # VHT MAX_MPDU_LENGTH is a 2-bit field: value 2 => 11454 only
    flags = decode_cap_word(0x2, "IEEE80211_VHT_CAP_")
    assert "MAX_MPDU_LENGTH_11454" in flags and "MAX_MPDU_LENGTH_7991" not in flags


def test_freq_to_channel() -> None:
    assert freq_to_channel(2412) == 1
    assert freq_to_channel(2484) == 14
    assert freq_to_channel(5180) == 36
    assert freq_to_channel(5955, "6GHZ") == 1
    assert freq_to_channel(6115, "6GHZ") == 33


def test_synthetic_usb_station() -> None:
    nl = fixture_host("mt7921u-usb").nl80211()
    assert nl is not None
    (s,) = nl.stations(5)
    assert s.signal_dbm == -52 and s.tx_rate and s.tx_rate.mode == "HE" and s.tx_rate.width_mhz == 80
    assert s.chain_signal_dbm == [-54, -55]
    assert s.flags.get("AUTHORIZED") is True
