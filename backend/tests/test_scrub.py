from whd.fixtures.capture import Scrubber

MAC = "a4:cf:12:34:56:78"  # made-up address


def test_scrubber_masks_address_variants_sharing_the_device_tail() -> None:
    s = Scrubber(keep=False)
    s.add_mac(MAC)
    out = s.text(
        f"perm {MAC}\nderived a6:cf:12:34:56:78 / AE:CF:12:34:56:78\nother 02:00:5e:10:00:09\n".encode()
    ).decode()
    assert "cf:12:34:56:78" not in out.lower()
    lines = out.splitlines()
    assert lines[0] == "perm 02:00:5e:10:00:01"
    assert lines[1] == "derived a6:00:5e:10:00:01 / AE:00:5e:10:00:01"
    assert lines[2] == "other 02:00:5e:10:00:09"  # unrelated addresses are untouched


def test_keep_mac_leaves_text_alone() -> None:
    s = Scrubber(keep=True)
    s.add_mac(MAC)
    assert s.text(MAC.encode()) == MAC.encode()
