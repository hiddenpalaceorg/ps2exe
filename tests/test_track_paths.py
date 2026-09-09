from types import SimpleNamespace

import pytest

from common.iso_path_reader.methods.directory import DirectoryPathReader
from dreamcast.processor import DreamcastIsoProcessor


def processor(root):
    instance = object.__new__(DreamcastIsoProcessor)
    instance.iso_path_reader = SimpleNamespace(parent_container=DirectoryPathReader(root), fp=SimpleNamespace(starting_sector=0))
    return instance


@pytest.mark.parametrize("name", ["../outside.bin", "/outside.bin", "..\\outside.bin", "C:\\outside.bin", "C:outside.bin", "\\\\host\\share\\file"])
def test_descriptor_names_and_direct_callers_reject_escape(tmp_path, name):
    p = processor(tmp_path)
    gdi = tmp_path / "disc.gdi"
    gdi.write_text(f'2\n1 0 4 2352 "disc.bin" 0\n2 10 4 2352 "{name}" 0\n')
    with pytest.raises(ValueError, match="Unsafe disc track"):
        p.parse_gdi(str(gdi), "disc.bin")
    cue = tmp_path / "disc.cue"
    cue.write_text(f'FILE "{name}" BINARY\n  TRACK 01 MODE1/2352\nFILE "disc.bin" BINARY\n  TRACK 03 MODE1/2352\n')
    with pytest.raises(ValueError, match="Unsafe disc track"):
        p.parse_cue(str(cue), "disc.bin")
    with pytest.raises(ValueError, match="Unsafe disc track"):
        p.get_fp_from_gdi(gdi, [{"file_name": name}])


def test_track_symlink_cannot_leave_root_and_relative_tracks_work(tmp_path):
    root = tmp_path / "disc"
    root.mkdir()
    (root / "Audio Files").mkdir()
    track = root / "Audio Files" / "track 2.bin"
    track.write_bytes(b"normal")
    outside = tmp_path / "private.bin"
    outside.write_bytes(b"private")
    (root / "link.bin").symlink_to(outside)
    p = processor(root)
    with pytest.raises(ValueError, match="outside"):
        p._track_file(root, "link.bin")
    for name in ("Audio Files/track 2.bin", "Audio Files\\track 2.bin"):
        with p.iso_path_reader.parent_container.open_file(p._track_file(root, name)) as fp:
            assert fp.read() == b"normal"
    gdi = root / "disc.gdi"
    gdi.write_text('2\n1 0 4 2352 "disc.bin" 0\n2 10 4 2352 "Audio Files/track 2.bin" 0\n')
    tracks = p.parse_gdi(str(gdi), "disc.bin")
    assert tracks[1]["file_name"] == "Audio Files/track 2.bin"


def test_relative_root_cannot_rewrite_validated_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from pathlib import Path
    Path("tests").mkdir()
    Path("outside.bin").write_bytes(b"outside")
    Path("tests/outside.bin").write_bytes(b"inside")
    p = processor(Path("tests"))
    target = p._track_file(Path("tests"), "outside.bin")
    with p.iso_path_reader.parent_container.open_file(target) as fp:
        assert fp.read() == b"inside"
