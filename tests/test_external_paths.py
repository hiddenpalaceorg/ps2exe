import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from common.iso_path_reader.methods.directory import DirectoryPathReader
from utils.installshield import InstallShieldCabWrapper, InstallShieldError


def test_directory_boundary_checks_handles_and_symlinks(tmp_path):
    root = tmp_path / "disc"
    root.mkdir()
    (root / "nested").mkdir()
    inside = root / "nested" / "normal file.bin"
    inside.write_bytes(b"inside")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    (root / "link").symlink_to(outside)
    reader = DirectoryPathReader(root)
    for path in ("../outside.bin", str(outside), root / "link"):
        for operation in (reader.get_file, reader.open_file, reader.get_file_size, reader.is_directory):
            with pytest.raises(PermissionError):
                operation(path)
    for path in ("nested/normal file.bin", inside):
        with reader.open_file(reader.get_file(path)) as fp:
            assert fp.read() == b"inside"
    assert list(reader.iso_iterator(root, recursive=True)) == [inside]
    # A handle obtained before a symlink changes must be checked again at use.
    handle = reader.get_file(inside)
    inside.unlink()
    inside.symlink_to(outside)
    with pytest.raises(PermissionError):
        reader.open_file(handle)


def test_cwd_relative_input_keeps_its_original_meaning(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("disc").mkdir()
    Path("disc/file.bin").write_bytes(b"inside")
    reader = DirectoryPathReader(Path("disc"))
    for name in ("disc/file.bin", "file.bin"):
        with reader.open_file(reader.get_file(name)) as fp:
            assert fp.read() == b"inside"


@pytest.mark.parametrize("directory,name", [
    ("../private", "file"), ("/private", "file"), ("\\\\server\\share", "file"),
    ("C:\\private", "file"), ("safe", "../../file"), ("safe", "/file"),
    ("safe", "C:file"), ("safe", "..\\file"),
])
def test_recorded_external_names_are_rejected_before_lookup(directory, name):
    wrapper = object.__new__(InstallShieldCabWrapper)
    wrapper._directory_name = lambda index, raw=False: directory
    wrapper._read_string = lambda offset: name
    wrapper.common = SimpleNamespace(cab_descriptor_offset=0)
    wrapper.cab = SimpleNamespace(file_table_offset=0)
    wrapper._open_external_at_recorded_path = lambda *args: pytest.fail("unsafe lookup")
    with pytest.raises(InstallShieldError, match="Unsafe external"):
        wrapper._open_external(SimpleNamespace(directory_index=0, name_offset=0), "member")


def test_relative_external_name_preserves_media_layout():
    wrapper = object.__new__(InstallShieldCabWrapper)
    wrapper._directory_name = lambda index, raw=False: "Setup Files\\English"
    wrapper._read_string = lambda offset: "normal file.bin"
    wrapper.common = SimpleNamespace(cab_descriptor_offset=0)
    wrapper.cab = SimpleNamespace(file_table_offset=0)
    result = io.BytesIO(b"normal")
    def lookup(fd, directory, name, path):
        assert directory == "Setup Files/English"
        assert name == "normal file.bin"
        return result
    wrapper._open_external_at_recorded_path = lookup
    assert wrapper._open_external(SimpleNamespace(directory_index=0, name_offset=0), "member") is result
