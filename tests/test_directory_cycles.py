import io
import struct
from types import SimpleNamespace

import pytest

from common.traversal import Traversal, TraversalError
from p3do.operafs.directory import Directory as OperaDirectory
from xbox.xdvdfs.directory import Directory as XboxDirectory
from xbox.stfs.stfs import STFS


class Source(io.BytesIO):
    seeks = 0
    def seek(self, offset, whence=0):
        self.seeks += 1
        assert self.seeks < 100, "unbounded traversal"
        return super().seek(offset, whence)
    def length(self):
        return len(self.getvalue())


def xbox_entry(left=0, right=0, flags=0, size=0, name=b"a"):
    return struct.pack("<HHIIBB", left, right, 0, size, flags, len(name)) + name


@pytest.mark.parametrize("side", ["left", "right"])
def test_xbox_entry_cycles(side):
    data = bytearray(64)
    data[:15] = xbox_entry(**{side: 4})
    data[16:31] = xbox_entry(**{side: 4})
    with pytest.raises(TraversalError, match="Cyclic"):
        XboxDirectory(Source(data), SimpleNamespace(volume_base_offset=0, sector_size=2048), 0, "root", 64)


def test_xbox_parent_cycle_and_valid_tree():
    volume = SimpleNamespace(volume_base_offset=0, sector_size=2048)
    with pytest.raises(TraversalError, match="Cyclic"):
        XboxDirectory(Source(xbox_entry(flags=0x10, size=64) + bytes(49)), volume, 0, "root", 64)
    data = bytearray(64)
    data[:15] = xbox_entry(left=4, name=b"a")
    data[16:31] = xbox_entry(name=b"b")
    directory = XboxDirectory(Source(data), volume, 0, "root", 64)
    assert [e.file_name for e in directory.entries] == ["b", "a"]
    data[:15] = xbox_entry(left=4, name=b"c")
    data[16:31] = xbox_entry(left=8, name=b"b")
    data[32:47] = xbox_entry(name=b"a")
    directory = XboxDirectory(Source(data), volume, 0, "root", 64)
    assert [e.file_name for e in directory.entries] == ["a", "b", "c"]


def opera_block(next_block=0xffffffff, flags=0):
    data = bytearray(2048)
    struct.pack_into(">IIIII", data, 0, next_block, 0xffffffff, 0, 92 if flags else 20, 20)
    if flags:
        struct.pack_into(">II4sIIIII32sII", data, 20, flags, 1, b"file", 2048, 1, 1, 0, 0, b"entry", 0, 0)
    return data


@pytest.mark.parametrize("data", [opera_block(0), opera_block(1) + opera_block(1), opera_block(flags=7)])
def test_opera_header_and_parent_cycles(data):
    with pytest.raises(TraversalError, match="Cyclic"):
        OperaDirectory(Source(data), 0, "root")


def test_opera_normal_file():
    directory = OperaDirectory(Source(opera_block(flags=2)), 0, "root")
    assert [e.file_name for e in directory.entries] == ["entry"]


def stfs_table(parents):
    data = bytearray(64 * len(parents))
    for index, parent in enumerate(parents):
        data[index * 64:index * 64 + 1] = bytes([65 + index % 26])
        struct.pack_into(">h", data, index * 64 + 0x32, parent)
    obj = STFS.__new__(STFS)
    obj.filetable_blocknumber = 0
    obj.filetable_blockcount = 1
    obj.read_filetable = lambda *args: data
    obj.parse_filetable()
    return obj


@pytest.mark.parametrize("parents", [[0], [1, 0], [-2, -1], [99], list(range(1, 130)) + [-1]])
def test_stfs_invalid_parent_graphs(parents):
    with pytest.raises(ValueError):
        stfs_table(parents)


def test_stfs_root_and_child_paths():
    assert set(stfs_table([-1, 0]).allfiles) == {b"/A", b"/A/B"}


def test_aliases_allowed_but_depth_and_total_work_are_bounded():
    walk = Traversal()
    root = walk.enter(1, frozenset())
    assert walk.enter(2, root) == walk.enter(2, root)
    walk.MAX_DEPTH = 2
    with pytest.raises(TraversalError, match="depth"):
        walk.enter(3, root | {2})
    walk.MAX_NODES = walk.nodes
    with pytest.raises(TraversalError, match="node"):
        walk.take()


@pytest.mark.parametrize("cyclic", [False, True])
def test_high_sierra_queue_checks_ancestry(monkeypatch, cyclic):
    from utils import pycdlib as hs

    root = SimpleNamespace(extent_location=lambda: 5, get_data_length=lambda: 1,
        set_ptr=lambda ptr: None, track_child=lambda *args: None)
    class Record:
        rock_ridge = None
        def parse(self, vd, data, parent): self.parent = parent
        def is_symlink(self): return False
        def is_dot(self): return False
        def is_dotdot(self): return False
        def is_dir(self): return True
        def get_data_length(self): return 0
        def extent_location(self): return 5 if cyclic else 6
        def set_ptr(self, ptr): pass
    monkeypatch.setattr(hs, "HsDirectoryRecord", Record)
    reader = SimpleNamespace(is_hs=True, _cdfp=io.BytesIO(b"\x01"),
        _get_iso_size=lambda: 2048, _seek_to_extent=lambda extent: None,
        logical_block_size=2048)
    vd = SimpleNamespace(is_pvd=lambda: False, root_directory_record=lambda: root)
    if cyclic:
        with pytest.raises(TraversalError, match="Cyclic"):
            hs.PyCdlib._walk_directories(reader, vd, {5: None, 6: None}, {}, [None])
    else:
        assert hs.PyCdlib._walk_directories(reader, vd, {6: None}, {}, [None]) == (1, 0)


@pytest.mark.parametrize("cyclic", [False, True])
def test_udf_queue_checks_ancestry(monkeypatch, cyclic):
    from common.udf import pycdlib_udf as udf

    desc = SimpleNamespace(log_block_num=0, offset=0, extent_length=1)
    root = SimpleNamespace(alloc_descs=[desc], track_file_ident_desc=lambda ident: None)
    leaf = SimpleNamespace(alloc_descs=[], track_file_ident_desc=lambda ident: None)
    class Tag:
        tag_ident = 257
        def parse(self, *args): pass
    class Ident:
        icb = SimpleNamespace(log_block_num=0 if cyclic else 1)
        def parse(self, *args): return 1
        def is_parent(self): return False
        def is_dir(self): return True
    monkeypatch.setattr(udf.udfmod, "UDFTag", Tag)
    monkeypatch.setattr(udf, "UDFFileIdentifierDescriptor", Ident)
    reader = SimpleNamespace(
        udf_main_descs=SimpleNamespace(partitions=[SimpleNamespace(part_start_location=0)]),
        root_relative_location=10, udf_file_set=SimpleNamespace(root_dir_icb=SimpleNamespace(log_block_num=0)),
        _parse_udf_file_entry=lambda extent, icb, parent: root if extent == 10 else leaf,
        _cdfp=io.BytesIO(b"x"), _seek_to_extent=lambda extent: None,
        logical_block_size=2048, vat=None)
    if cyclic:
        with pytest.raises(TraversalError, match="Cyclic"):
            udf.PyCdlibUdf._walk_udf_directories(reader, {})
    else:
        udf.PyCdlibUdf._walk_udf_directories(reader, {})
