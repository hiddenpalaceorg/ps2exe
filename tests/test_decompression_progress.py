import io
import struct
import zipfile
from types import SimpleNamespace

import pytest

from utils.archives import Inflate64Reader, ImplodedReader
from utils.files import OffsetFile


class Buffer(io.BytesIO):
    offset = 0
    name = "buffer"

    def __getitem__(self, span):
        return self.getvalue()[span]

    def __setitem__(self, span, data):
        self.seek(span.start)
        self.write(data)


class Counted(io.BytesIO):
    calls = 0

    def read(self, size=-1):
        assert size != 0, "zero reads are not safe on archive-backed streams"
        self.calls += 1
        assert self.calls < 10, "decompression did not stop"
        return super().read(size)


def reader(cls, source, size):
    r = cls.__new__(cls)
    r.entry = SimpleNamespace(file_size=size)
    r.fp = Buffer()
    r.size = size
    r.pos = r.read_bytes = 0
    r.pbar = None
    r._closed = False
    r._running_crc = r._expected_crc = None
    r.name = "member"
    r.archive = SimpleNamespace(fp=source)
    r.compressed_left = len(source.getvalue())
    return r


@pytest.mark.parametrize("cls", [Inflate64Reader, ImplodedReader])
def test_truncated_member_stops_and_cleanup_does_not_drain(cls):
    source = Counted(b"")
    r = reader(cls, source, 100)
    r.decomp = SimpleNamespace(read=source.read, inflate=lambda data: data, eof=True)
    with pytest.raises(EOFError):
        r._get_data(100)
    calls = source.calls
    r.close()
    assert source.calls == calls
    assert r.fp.end_pos == 0


@pytest.mark.parametrize("cls", [Inflate64Reader, ImplodedReader])
def test_valid_member_and_repeated_cached_read(cls):
    source = Counted(b"hello")
    r = reader(cls, source, 5)
    r.decomp = SimpleNamespace(read=source.read, inflate=lambda data: data, eof=False)
    assert r._get_data(5) == b"hello"
    assert r._get_data(5) == b"hello"
    assert source.calls == 1


def test_inflate_does_not_consume_following_member_or_spin_on_empty_output():
    source = Counted(b"xyFOLLOWING")
    r = reader(Inflate64Reader, source, 100)
    r.compressed_left = 2
    r.decomp = SimpleNamespace(inflate=lambda data: b"", eof=False)
    with pytest.raises(EOFError):
        r._get_data(100)
    assert source.tell() == 2
    assert source.calls == 1


def test_inflate_can_consume_headers_before_emitting_output():
    source = Counted(b"a" * 65536 + b"hello")
    r = reader(Inflate64Reader, source, 5)
    r.decomp = SimpleNamespace(inflate=lambda data: b"" if len(data) == 65536 else data, eof=False)
    assert r._get_data(5) == b"hello"
    assert source.calls == 2


def test_real_inflater_and_zip_payload_offset():
    data = b"hello deflate" * 100
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED, compresslevel=0) as archive:
        archive.writestr("member", data)
        archive.writestr("following", b"next")
    raw = bytearray(packed.getvalue())
    struct.pack_into("<H", raw, 8, 9)
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, central + 10, 9)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entry = archive.getinfo("member")
        r = Inflate64Reader(entry, archive, Buffer())
        assert r.start_pos == 30 + len("member")
        assert r._get_data(len(data)) == data
        assert archive.fp.tell() == r.start_pos + entry.compress_size
        assert r._get_data(len(data)) == data
        r._closed = True


def test_real_imploded_literals_and_truncated_output():
    from bitarray import bitarray
    from utils.zip_explode import ExplodingInputStream

    bits = bitarray(endian="little")
    for byte in b"hello":
        bits.append(1)
        bits.extend(bool(byte & (1 << bit)) for bit in range(8))
    packed = bytes([3, 0xf5, 0xf5, 0xf5, 0xf5]) * 2 + bits.tobytes()
    source = Counted(packed)
    r = reader(ImplodedReader, source, 6)
    r.decomp = ExplodingInputStream(4096, 2, source)
    assert r._get_data(5) == b"hello"
    r.pos = 5
    with pytest.raises(EOFError):
        r._get_data(1)
    r.close()


def test_truncated_offset_file_preserves_only_readable_prefix():
    source = Counted(b"hello")
    r = reader(ImplodedReader, source, 6)
    r.fp = OffsetFile(Buffer(b"hello\x00"), 0, 6)
    r.decomp = source
    with pytest.raises(EOFError):
        r._get_data(6)
    assert len(r.fp) == 5
    assert r.fp[0:6] == b"hello"
    r.close()
