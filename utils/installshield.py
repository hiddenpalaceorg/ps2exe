import datetime
import io
import logging
import re
import struct
import zlib
from dataclasses import dataclass
from hashlib import md5

from utils.common import format_bar_desc
from utils.files import AccessBySliceFile, OffsetFile, get_file_size
from utils.in_memory_rollover_temp_file import InMemoryRolloverTempFile
from utils.progress import DecompressionCounterMixin
from utils.structs import Struct

try:
    import numpy
except ImportError:
    numpy = None

LOGGER = logging.getLogger(__name__)

CAB_SIGNATURE = b"ISc("
END_OF_CHUNK = b"\x00\x00\xff\xff"

FILE_SPLIT = 1
FILE_OBFUSCATED = 2
FILE_COMPRESSED = 4
FILE_INVALID = 8

LINK_PREV = 1
LINK_NEXT = 2

# Set by the scanner to locate cabinet volumes on sibling discs of a
# multi-disc set. Called with the wrapper, returns (container, base_dir)
# pairs to search; candidate volumes are validated before use
SIBLING_DISC_RESOLVER = None

# ror8(x ^ 0xd5, 2), the position-independent half of the deobfuscation step
_DEOBFUSCATE_TABLE = bytes((((b ^ 0xD5) >> 2) | ((b ^ 0xD5) << 6)) & 0xFF for b in range(256))
if numpy:
    _DEOBFUSCATE_TABLE_NP = numpy.frombuffer(_DEOBFUSCATE_TABLE, dtype=numpy.uint8)


def deobfuscate(data, seed):
    if numpy:
        rotated = _DEOBFUSCATE_TABLE_NP[numpy.frombuffer(data, dtype=numpy.uint8)]
        offsets = ((numpy.arange(len(data), dtype=numpy.int64) + seed) % 0x47).astype(numpy.uint8)
        return (rotated - offsets).tobytes(), seed + len(data)
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = (_DEOBFUSCATE_TABLE[b] - ((seed + i) % 0x47)) & 0xFF
    return bytes(out), seed + len(data)


def dos_date_time(date, time):
    return (1980 + (date >> 9), (date >> 5) & 0xF, date & 0x1F,
            time >> 11, (time >> 5) & 0x3F, (time & 0x1F) * 2)


class InstallShieldError(Exception):
    pass


class InstallShieldNotFirstVolume(InstallShieldError):
    """This ISc( file is a secondary data volume, the set is anchored elsewhere"""
    pass


class InstallShieldEmptyCabinet(InstallShieldError):
    pass


@dataclass
class CommonHeader(Struct):
    signature: bytes = b""
    version: int = 0
    volume_info: int = 0
    cab_descriptor_offset: int = 0
    cab_descriptor_size: int = 0

    struct = struct.Struct("<4sIIII")

    def check_magic(self):
        return self.signature == CAB_SIGNATURE


@dataclass
class CabDescriptor(Struct):
    file_table_offset: int = 0
    file_table_size: int = 0
    file_table_size2: int = 0
    directory_count: int = 0
    file_count: int = 0
    file_table_offset2: int = 0

    struct = struct.Struct("<12xI4xIII8xII")


@dataclass
class VolumeHeaderV5(Struct):
    data_offset: int = 0
    first_file_index: int = 0
    last_file_index: int = 0
    first_file_offset: int = 0
    first_file_size_expanded: int = 0
    first_file_size_compressed: int = 0
    last_file_offset: int = 0
    last_file_size_expanded: int = 0
    last_file_size_compressed: int = 0

    struct = struct.Struct("<I4x8I")


class VolumeHeaderV6(VolumeHeaderV5):
    struct = struct.Struct("<QIIQQQQQQ")


class FileDescriptor:
    index = None
    md5 = None
    volume = 1
    link_previous = 0
    link_next = 0
    link_flags = 0

    @property
    def valid(self):
        return not self.flags & FILE_INVALID and self.name_offset and self.data_offset


@dataclass
class FileDescriptorV5(FileDescriptor, Struct):
    name_offset: int = 0
    directory_index: int = 0
    flags: int = 0
    expanded_size: int = 0
    compressed_size: int = 0
    dos_date: int = 0
    dos_time: int = 0
    data_offset: int = 0

    struct = struct.Struct("<IH2xHII4xH2xH2x8xI")


@dataclass
class FileDescriptorV6(FileDescriptor, Struct):
    flags: int = 0
    expanded_size: int = 0
    compressed_size: int = 0
    data_offset: int = 0
    md5: bytes = b""
    name_offset: int = 0
    directory_index: int = 0
    dos_date: int = 0
    dos_time: int = 0
    link_previous: int = 0
    link_next: int = 0
    link_flags: int = 0
    volume: int = 0

    struct = struct.Struct("<HQQQ16s16xIH4xHH4xIIBH")


@dataclass
class OffsetList(Struct):
    name_offset: int = 0
    descriptor_offset: int = 0
    next_offset: int = 0

    struct = struct.Struct("<III")


@dataclass
class FileGroupV5(Struct):
    name_offset: int = 0
    first_file: int = 0
    last_file: int = 0

    struct = struct.Struct("<I72xii")


class FileGroupV6(FileGroupV5):
    struct = struct.Struct("<I18xii")


class InstallShieldVolumeReader:
    """Reads one file's raw (still compressed/obfuscated) data stream across volumes"""

    def __init__(self, wrapper, file_descriptor):
        self.wrapper = wrapper
        self.fd = file_descriptor
        self.index = file_descriptor.index
        self.volume = None
        self.volume_header = None
        self.volume_bytes_left = 0
        self.volume_fp = None
        self._volume_pos = 0
        self._deobfuscate_seed = 0
        self.open_volume(file_descriptor.volume)
        # IS5 and older don't store the volume in the file descriptor,
        # advance until we find the volume this file starts in
        while self.wrapper.major_version <= 5 and self.index > self.volume_header.last_file_index:
            self.open_volume(self.volume + 1)

    def open_volume(self, volume):
        fp = self.wrapper.get_volume_fp(volume)
        fp.seek(0)
        common_data = fp.read(CommonHeader.struct.size)
        if len(common_data) != CommonHeader.struct.size or \
                not CommonHeader.unpack(common_data).check_magic():
            raise InstallShieldError("Volume %d is not an InstallShield cabinet" % volume)

        if self.wrapper.major_version <= 5:
            header_class = VolumeHeaderV5
        else:
            header_class = VolumeHeaderV6
        header_data = fp.read(header_class.struct.size)
        if len(header_data) != header_class.struct.size:
            raise InstallShieldError("Short volume header in volume %d" % volume)
        header = self.volume_header = header_class.unpack(header_data)
        if self.wrapper.major_version <= 5 and header.last_file_offset == 0:
            header.last_file_offset = 0x7FFFFFFF

        fd = self.fd
        # IS5 doesn't set the split flag in the file descriptor, derive it
        # from the volume header
        if self.wrapper.major_version == 5:
            if (self.index < self.wrapper.cab.file_count - 1 and
                    self.index == header.last_file_index and
                    header.last_file_size_compressed != fd.compressed_size):
                fd.flags |= FILE_SPLIT
            elif (self.index > 0 and self.index == header.first_file_index and
                    header.first_file_size_compressed != fd.compressed_size):
                fd.flags |= FILE_SPLIT

        if fd.flags & FILE_SPLIT:
            if self.index == header.last_file_index and header.last_file_offset != 0x7FFFFFFF:
                data_offset = header.last_file_offset
                bytes_left_expanded = header.last_file_size_expanded
                bytes_left_compressed = header.last_file_size_compressed
            elif self.index == header.first_file_index:
                data_offset = header.first_file_offset
                bytes_left_expanded = header.first_file_size_expanded
                bytes_left_compressed = header.first_file_size_compressed
            else:
                self.volume = volume
                self.volume_fp = fp
                self.volume_bytes_left = 0
                return
        else:
            data_offset = fd.data_offset
            bytes_left_expanded = fd.expanded_size
            bytes_left_compressed = fd.compressed_size

        if fd.flags & FILE_COMPRESSED:
            self.volume_bytes_left = bytes_left_compressed
        else:
            self.volume_bytes_left = bytes_left_expanded

        self.volume = volume
        self.volume_fp = fp
        self._volume_pos = data_offset

    def read(self, size):
        result = bytearray()
        bytes_left = size
        while bytes_left:
            if self.volume_bytes_left == 0:
                # The previous read can end exactly at this file's last byte
                # in the current volume, so the crossing happens here
                self.open_volume(self.volume + 1)
                continue
            bytes_to_read = min(bytes_left, self.volume_bytes_left)
            # Volume file objects are shared between readers, always re-seek
            self.volume_fp.seek(self._volume_pos)
            data = self.volume_fp.read(bytes_to_read)
            if len(data) != bytes_to_read:
                raise InstallShieldError(
                    "Failed to read 0x%x bytes of file %d from volume %d at offset 0x%x" %
                    (bytes_to_read, self.index, self.volume, self._volume_pos))
            self._volume_pos += len(data)
            result += data
            bytes_left -= bytes_to_read
            self.volume_bytes_left -= bytes_to_read

        data = bytes(result)
        if self.fd.flags & FILE_OBFUSCATED:
            data, self._deobfuscate_seed = deobfuscate(data, self._deobfuscate_seed)
        return data


class InstallShieldExternalReader:
    """Reads a file whose data is stored in a separate file next to the
    cabinet instead of inside it (data offset at the end of the cabinet)"""

    # (source path, size) when the loose file matches neither recorded size,
    # i.e. the media carries a different version than the cabinet records
    version_mismatch = None

    def __init__(self, file_descriptor, fp, file_size):
        self.fd = file_descriptor
        self.fp = fp
        self.volume = file_descriptor.volume
        self._pos = 0
        self._deobfuscate_seed = 0
        self._tail = b""
        if file_descriptor.flags & FILE_COMPRESSED:
            # The compressed data is sometimes truncated just before its end
            # of chunk marker, virtually append it
            diff = file_descriptor.compressed_size - file_size
            if diff > 0:
                diff = min(len(END_OF_CHUNK), diff)
                self._tail = END_OF_CHUNK[len(END_OF_CHUNK) - diff:]
                self.volume_bytes_left = file_size + diff
            else:
                self.volume_bytes_left = file_descriptor.compressed_size
        else:
            self.volume_bytes_left = file_descriptor.expanded_size
        self._file_size = file_size

    def open_volume(self, volume):
        raise InstallShieldError(
            "No volume %d for external file %d" % (volume, self.fd.index))

    def read(self, size):
        bytes_to_read = min(size, self.volume_bytes_left)
        if bytes_to_read == 0:
            raise InstallShieldError("No more data for external file %d" % self.fd.index)
        result = b""
        from_file = min(bytes_to_read, self._file_size - self._pos)
        if from_file > 0:
            self.fp.seek(self._pos)
            result = self.fp.read(from_file)
        if len(result) < bytes_to_read and self._tail:
            tail_start = self._pos + len(result) - self._file_size
            if tail_start >= 0:
                result += self._tail[tail_start:tail_start + bytes_to_read - len(result)]
        if len(result) != bytes_to_read:
            raise InstallShieldError(
                "Failed to read 0x%x bytes of external file %d at offset 0x%x" %
                (bytes_to_read, self.fd.index, self._pos))
        self._pos += len(result)
        self.volume_bytes_left -= len(result)
        if size > bytes_to_read:
            raise InstallShieldError("No more data for external file %d" % self.fd.index)
        if self.fd.flags & FILE_OBFUSCATED:
            result, self._deobfuscate_seed = deobfuscate(result, self._deobfuscate_seed)
        return result


class InstallShieldFileReader(AccessBySliceFile, io.IOBase):
    def __init__(self, wrapper, file_descriptor, path):
        super().__init__()
        self.wrapper = wrapper
        self.fd = file_descriptor
        self.name = path
        raw = None
        try:
            # Resolve the data source before sizing this reader: an external
            # file on the media can be a different version than the cabinet
            # records, which corrects the descriptor's sizes. Errors are
            # deferred to the first read so files on missing volumes still
            # yield their partial data instead of failing to open
            raw = wrapper._make_raw_reader(file_descriptor, path)
        except (InstallShieldError, EOFError, OSError):
            pass
        self.size = file_descriptor.expanded_size
        self._version_mismatch = getattr(raw, "version_mismatch", None)
        self.read_bytes = 0
        start = wrapper.alloc_pos
        wrapper.alloc_pos += self.size
        self.fp = OffsetFile(wrapper.uncompressed, start, start + self.size, path)
        self.blocks = wrapper.new_style_blocks(file_descriptor, path, raw)
        self._md5 = md5()
        self._failed = False
        self._retried_old_style = False
        self._new_style_error = None

    def length(self):
        return self.size

    def __len__(self):
        return self.size

    def __getitem__(self, item):
        if isinstance(item, slice):
            pos = item.start
            length = item.stop - item.start
        else:
            pos = item
            length = 1
        self.seek(pos)
        return self._get_data(length)

    def _get_data(self, n, discard=False):
        needed = min(self.size, self.pos + n)
        if needed > self.read_bytes:
            self.fp.seek(self.read_bytes)
            while self.read_bytes < needed:
                try:
                    block = next(self.blocks)
                except StopIteration:
                    self._fail("expanded size expected to be %d, but was %d" %
                               (self.size, self.read_bytes))
                    break
                except (zlib.error, InstallShieldError, EOFError, OSError) as e:
                    if self._can_retry_old_style():
                        self._restart_old_style(e)
                        continue
                    self._fail(self._failure_message(e))
                    break
                if self.read_bytes + len(block) > self.size:
                    block = block[:self.size - self.read_bytes]
                if not block:
                    continue
                self.fp.write(block)
                self._md5.update(block)
                self.read_bytes += len(block)
                if self.wrapper.counter:
                    self.wrapper.counter.update(len(block))
            if self.read_bytes >= self.size and not self._failed:
                self._verify_md5()
        if not discard:
            return self.fp[self.pos:self.pos + n]

    def _can_retry_old_style(self):
        # Old-style cabinets (IS5 and older) delimit chunks with an end of
        # chunk marker instead of a length prefix. IS6+ is always new-style,
        # a retry would only misparse
        return (not self._retried_old_style and self.fd.flags & FILE_COMPRESSED
                and self.wrapper.major_version <= 5)

    def _restart_old_style(self, error):
        self._retried_old_style = True
        self._new_style_error = str(error)
        LOGGER.debug("Retrying %s with old-style decompression: %s", self.name, error)
        self.blocks = self.wrapper.old_style_blocks(self.fd, self.name)
        if self.wrapper.counter and self.read_bytes:
            # The failed attempt's blocks are already on the counter and
            # the retry recounts from the start
            self.wrapper.counter.update(-self.read_bytes)
        self.read_bytes = 0
        self._md5 = md5()
        self.fp.seek(0)

    def _failure_message(self, error):
        if self._retried_old_style and str(error) != self._new_style_error:
            message = "%s (retried old-style: %s)" % (self._new_style_error, error)
        else:
            message = str(error)
        if self._version_mismatch:
            source, file_size = self._version_mismatch
            message = ("external file %s is a different version than the "
                       "cabinet records (%d bytes on the media, %d recorded) "
                       "and does not decode as a compressed stream (%s)" %
                       (source, file_size, self.fd.expanded_size, message))
        return message

    def _fail(self, message):
        if not self._failed:
            self._failed = True
            LOGGER.warning("File %s could not be fully extracted: %s", self.name, message)
        self.fp.end_pos = self.fp.offset + self.read_bytes
        self.read_bytes = self.size

    def _verify_md5(self):
        # Only IS6 and later store a meaningful checksum
        if self.wrapper.major_version >= 6 and self.fd.md5 and self.fd.md5 != b"\x00" * 16:
            if self._md5.digest() != self.fd.md5:
                LOGGER.warning("MD5 checksum failure for file %s", self.name)
        self._verify_md5 = lambda: None

    def close(self):
        return


class InstallShieldEntry:
    is_dir = False
    date_time = None

    def __init__(self, wrapper, file_descriptor, path):
        self.wrapper = wrapper
        self.fd = file_descriptor
        self.path = path
        self.file_size = file_descriptor.expanded_size
        if file_descriptor.dos_date:
            self.date_time = dos_date_time(file_descriptor.dos_date, file_descriptor.dos_time)

    @property
    def file_name(self):
        return self.path

    def open(self):
        reader = self.wrapper.get_reader(self)
        reader.seek(0)
        return reader

    def close(self):
        return


class InstallShieldCabWrapper(DecompressionCounterMixin):
    MAX_FILE_COUNT = 4 * 1024 * 1024

    def __init__(self, fp, file_name, parent_container, pbar=None):
        self.fp = fp
        self.path = getattr(fp, "name", None) or file_name
        self.parent_container = parent_container
        self.pbar = pbar
        self.counter = None
        self.entries = {}
        self.uncompressed = None
        self.alloc_pos = 0
        self._readers = {}
        self._volume_fps = {}
        self._own_volume_fps = []
        self._string_cache = {}
        self._external_files = {}
        self._sibling_containers = None
        self._unresolved_volumes = set()
        self._ignored_obfuscation = 0
        self._closed = False

        # The volume set prefix is the base name up to the first dot or digit
        match = re.match(r"([^.\d]*)(\d*)", file_name)
        self.volume_prefix = match.group(1)
        self.own_volume = int(match.group(2)) if match.group(2) else 1
        extension = file_name[file_name.rfind("."):] if "." in file_name else ""
        self.is_header_file = extension.lower() == ".hdr"

        if "\\" in self.path and "/" not in self.path:
            self._sep = "\\"
        else:
            self._sep = "/"
        self._dir = self.path.rsplit(self._sep, 1)[0] if self._sep in self.path else ""

        fp.seek(0)
        common_data = fp.read(CommonHeader.struct.size)
        if len(common_data) != CommonHeader.struct.size:
            raise InstallShieldError("Not an InstallShield cabinet: %s" % file_name)
        self.common = CommonHeader.unpack(common_data)
        if not self.common.check_magic():
            raise InstallShieldError("Not an InstallShield cabinet: %s" % file_name)

        if not self.is_header_file:
            self._ensure_first_volume(file_name)

        if not self.common.cab_descriptor_offset or not self.common.cab_descriptor_size:
            raise InstallShieldError("Cabinet %s has no descriptor (data-only volume?)" % file_name)

        self.major_version = self._parse_major_version(self.common.version)

        self._parse_cab_descriptor()
        self._parse_entries()

        if not self.entries:
            raise InstallShieldEmptyCabinet("No valid files found in cabinet %s" % file_name)

        if not self.is_header_file:
            self._volume_fps[self.own_volume] = fp

        # Linked (duplicate) entries share one reader and decompress once, so
        # they contribute nothing to the counter or the decompression buffer
        unique_fds = {fd.index: fd for fd in
                      (self._resolve_link(entry.fd) for entry in self.entries.values())}
        self.total_size = float(sum(fd.expanded_size for fd in unique_fds.values()))
        self.uncompressed = InMemoryRolloverTempFile.with_memory_budget(int(self.total_size))

    def _ensure_first_volume(self, file_name):
        # The set is anchored at the .hdr file (IS6+) or the first .cab
        # volume (IS5 and older), skip secondary volumes so the set is only
        # processed once
        header_fp = self._open_sibling(1, "hdr")
        if header_fp is not None:
            self._close_fp(header_fp)
            raise InstallShieldNotFirstVolume(
                "%s is a data volume, set is anchored at its .hdr file" % file_name)
        if self.own_volume > 1:
            first_volume_fp = self._open_sibling(1, "cab")
            if first_volume_fp is not None:
                self._close_fp(first_volume_fp)
                raise InstallShieldNotFirstVolume(
                    "%s is a secondary volume of a multi-volume set" % file_name)

    @staticmethod
    def _parse_major_version(version):
        if version >> 24 == 1:
            return (version >> 12) & 0xF
        if version >> 24 in (2, 4):
            return (version & 0xFFFF) // 100
        return 0

    def __enter__(self):
        self._create_counter(self.total_size)
        return self

    def __exit__(self, *args):
        if self._closed:
            return
        self._closed = True
        for fp in self._own_volume_fps:
            self._close_fp(fp)
        self._own_volume_fps = []
        self._volume_fps = {}
        self._readers = {}
        if self.uncompressed:
            self.uncompressed.close()
        self._close_counter()

    def __del__(self):
        try:
            self.__exit__(None, None, None)
        except Exception:
            pass

    def __iter__(self):
        yield from self.entries.values()

    @staticmethod
    def _enter_fp(fp):
        try:
            fp.__enter__()
        except AttributeError:
            pass

    @staticmethod
    def _close_fp(fp):
        try:
            fp.__exit__(None, None, None)
        except AttributeError:
            pass
        try:
            fp.close()
        except Exception:
            pass

    def _read_at(self, offset, size):
        self.fp.seek(offset)
        data = self.fp.read(size)
        if len(data) != size:
            raise InstallShieldError(
                "Short read at offset 0x%x (expected 0x%x bytes, got 0x%x)" %
                (offset, size, len(data)))
        return data

    def _read_string(self, offset):
        if offset in self._string_cache:
            return self._string_cache[offset]
        self.fp.seek(offset)
        if self.major_version >= 17:
            # Unicode versions store UTF-16LE strings
            result = self._read_utf16_string()
        else:
            result = self._read_cp1252_string()
        self._string_cache[offset] = result
        return result

    def _read_utf16_string(self):
        buf = b""
        while len(buf) < 65536:
            chunk = self.fp.read(256)
            if not chunk:
                break
            buf += chunk
            for i in range(0, len(buf) - 1, 2):
                if buf[i] == 0 and buf[i + 1] == 0:
                    buf = buf[:i]
                    break
            else:
                continue
            break
        return buf.decode("utf-16-le", errors="replace")

    def _read_cp1252_string(self):
        buf = b""
        while len(buf) < 65536:
            chunk = self.fp.read(256)
            if not chunk:
                break
            terminator = chunk.find(b"\x00")
            if terminator >= 0:
                buf += chunk[:terminator]
                break
            buf += chunk
        return buf.decode("cp1252", errors="replace")

    def _parse_cab_descriptor(self):
        base = self.common.cab_descriptor_offset
        self.cab = CabDescriptor.unpack(self._read_at(base, CabDescriptor.struct.size))

        if self.cab.file_table_size != self.cab.file_table_size2:
            LOGGER.warning("File table sizes do not match in %s", self.path)

        if self.cab.file_count > self.MAX_FILE_COUNT or self.cab.directory_count > self.MAX_FILE_COUNT:
            raise InstallShieldError(
                "Bad file table (%d files, %d directories)" %
                (self.cab.file_count, self.cab.directory_count))

        count = self.cab.directory_count + self.cab.file_count
        table = self._read_at(base + self.cab.file_table_offset, count * 4)
        self.file_table = struct.unpack("<%dI" % count, table)

        self._parse_file_groups()

    def _parse_file_groups(self):
        base = self.common.cab_descriptor_offset
        group_class = FileGroupV5 if self.major_version <= 5 else FileGroupV6
        self.file_groups = []
        # The descriptor holds 71 file group list heads at offset 0x3E
        try:
            offsets = struct.unpack("<71I", self._read_at(base + 0x3E, 71 * 4))
        except InstallShieldError:
            return
        seen = set()
        for offset in offsets:
            next_offset = offset
            while next_offset and next_offset not in seen and len(seen) < self.MAX_FILE_COUNT:
                seen.add(next_offset)
                try:
                    entry = OffsetList.unpack(self._read_at(base + next_offset, OffsetList.struct.size))
                    next_offset = entry.next_offset
                    if not entry.descriptor_offset:
                        continue
                    group = group_class.unpack(
                        self._read_at(base + entry.descriptor_offset, group_class.struct.size))
                    name = self._read_string(base + group.name_offset)
                except (InstallShieldError, struct.error) as e:
                    LOGGER.warning("Could not read file group in %s: %s", self.path, e)
                    break
                self.file_groups.append(
                    (group.first_file, group.last_file, name.replace("\\", "/").strip("/")))

    def _file_group_name(self, index):
        for first_file, last_file, name in self.file_groups:
            if first_file <= index <= last_file:
                return name
        return ""

    def _directory_name(self, index, raw=False):
        if index >= self.cab.directory_count:
            if index != 0xFFFF:
                LOGGER.warning("Invalid directory index %d in %s", index, self.path)
            return ""
        name = self._read_string(
            self.common.cab_descriptor_offset + self.cab.file_table_offset + self.file_table[index])
        return name if raw else name.replace("\\", "/").strip("/")

    def _read_file_descriptor(self, index):
        base = self.common.cab_descriptor_offset
        if self.major_version <= 5:
            offset = (base + self.cab.file_table_offset +
                      self.file_table[self.cab.directory_count + index])
            fd = FileDescriptorV5.unpack(self._read_at(offset, FileDescriptorV5.struct.size))
            if self.major_version == 5:
                fd.md5 = self._read_at(offset + FileDescriptorV5.struct.size, 0x10)
            fd.volume = self.own_volume
            if fd.flags & FILE_OBFUSCATED:
                # IS5 and older set this bit on files that are stored plain;
                # the XOR obfuscation it selects only exists in IS6+, so
                # honoring it here corrupts the data (as unshield does)
                fd.flags &= ~FILE_OBFUSCATED
                self._ignored_obfuscation += 1
        else:
            offset = (base + self.cab.file_table_offset + self.cab.file_table_offset2 +
                      index * FileDescriptorV6.struct.size)
            fd = FileDescriptorV6.unpack(self._read_at(offset, FileDescriptorV6.struct.size))
        fd.index = index
        return fd

    def _parse_entries(self):
        self.file_descriptors = []
        invalid = 0
        for index in range(self.cab.file_count):
            try:
                fd = self._read_file_descriptor(index)
            except (InstallShieldError, struct.error, IndexError) as e:
                LOGGER.warning("Could not read file descriptor %d in %s: %s",
                               index, self.path, e)
                fd = FileDescriptorV5(flags=FILE_INVALID)
                fd.index = index
            self.file_descriptors.append(fd)

        for fd in self.file_descriptors:
            if not fd.valid:
                invalid += 1
                continue
            name = self._read_string(
                self.common.cab_descriptor_offset + self.cab.file_table_offset + fd.name_offset)
            if not name:
                invalid += 1
                continue
            directory = self._directory_name(fd.directory_index)
            group = self._file_group_name(fd.index)
            path = "/".join(part for part in (group, directory, name) if part)
            if path in self.entries:
                LOGGER.debug("Duplicate path %s in %s, keeping first", path, self.path)
                continue
            self.entries[path] = InstallShieldEntry(self, fd, path)

        if invalid:
            LOGGER.debug("Skipped %d invalid file entries in %s", invalid, self.path)
        if self._ignored_obfuscation:
            LOGGER.debug("Ignored the obfuscation flag on %d files in %s "
                         "(pre-IS6 cabinet, data is stored plain)",
                         self._ignored_obfuscation, self.path)

    def _open_sibling(self, index, extension, container=None, base_dir=None):
        if container is None:
            container = self.parent_container
        if base_dir is None:
            base_dir = self._dir
        names = []
        for prefix in (self.volume_prefix, self.volume_prefix.lower(), self.volume_prefix.upper()):
            for ext in (extension.lower(), extension.upper()):
                name = "%s%d.%s" % (prefix, index, ext)
                if name not in names:
                    names.append(name)
        directories = [base_dir]
        # Multi-disk layouts keep each volume in its own numbered directory
        # (disk1/data1.cab, disk2/data2.cab, ...)
        if base_dir:
            parent, sep, dir_name = base_dir.rpartition(self._sep)
            match = re.match(r"(.*?)(\d+)$", dir_name)
            if match:
                for number in {str(index), str(index).zfill(len(match.group(2)))}:
                    sibling_dir = parent + sep + match.group(1) + number
                    if sibling_dir not in directories:
                        directories.append(sibling_dir)
        for directory in directories:
            for name in names:
                path = directory + self._sep + name if directory else name
                try:
                    file = container.get_file(path)
                    fp = container.open_file(file)
                except Exception:
                    continue
                self._enter_fp(fp)
                try:
                    fp.seek(0)
                    if fp.read(4) == CAB_SIGNATURE:
                        return fp
                except Exception:
                    pass
                self._close_fp(fp)
        return None

    def get_volume_fp(self, volume):
        if volume in self._volume_fps:
            return self._volume_fps[volume]
        fp = self._open_sibling(volume, "cab")
        if fp is None:
            fp = self._open_cross_disc_volume(volume)
        if fp is None:
            raise InstallShieldError("Failed to open input cabinet file %d" % volume)
        self._volume_fps[volume] = fp
        self._own_volume_fps.append(fp)
        return fp

    def _open_cross_disc_volume(self, volume):
        if volume in self._unresolved_volumes:
            return None
        if self._sibling_containers is None:
            self._sibling_containers = []
            if SIBLING_DISC_RESOLVER is not None:
                try:
                    self._sibling_containers = list(SIBLING_DISC_RESOLVER(self))
                except Exception as e:
                    LOGGER.warning("Sibling disc resolution failed for %s: %s", self.path, e)
        for container, base_dir in self._sibling_containers:
            fp = self._open_sibling(volume, "cab", container, base_dir)
            if fp is None:
                continue
            if self._validate_volume(fp, volume):
                LOGGER.info("Resolved cabinet volume %d of %s from a sibling disc",
                            volume, self.path)
                return fp
            LOGGER.warning("Rejected cabinet volume %d candidate for %s: "
                           "not a volume of this set", volume, self.path)
            self._close_fp(fp)
        self._unresolved_volumes.add(volume)
        return None

    def _validate_volume(self, fp, volume):
        # A name-matched sibling can be an unrelated product (e.g. a sequel),
        # only accept a volume that provably belongs to this set
        try:
            fp.seek(0)
            common_data = fp.read(CommonHeader.struct.size)
            if len(common_data) != CommonHeader.struct.size:
                return False
            common = CommonHeader.unpack(common_data)
            if not common.check_magic() or common.version != self.common.version:
                return False
            header_class = VolumeHeaderV5 if self.major_version <= 5 else VolumeHeaderV6
            header_data = fp.read(header_class.struct.size)
            if len(header_data) != header_class.struct.size:
                return False
            header = header_class.unpack(header_data)
            if header.first_file_index > header.last_file_index or \
                    header.last_file_index >= self.cab.file_count:
                return False
            if self.major_version < 6:
                # Old descriptors store no per-file volumes or checksums,
                # version + header consistency is the best available check
                return True
            # The descriptor records which volume each file starts in;
            # those files must fall inside the range the volume claims
            own_files = [fd.index for fd in self.file_descriptors
                         if fd.valid and fd.volume == volume]
            if own_files and not (header.first_file_index <= min(own_files) and
                                  max(own_files) <= header.last_file_index):
                return False
            return self._md5_spot_check(fp, volume, header)
        except (InstallShieldError, struct.error, OSError, ValueError) as e:
            LOGGER.debug("Error validating cabinet volume %d candidate: %s", volume, e)
            return False

    def _md5_spot_check(self, fp, volume, header):
        # Decompress the smallest file stored wholly in the candidate volume
        # and compare it against the descriptor's embedded MD5
        volume_size = get_file_size(fp)
        candidates = [
            fd for fd in self.file_descriptors
            if fd.valid and fd.volume == volume and fd.md5 and fd.md5 != b"\x00" * 16
            and not fd.flags & FILE_SPLIT and not fd.link_flags & LINK_PREV
            and header.first_file_index <= fd.index <= header.last_file_index
            and (volume_size is None or fd.data_offset < volume_size)
        ]
        if not candidates:
            return True
        fd = min(candidates, key=lambda f: f.compressed_size)
        self._volume_fps[volume] = fp
        try:
            digest = md5()
            for block in self.new_style_blocks(fd, "volume %d spot check" % volume):
                digest.update(block)
            return digest.digest() == fd.md5
        except (zlib.error, InstallShieldError, EOFError, OSError) as e:
            LOGGER.debug("Cabinet volume %d candidate spot check failed: %s", volume, e)
            return False
        finally:
            del self._volume_fps[volume]

    def _resolve_link(self, fd):
        seen = set()
        while fd.link_flags & LINK_PREV:
            if fd.link_previous in seen or fd.link_previous >= len(self.file_descriptors):
                LOGGER.warning("Broken file link chain for file %d in %s", fd.index, self.path)
                break
            seen.add(fd.index)
            fd = self.file_descriptors[fd.link_previous]
        return fd

    def get_reader(self, entry):
        fd = self._resolve_link(entry.fd)
        reader = self._readers.get(fd.index)
        if reader is None:
            reader = InstallShieldFileReader(self, fd, entry.path)
            self._readers[fd.index] = reader
        entry.file_size = reader.size
        if self.counter:
            self.counter.update(incr=0, file_name=format_bar_desc(entry.path, 30))
        return reader

    def _make_raw_reader(self, fd, path):
        raw = InstallShieldVolumeReader(self, fd)
        volume_size = get_file_size(raw.volume_fp)
        if volume_size is not None and fd.data_offset >= volume_size:
            # The data is not inside the cabinet but in a separate file next
            # to it, in the file's directory
            LOGGER.debug("File %s is not inside the cabinet, trying external file", path)
            return self._open_external(fd, path)
        return raw

    def _open_external(self, fd, path):
        directory = self._directory_name(fd.directory_index, raw=True)
        name = self._read_string(
            self.common.cab_descriptor_offset + self.cab.file_table_offset + fd.name_offset)
        # These names now address host files, not installation destinations.
        # Validate before display-path normalization discards leading slashes.
        for value in (directory, name):
            normalized = value.replace("\\", "/")
            if (normalized.startswith("/") or ":" in normalized or
                    ".." in normalized.split("/") or "\x00" in normalized):
                raise InstallShieldError("Unsafe external file path")
        directory = directory.replace("\\", "/")
        name = name.replace("\\", "/")
        reader = self._open_external_at_recorded_path(fd, directory, name, path)
        if reader is None:
            reader = self._open_external_by_search(fd, directory, name, path)
        if reader is None:
            raise InstallShieldError(
                "File %s is not inside the cabinet and no external file was found" % path)
        return reader

    def _open_external_at_recorded_path(self, fd, directory, name, path):
        parts = [part for part in directory.split("/") if part] + [name]
        candidates = [self._sep.join(parts)]
        if len(parts) > 1:
            candidates.append(name)
        for candidate in candidates:
            full_path = self._dir + self._sep + candidate if self._dir else candidate
            try:
                file = self.parent_container.get_file(full_path)
                fp = self.parent_container.open_file(file)
                file_size = self.parent_container.get_file_size(file)
            except Exception:
                continue
            self._enter_fp(fp)
            self._own_volume_fps.append(fp)
            return self._make_external_reader(fd, fp, file_size, path, full_path)
        return None

    def _open_external_by_search(self, fd, directory, name, path):
        # The setup script can place external files in media subdirectories
        # the cabinet doesn't record (e.g. per-language directories); search
        # the cabinet's directory tree for them
        found = self._find_external_file(fd, directory, name)
        if not found:
            return None
        found_path, file_size, file = found
        try:
            fp = self.parent_container.open_file(file)
        except Exception as e:
            raise InstallShieldError(
                "Could not open external file %s for %s: %s" % (found_path, path, e))
        self._enter_fp(fp)
        self._own_volume_fps.append(fp)
        LOGGER.debug("Using external file %s for %s", found_path, path)
        return self._make_external_reader(fd, fp, file_size, path, found_path)

    def _make_external_reader(self, fd, fp, file_size, path, source):
        if fd.flags & FILE_COMPRESSED and \
                fd.compressed_size == fd.expanded_size == file_size:
            # Some cabinets flag external files as compressed even though
            # they are stored plain on the media
            LOGGER.debug("External file for %s is stored despite its compressed flag", path)
            fd.flags &= ~FILE_COMPRESSED
        if not fd.flags & FILE_COMPRESSED and file_size != fd.expanded_size:
            # The media can carry a different version of a loose file than
            # the cabinet records (updated after the cabinet was built); the
            # on-media file is what actually exists, so trust its size. The
            # descriptor's checksum describes the recorded version, not this one
            LOGGER.info("External file for %s is %d bytes on the media but the cabinet "
                        "records %d, using the on-media file", path, file_size, fd.expanded_size)
            fd.expanded_size = file_size
            fd.compressed_size = file_size
            fd.md5 = b""
        reader = InstallShieldExternalReader(fd, fp, file_size)
        if fd.flags & FILE_COMPRESSED and \
                file_size != fd.expanded_size and file_size != fd.compressed_size:
            # A compressed external whose loose size matches neither recorded
            # size is a different version of the file (e.g. a demo disc
            # carrying a vestigial retail manifest); if it then fails to
            # decode, the failure should say that instead of a chunk error
            reader.version_mismatch = (source, file_size)
        return reader

    def _external_file_index(self, restricted=True):
        if restricted in self._external_files:
            return self._external_files[restricted]
        by_name = {}
        by_size = {}
        self._external_files[restricted] = (by_name, by_size)
        prefix = self._dir.replace("\\", "/").lower() if restricted else ""
        try:
            root = self.parent_container.get_root_dir()
            for file in self.parent_container.iso_iterator(root, recursive=True):
                file_path = str(self.parent_container.get_file_path(file)).replace("\\", "/")
                if prefix and not file_path.lower().startswith(prefix + "/"):
                    continue
                try:
                    size = self.parent_container.get_file_size(file)
                except Exception:
                    continue
                basename = file_path.rsplit("/", 1)[-1].lower()
                by_name.setdefault(basename, []).append((file_path, size, file))
                by_size.setdefault(size, []).append((file_path, size, file))
        except Exception as e:
            LOGGER.warning("Could not index external files for %s: %s", self.path, e)
        return self._external_files[restricted]

    @staticmethod
    def _component_matches(cab_component, disk_component):
        """Does an on-disk path component match one recorded in the cabinet,
        allowing for 8.3 short-name mangling (Tutorial Files -> TUTORI~1,
        seq. bmp -> SEQ~1.BMP)"""
        cab_component = cab_component.lower()
        disk_component = disk_component.lower()
        if cab_component == disk_component:
            return True
        if "~" not in disk_component:
            return False

        def sanitize(part):
            return re.sub(r"[^a-z0-9_!#$%&'()@^`{}~-]", "", part)

        disk_base, _, disk_ext = disk_component.rpartition(".")
        if not disk_base:
            disk_base, disk_ext = disk_component, ""
        short_prefix = disk_base.split("~")[0]
        if not short_prefix:
            return False
        # The long name's last dot may have become the short extension
        # separator, or been stripped entirely
        cab_base, _, cab_ext = cab_component.rpartition(".")
        interpretations = [(sanitize(cab_component), "")]
        if cab_base:
            interpretations.append((sanitize(cab_base), sanitize(cab_ext)))
        return any(base.startswith(short_prefix) and disk_ext in (ext, ext[:3])
                   for base, ext in interpretations)

    def _directory_matches(self, directory, disk_parent):
        cab_parts = [part for part in directory.split("/") if part]
        if not cab_parts:
            return True
        disk_parts = [part for part in disk_parent.split("/") if part]
        if len(disk_parts) < len(cab_parts):
            return False
        return all(self._component_matches(cab_part, disk_part)
                   for cab_part, disk_part in zip(cab_parts, disk_parts[-len(cab_parts):]))

    def _find_external_file(self, fd, directory, name):
        directory = directory.replace("\\", "/").lower()
        # Media can also share files between installers outside the
        # cabinet's own directory (e.g. one DirectX redist for all of a
        # disc's demos); only widen the search when nothing closer matches
        for restricted in (True, False):
            found = self._match_external_file(fd, directory, name, restricted)
            if found:
                return found
            if not self._dir:
                break
        return None

    def _match_external_file(self, fd, directory, name, restricted):
        by_name, by_size = self._external_file_index(restricted)
        suffix = "/".join(part for part in directory.split("/") if part)
        matches = []
        for file_path, size, file in by_name.get(name.lower(), []):
            parent = file_path.rsplit("/", 1)[0].lower() if "/" in file_path else ""
            if suffix and not parent.endswith(suffix):
                continue
            matches.append((file_path, size, file))
        if len(matches) == 1:
            return matches[0]
        # Same name in several media directories (e.g. one per language):
        # the loose file's size matches the descriptor's expanded size
        sized = sorted((m for m in matches if m[1] == fd.expanded_size),
                       key=lambda m: m[0])
        if sized:
            if len(sized) > 1:
                LOGGER.debug("Multiple external candidates for %s, using %s",
                             name, sized[0][0])
            return sized[0]
        # The iso9660 view of a disc mangles long names (TUTORI~1), so look
        # for a mangling-aware match among same-sized files
        fuzzy = []
        for file_path, size, file in by_size.get(fd.expanded_size, []):
            parent, _, disk_name = file_path.lower().rpartition("/")
            if self._component_matches(name.lower(), disk_name) and \
                    self._directory_matches(directory, parent):
                fuzzy.append((file_path, size, file))
        if len(fuzzy) == 1:
            return fuzzy[0]
        if fuzzy:
            # Several equally-plausible short names (POSITI~1/~2/~3.C3D);
            # the file's timestamp disambiguates them. Sibling files can be
            # saved seconds apart, so an exact match beats a rounded one
            deltas = {m[0]: self._file_date_delta(fd, m[2]) for m in fuzzy}
            for tolerance in (0, 2):
                dated = sorted((m for m in fuzzy
                                if deltas[m[0]] is not None and deltas[m[0]] <= tolerance),
                               key=lambda m: m[0])
                if len(dated) == 1:
                    LOGGER.debug("Paired %s with %s by timestamp", name, dated[0][0])
                    return dated[0]
            LOGGER.debug("Ambiguous external candidates for %s: %s",
                         name, [m[0] for m in fuzzy])
        return None

    def _file_date_delta(self, fd, file):
        if not fd.dos_date:
            return None
        try:
            disk_date = self.parent_container.get_file_date(file)
            if not isinstance(disk_date, datetime.datetime):
                disk_date = datetime.datetime.fromtimestamp(file.stat().st_mtime)
            cab_date = datetime.datetime(*dos_date_time(fd.dos_date, fd.dos_time))
        except (ValueError, OSError, AttributeError):
            return None
        if not disk_date:
            return None
        # DOS timestamps have two-second resolution and no timezone, and the
        # filesystem's dates may be shifted by the authoring timezone;
        # timezones come in 15 minute steps
        delta = (disk_date.replace(tzinfo=None) - cab_date).total_seconds()
        return abs(delta - round(delta / 900) * 900)

    def new_style_blocks(self, fd, path, raw=None):
        if raw is None:
            raw = self._make_raw_reader(fd, path)
        if not fd.flags & FILE_COMPRESSED:
            bytes_left = fd.expanded_size
            while bytes_left > 0:
                data = raw.read(min(65536, bytes_left))
                bytes_left -= len(data)
                yield data
            return
        compressed_left = fd.compressed_size
        while compressed_left > 0:
            chunk_header = raw.read(2)
            chunk_size = chunk_header[0] | chunk_header[1] << 8
            if chunk_size == 0:
                raise InstallShieldError("Zero-length chunk (old-style cabinet?)")
            chunk = raw.read(chunk_size)
            compressed_left -= 2 + chunk_size
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            data = decompressor.decompress(chunk + b"\x00")
            if not decompressor.eof:
                raise zlib.error("Incomplete deflate stream in chunk")
            yield data

    @staticmethod
    def _old_style_chunk_size(buf, pos):
        match = buf.find(END_OF_CHUNK, pos)
        if match < 0:
            raise InstallShieldError("Could not find end of chunk")
        chunk_size = match - pos
        # The end of chunk marker can appear inside a chunk. The first bit
        # of a compressed block is always zero, so treat a set bit after
        # the marker as a false positive and keep looking
        while (pos + chunk_size + 4) < len(buf) and buf[pos + chunk_size + 4] & 1:
            chunk_size += 4
            match = buf.find(END_OF_CHUNK, pos + chunk_size)
            if match < 0:
                raise InstallShieldError("Could not find end of chunk")
            chunk_size = match - pos
        return chunk_size

    def old_style_blocks(self, fd, path):
        raw = self._make_raw_reader(fd, path)
        bytes_left = fd.expanded_size
        while bytes_left > 0:
            if raw.volume_bytes_left == 0:
                raw.open_volume(raw.volume + 1)
            if not fd.flags & FILE_COMPRESSED:
                data = raw.read(min(65536, bytes_left))
                bytes_left -= len(data)
                yield data
                continue
            buf = raw.read(raw.volume_bytes_left)
            pos = 0
            while pos < len(buf) and bytes_left > 0:
                chunk_size = self._old_style_chunk_size(buf, pos)
                decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                data = decompressor.decompress(buf[pos:pos + chunk_size])
                pos += chunk_size + 4
                bytes_left -= len(data)
                yield data
