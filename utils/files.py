import io
import logging
import math
import mmap
import os
from io import UnsupportedOperation

from utils.common import MSF
from utils.mmap import FakeMemoryMap
from utils.unscambler import unscramble_data, lookup_table

LOGGER = logging.getLogger(__name__)


class BaseFile:
    def __init__(self):
        self.pos = 0

    def seekable(self):
        return True

    def seek(self, pos, whence=os.SEEK_SET):
        LOGGER.debug(f"seek {pos} {whence}")
        if whence == os.SEEK_SET:
            self.pos = pos
        elif whence == os.SEEK_CUR:
            self.pos += pos
        elif whence == os.SEEK_END:
            self.pos = len(self) + pos

    def tell(self):
        return self.pos

    def peek(self, n):
        if n is None or n < 0:
            n = self.length() - self.pos
        return self._get_data(n)

    def readinto(self, b):
        readsize = self.length() - self.tell()
        if readsize > 0:
            mv = memoryview(b)
            m = mv.cast('B')
            readsize = min(readsize, len(m))
            data = self.read(readsize)
            n = len(data)
            m[:n] = data
        else:
            n = 0

        return n

    def read(self, n=None):
        if n is None or n < 0:
            n = self.length() - self.pos
        if n + self.pos > self.length():
            n = self.length() - self.pos
        ret = self._get_data(n)
        self.pos += len(ret)
        return ret

    def close(self):
        raise NotImplementedError

    def length(self):
        return len(self)

    def _get_data(self, n):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError


class AccessBySliceFile(BaseFile):
    def _get_data(self, n, discard=False):
        pos = self.tell()
        return self[pos:pos + n]

    def __enter__(self):
        self.pos = 0
        return self

    def __exit__(self, *args):
        return

    def __getitem__(self, key):
        raise NotImplementedError


class MmapWrapper(AccessBySliceFile, BaseFile):
    def __init__(self, mmap):
        super().__init__()
        self.mmap = mmap
        self.name = getattr(self.mmap, "name", None)

    def __len__(self):
        return len(self.mmap)

    def close(self):
        self.mmap.close()


class MmappedFile(MmapWrapper):
    def __init__(self, fp):
        if isinstance(fp, (mmap.mmap, FakeMemoryMap)):
            self.mmap = fp
            self.name = None
        else:
            try:
                self.mmap = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            except (AttributeError, UnsupportedOperation):
                self.mmap = FakeMemoryMap(fp)
            self.name = getattr(fp, "name", "")

    def __getattr__(self, item):
        return getattr(self.mmap, item)

    def __getitem__(self, key):
        return self.mmap.__getitem__(key)

    def close(self):
        self.mmap.close()

    def length(self):
        return len(self.mmap)

    def __len__(self):
        return self.mmap.__len__()


class ConcatenatedFile(AccessBySliceFile):
    def __init__(self, fps, offsets):
        super().__init__()
        self.files = []
        self.lengths = []
        self.offsets = offsets[:]
        self.offsets.sort()
        self.pos = 0
        self.name = fps[0].name
        self.starting_sector = 0

        for fp in fps:
            if not isinstance(fp, BaseFile):
                file = MmappedFile(fp)
            else:
                file = fp
            self.files.append(file)
            self.lengths.append(len(file))

    def close(self):
        [fp.close() for fp in self.files]

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.start, key.stop, key.step
            if start is None:
                start = 0

            if stop is None:
                stop = self.offsets[-1] + self.lengths[-1]

            # Find start
            found = False
            file_start = file_stop = None
            rest = 0
            file = 0

            for file, file_start, file_stop in reversed(list(self.ranges())):
                if file_stop >= start >= file_start:
                    if file_stop < stop:
                        rest = stop - file_stop
                        stop = file_stop

                    found = True
                    break

            if not found:
                return b""

            start = start - file_start
            stop = stop - file_start
            ret = self.files[file][start:stop:step]
            if rest:
                ret += self.files[file+1][0:rest]
            return ret

    def ranges(self):
        for i in range(len(self.files)):
            yield i, self.offsets[i], self.offsets[i]+self.lengths[i]

    def __len__(self):
        return self.offsets[-1] + self.lengths[-1]


class BinWrapperException(Exception):
    pass


class BinWrapper(AccessBySliceFile):
    def __init__(self, fp, sector_size=None, sector_offset=None, virtual_sector_size=None):
        super().__init__()
        self.file = self.name = getattr(fp, "name", "")

        if not isinstance(fp, MmapWrapper):
            self.mmap = MmappedFile(fp)
        else:
            self.mmap = fp

        self.is_scrambled, data_offset = ScrambledFile.test_scrambled(fp)
        if self.is_scrambled:
            self.mmap = ScrambledFile(self.mmap, data_offset)

        if not LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug = lambda x: x

        self.virtual_sector_size = None
        if sector_size is None or sector_offset is None:
            self.detect_sector_size()
        else:
            self.sector_size = sector_size
            self.sector_offset = sector_offset
            self.virtual_sector_size = virtual_sector_size

        if self.virtual_sector_size is None:
            self.virtual_sector_size = self.sector_size - self.sector_offset

        self.starting_sector = self.virtual_offset = 0
        if self.sector_size == 2352:
            self.starting_sector = self.get_first_sector()
            self.virtual_offset = self.starting_sector * self.virtual_sector_size

        LOGGER.debug(f"{self.sector_size=} {self.sector_offset=}")

    def close(self):
        self.mmap.close()

    def seek(self, pos, whence=os.SEEK_SET):
        if self.sector_offset == 0:
            return self.mmap.seek(pos, whence)

        return self._set_pos(pos, whence)

    def _set_pos(self, pos, whence=os.SEEK_SET):
        LOGGER.debug(f"seek {pos} {whence}")
        if whence == os.SEEK_SET:
            self.pos = pos
        elif whence == os.SEEK_CUR:
            self.pos += pos
        elif whence == os.SEEK_END:
            self.pos = self.length() + pos
        else:
            raise BinWrapperException("Unsupported")
        if self.pos < self.virtual_offset:
            self.pos += self.virtual_offset

    def tell(self):
        if self.sector_offset == 0:
            return self.mmap.tell()

        LOGGER.debug("tell")
        return self.pos

    def _read(self, pos, length):
        buffer = bytearray()

        while length > 0:
            sector = pos // self.virtual_sector_size
            if sector >= self.starting_sector:
                sector -= self.starting_sector
            pos_in_sector = pos % self.virtual_sector_size
            sector_read_length = min(length, self.virtual_sector_size - pos_in_sector)
            read_pos = sector * self.sector_size + self.sector_offset + pos % self.virtual_sector_size

            LOGGER.debug(f"{pos=} {sector=} {pos_in_sector=} {sector_read_length=}")

            buffer.extend(self.mmap[read_pos:read_pos + sector_read_length])

            pos += sector_read_length
            length -= sector_read_length

        # LOGGER.debug()(buffer)
        return bytes(buffer), pos

    def peek(self, n=-1):
        if self.sector_offset == 0:
            return self.mmap.peek(n)

        buffer, _ = self._read(self.pos, n)

        # if the directory record is less than 30 bytes (it can't be that small),
        # then it's probably garbage padding. Fill the rest of this sector with zeroes
        lenbyte = bytearray([buffer[0]])[0]
        if n == 1 and lenbyte and lenbyte < 30:
            return b'\x00'

        return buffer

    def read(self, n=-1):
        if self.sector_offset == 0:
            return self.mmap.read(n)

        length = n
        LOGGER.debug(f"read {length}")

        ret, self.pos = self._read(self.pos, length)
        return ret

    def length(self):
        len = self.mmap.length() // self.sector_size * self.virtual_sector_size
        if self.mmap.length() % self.sector_size:
            return len + (self.mmap.length() - len)
        return len

    def __getitem__(self, item):
        if isinstance(item, slice):
            pos = item.start
            length = item.stop - item.start
        else:
            pos = item
            length = 1

        return self._read(pos, length)[0]

    def __len__(self):
        return self.length()

    def detect_sector_size(self):
        # 3DO discs
        self.mmap.seek(0)
        ident = self.mmap.read(7)
        if ident == b"\x01\x5A\x5A\x5A\x5A\x5A\x01":
            self.sector_size = 2048
            self.sector_offset = 0
            return

        self.mmap.seek(0x10)
        ident = self.mmap.read(7)
        if ident == b"\x01\x5A\x5A\x5A\x5A\x5A\x01":
            self.sector_size = 2352
            self.sector_offset = 16
            self.virtual_sector_size = 2048
            return

        # Apple formatted disc
        self.mmap.seek(0x430)
        ident = self.mmap.read(9)
        if ident == b"Apple_HFS":
            self.sector_size = 2048
            self.sector_offset = 0
            return

        self.mmap.seek(0x440)
        ident = self.mmap.read(9)
        if ident == b"Apple_HFS":
            self.sector_size = 2352
            self.sector_offset = 16
            self.virtual_sector_size = 2048
            return

        self.mmap.seek(0x630)
        ident = self.mmap.read(9)
        if ident == b"Apple_HFS":
            self.sector_size = 2352
            self.sector_offset = 16
            self.virtual_sector_size = 2048
            return

        self.mmap.seek(0x640)
        ident = self.mmap.read(9)
        if ident == b"Apple_HFS":
            self.sector_size = 2352
            self.sector_offset = 16
            self.virtual_sector_size = 2048
            return

        # ISO9660 or CD-I discs
        for magic_offset, magics in [(0, [b"CD001", b"CD-I ", b"BEA01"]), (8, [b'CDROM'])]:
            self.mmap.seek(0x8001 + magic_offset)
            ident = self.mmap.read(5)
            LOGGER.debug(ident)
            if ident in magics:
                self.sector_size = 2048
                self.sector_offset = 0
                return

            self.mmap.seek(0x9311 + magic_offset)
            ident = self.mmap.read(5)
            LOGGER.debug(ident)
            if ident in magics:
                self.sector_size = 2352
                self.sector_offset = 16
                self.virtual_sector_size = 2048
                return

            self.mmap.seek(0x9319 + magic_offset)
            ident = self.mmap.read(5)
            LOGGER.debug(ident)
            if ident in magics:
                self.sector_size = 2352
                self.sector_offset = 24
                self.virtual_sector_size = 2048
                return

            self.mmap.seek(0x9801 + magic_offset)
            ident = self.mmap.read(5)
            LOGGER.debug(ident)
            if ident in magics:
                self.sector_size = 2048
                self.sector_offset = 0
                self.mmap = OffsetFile(self.mmap, 0x9801 - 0x8001, self.mmap.length())

                return

            self.mmap.seek(0x9c41 + magic_offset)
            ident = self.mmap.read(5)
            LOGGER.debug(ident)
            if ident in magics:
                self.sector_size = 2352
                self.sector_offset = 16
                self.virtual_sector_size = 2048
                return

        raise BinWrapperException("Cannot detect sector size, is this a disc image?")

    def get_first_sector(self):
        sector_header = b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00"
        self.mmap.seek(0)
        data = self.mmap.read(12)
        if data != sector_header:
            LOGGER.warning("Could not determine starting LBA for file")
            return 0
        msf_raw = self.mmap.read(3)
        msf = MSF(msf_raw)
        return msf.to_sector()


class ScrambledFile(MmapWrapper):
    def __init__(self, mmap, offset):
        self.offset = offset
        super().__init__(mmap)

    def seek(self, pos, whence=os.SEEK_SET):
        return super().seek(pos+self.offset, whence)

    def tell(self):
        return super().tell() - self.offset

    def __getitem__(self, item):
        if isinstance(item, slice):
            actual_pos = item.start
            item = slice(item.start+self.offset, item.stop+self.offset)
        else:
            actual_pos = item
            item += self.offset
        return unscramble_data(self.mmap.__getitem__(item), actual_pos)

    def length(self):
        return super().length() - self.offset

    @staticmethod
    def test_scrambled(fp):
        sector_header = b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00"
        # Some dumps are offset by 128 bytes and contain scrambled data afterwards
        fp.seek(128)
        data = fp.read(12)
        if data == sector_header:
            return (True, 128)

        # Check for redumper-style scram files that include
        # leadin and are not corrected for disc write offset
        fp.seek(45150 * 2352)
        data = fp.read(2352)
        if sector_header in data:
            header_pos = data.find(sector_header)
            fp.seek(45150 * 2352 + header_pos)
            header = fp.read(16)
            header_unscrambled = bytes(bytearray(v ^ lookup_table[k] for k, v in enumerate(header)))
            msf_raw = header_unscrambled[12:15]
            msf = MSF(msf_raw)
            sector = msf.to_sector()
            if -10 < msf.to_sector() < 10:
                offset = (45150 * 2352) - (sector * 2352 - header_pos)
                return (True, offset)

        # Check for discs that are scrambled but not offset.
        for offset in [0x9311, 0x9319, 0x9c41]:
            lookup_table_start = offset % 2352
            unscramble_seed = lookup_table[lookup_table_start:lookup_table_start+5]
            fp.seek(offset)
            ident = bytes(bytearray(v ^ unscramble_seed[k] for k, v in enumerate(fp.read(5))))
            if ident in [b"CD001", b"CD-I ", b"BEA01"]:
                return (True, 0)

        return False, None


class OffsetFile(MmapWrapper):
    def __init__(self, mmap, offset, end_pos, file_name=None):
        super().__init__(mmap)
        self.offset = offset
        self.end_pos = end_pos
        self.mmap = mmap
        self.name = file_name or self.mmap.name

    def seek(self, pos, whence=os.SEEK_SET):
        if whence == os.SEEK_CUR:
            pos = self.pos - self.offset + pos
        elif whence == os.SEEK_END:
            pos = len(self) + pos
        if pos >= self.length():
            pos = self.length()
        return super().seek(pos+self.offset, os.SEEK_SET)

    def tell(self):
        return super().tell() - self.offset

    def read(self, n=None):
        if n:
            ret = self[self.tell():self.tell()+n]
        else:
            ret = self[self.tell():self.end_pos-self.offset]

        self.pos += len(ret)
        return ret

    def __getitem__(self, item):
        if isinstance(item, slice):
            read_pos = item.start
            read_len = item.stop - item.start
        else:
            read_pos = item
            read_len = 1
        self.seek(read_pos)
        file_pos = super().tell()
        if file_pos + read_len > self.end_pos:
            read_len = self.end_pos - file_pos
        if self.tell() == self.length():
            return b''
        return self.mmap[file_pos:file_pos+read_len]

    def write(self, data):
        try:
            self.mmap.seek(self.pos)
            ret = self.mmap.write(data)
            self.pos += len(data)
            return ret
        except ValueError:
            raise

    def length(self):
        return self.end_pos - self.offset

    def __len__(self):
        return self.length()

    def close(self):
        pass


def get_file_size(file):
    try:
        file.fileno()
        return os.stat(file.name).st_size
    except (AttributeError, UnsupportedOperation):
        from utils.archives import ArchiveEntryReader, ArchiveEntryWrapper

        if isinstance(file, ArchiveEntryReader):
            return file.entry.file_size

        if isinstance(file, ArchiveEntryWrapper):
            return file.file_size

        pos = file.tell()
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(pos)
        return size


def iterate_patterns(fp, pattern, chunk_size=0):
    if chunk_size < len(pattern):
        chunk_size = len(pattern)

    initial_position = fp.tell()

    compensation = len(pattern) - 1
    try:
        while True:
            current_position = fp.tell()

            # Prepend the padding from the last chunk, to make sure that we find the pattern,
            # even if it straddles the chunk boundary.
            data = fp.read(chunk_size)
            if data == b"":
                # We've reached the end of the stream.
                return

            if len(data) < len(pattern):
                # The length that we read from the file is the same
                # length or less than as the pattern we're looking
                # for, and we didn't find the pattern in there.
                return

            marker = data.find(pattern)
            while marker != -1:
                found_pos = current_position + marker
                # Reset the file pointer so that calling code cannot
                # depend on the side effect of this iterator advancing
                # it.
                fp.seek(initial_position)
                yield found_pos
                # We want to seek past the found position to the next byte,
                # so we can call find_first again without extra seek
                # This might seek past the actual end of the file
                fp.seek(found_pos + len(pattern))
                marker = data.find(pattern, marker + len(pattern))

            fp.seek(-compensation, os.SEEK_CUR)
    finally:
        fp.seek(initial_position)
