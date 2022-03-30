import logging
import mmap
import os

from utils.unscambler import unscramble_data

LOGGER = logging.getLogger(__name__)

class BaseFile:
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

    def length(self):
        return len(self)

    def peek(self, n):
        return self._get_data(n)

    def read(self, n):
        ret = self._get_data(n)
        self.pos += n
        return ret

    def _get_data(self, n):
        pos = self.tell()
        return self[pos:pos + n]

    def ranges(self):
        raise NotImplementedError

    def __getitem__(self, key):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError


class MmappedFile(BaseFile):
    def __init__(self, fp):
        self.post_read_func = None
        if isinstance(fp, mmap.mmap):
            self.mmap = fp
            self.name = None
        else:
            self.mmap = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            self.name = fp.name

    def ranges(self):
        yield 0, 0, len(self)

    def __getitem__(self, key):
        return self.mmap.__getitem__(key)

    def close(self):
        self.mmap.close()

    def __len__(self):
        return self.mmap.__len__()


class ConcatenatedFile(BaseFile):
    def __init__(self, fps, offsets):
        self.files = []
        self.lengths = []
        self.offsets = offsets[:]
        self.offsets.sort()
        self.pos = 0

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
                if start >= file_start:
                    if file_stop < stop:
                        rest = stop - file_stop
                        stop = file_stop

                    found = True
                    break

            if not found:
                raise ValueError("No chunk containing range")

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


class BinWrapper(BaseFile):
    def __init__(self, fp, sector_size = None, sector_offset = None):
        self.file = fp.name

        self.is_scrambled, data_offset = ScrambledFile.test_scrambled(fp)
        if self.is_scrambled:
            self.mmap = ScrambledFile(fp, data_offset)
        elif not isinstance(fp, MmappedFile):
            self.mmap = MmappedFile(fp)
        else:
            self.mmap = fp

        if not LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug = lambda x: x

        if sector_size is None or sector_offset is None:
            self.detect_sector_size()
        else:
            self.sector_size = sector_size
            self.sector_offset = sector_offset

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

    def tell(self):
        if self.sector_offset == 0:
            return self.mmap.tell()

        LOGGER.debug("tell")
        return self.pos

    def _read(self, pos, length):
        buffer = bytearray()

        while length > 0:
            sector = pos // 2048
            pos_in_sector = pos % 2048
            sector_read_length = min(length, 2048 - pos_in_sector)
            read_pos = sector * self.sector_size + self.sector_offset + pos % 2048

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
        return self.mmap.length() // self.sector_size * 2048

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
            return

        # Gamecube disc
        self.mmap.seek(0x1C)
        ident = self.mmap.read(4)
        if ident == b"\xC2\x33\x9F\x3D":
            self.sector_size = 2048
            self.sector_offset = 0
            return

        # early Gamecube demo disc
        self.mmap.seek(0)
        ident = self.mmap.read(64)
        if ident == b"\x30\x30\x00\x45\x30\x31" + b"\x00" * 26 + \
                    b"\x4E\x44\x44\x45\x4D\x4F" + b"\x00" * 26:
            self.sector_size = 2048
            self.sector_offset = 0
            return

        # Wii disc
        self.mmap.seek(0x18)
        ident = self.mmap.read(4)
        if ident == b"\x5D\x1C\x9E\xA3":
            self.sector_size = 2048
            self.sector_offset = 0
            return

        # ISO9660 or CD-I discs
        self.mmap.seek(0x8001)
        ident = self.mmap.read(5)
        LOGGER.debug(ident)
        if ident in [b"CD001", b"CD-I ", b"BEA01"]:
            self.sector_size = 2048
            self.sector_offset = 0
            return

        self.mmap.seek(0x9311)
        ident = self.mmap.read(5)
        LOGGER.debug(ident)
        if ident in [b"CD001", b"CD-I ", b"BEA01"]:
            self.sector_size = 2352
            self.sector_offset = 16
            return

        self.mmap.seek(0x9319)
        ident = self.mmap.read(5)
        LOGGER.debug(ident)
        if ident in [b"CD001", b"CD-I ", b"BEA01"]:
            self.sector_size = 2352
            self.sector_offset = 24
            return

        # Xbox (360) discs
        self.mmap.seek(0x10000)
        ident = self.mmap.read(20)
        if ident == b"MICROSOFT*XBOX*MEDIA":
            self.sector_size = 2048
            self.sector_offset = 0
            return

        raise BinWrapperException("Cannot detect sector size, is this a disc image?")


class ScrambledFile(MmappedFile):
    def __init__(self, fp, offset):
        self.offset = offset
        super().__init__(fp)

    def seek(self, pos, whence=os.SEEK_SET):
        return super().seek(pos+self.offset, whence)

    def tell(self):
        return super().tell() - self.offset

    def peek(self, n=-1):
        actual_pos = super().tell()
        return unscramble_data(super().peek(n), actual_pos)

    def read(self, n=-1):
        return super().read(n)

    def __getitem__(self, item):
        if isinstance(item, slice):
            actual_pos = item.start
            item = slice(item.start+self.offset, item.stop+self.offset)
        else:
            actual_pos = item
            item += self.offset
        return unscramble_data(super().__getitem__(item), actual_pos)

    @staticmethod
    def test_scrambled(fp):
        # Some dumps are offset by 128 bytes and contain scrambled data afterwards
        fp.seek(128)
        data = fp.read(12)
        if data == b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00":
            return (True, 128)

        # Check for discs that are scrambled but not offset.
        fp.seek(0x9319)
        ident = bytes(bytearray(v ^ [0x02, 0xFE, 0x81, 0x80, 0x60][k] for k, v in enumerate(fp.read(5))))
        if ident in [b"CD001", b"CD-I ", b"BEA01"]:
            return (True, 0)

        return False, None