import os
import logging
import mmap

from scrambled_wrapper import ScrambleWrapper

LOGGER = logging.getLogger(__name__)

class BinWrapperException(Exception):
    pass

class BinWrapper:
    def __init__(self, fp):
        self.fp = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        self.file = fp.name
        self.pos = 0
        self.repair_padding = False

        if self.is_scrambled():
            self.fp = ScrambleWrapper(self.fp, offset=128)

        if not LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug = lambda x: x


        self.detect_sector_size()
        LOGGER.debug(f"{self.sector_size=} {self.sector_offset=}")

    def close(self):
        self.fp.close()

    def seek(self, pos, whence=os.SEEK_SET):
        if self.sector_offset == 0:
            return self.fp.seek(pos, whence)

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
            return self.fp.tell()

        LOGGER.debug("tell")
        return self.pos

    def peek(self, n=-1):
        if self.sector_offset == 0:
            return self.fp[self.fp.tell():self.fp.tell()+n]

        cur_pos = self.fp.tell()
        original_pos = self.pos
        buffer = self.read(n)
        self.fp.seek(cur_pos)
        self.pos = original_pos

        # if the directory record is less than 30 bytes (it can't be that small),
        # then it's probably garbage padding. Fill the rest of this sector with zeroes
        lenbyte = bytearray([buffer[0]])[0]
        if n == 1 and lenbyte and lenbyte < 30:
            return b'\x00'

        return buffer

    def read(self, n=-1):
        if self.sector_offset == 0:
            return self.fp.read(n)
        length = n
        LOGGER.debug(f"read {length}")
        buffer = bytearray()

        while length > 0:
            sector = self.pos // 2048
            pos_in_sector = self.pos % 2048
            sector_read_length = min(length, 2048 - pos_in_sector)
            pos = sector * self.sector_size + self.sector_offset + self.pos % 2048

            LOGGER.debug(f"{self.pos=} {sector=} {pos_in_sector=} {sector_read_length=}")

            buffer.extend(self.fp[pos:pos+sector_read_length])

            self.pos += sector_read_length
            length -= sector_read_length

        # LOGGER.debug()(buffer)
        return bytes(buffer)

    def length(self):
        self.fp.seek(0, os.SEEK_END)
        return self.fp.tell() // self.sector_size * 2048

    def is_scrambled(self):
        self.fp.seek(128)
        data = self.fp.read(12)
        return data == b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00"

    def detect_sector_size(self):
        self.fp.seek(0)
        ident = self.fp.read(7)
        if ident == b"\x01\x5A\x5A\x5A\x5A\x5A\x01":
            self.sector_size = 2048
            self.sector_offset = 0
            return

        self.fp.seek(0x10)
        ident = self.fp.read(7)
        if ident == b"\x01\x5A\x5A\x5A\x5A\x5A\x01":
            self.sector_size = 2352
            self.sector_offset = 16
            return

        self.fp.seek(0x8001)
        ident = self.fp.read(5)
        LOGGER.debug(ident)
        if ident == b"CD001" or ident == b"CD-I ":
            self.sector_size = 2048
            self.sector_offset = 0
            return
        
        self.fp.seek(0x9311)
        ident = self.fp.read(5)
        LOGGER.debug(ident)
        if ident == b"CD001" or ident == b"CD-I ":
            self.sector_size = 2352
            self.sector_offset = 16
            return

        self.fp.seek(0x9319)
        ident = self.fp.read(5)
        LOGGER.debug(ident)
        if ident == b"CD001" or ident == b"CD-I ":
            self.sector_size = 2352
            self.sector_offset = 24
            return
        elif bytes(bytearray(v ^ [0x02,0xFE,0x81,0x80,0x60][k] for k,v in enumerate(ident))) == b"CD-I ":
            self.sector_size = 2352
            self.sector_offset = 24
            self.fp = ScrambleWrapper(self.fp, offset=0)
            return

        self.fp.seek(0x10000)
        ident = self.fp.read(20)
        if ident == b"MICROSOFT*XBOX*MEDIA":
            self.sector_size = 2048
            self.sector_offset = 0
            return

        raise BinWrapperException("Cannot detect sector size, is this a disc image?")
