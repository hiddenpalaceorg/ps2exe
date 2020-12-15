import os
import logging
import re

LOGGER = logging.getLogger(__name__)

class BinWrapperException(Exception):
    pass

class BinWrapper:
    def __init__(self, fp):
        self.fp = fp
        self.pos = 0
        self.repair_padding = False

        self.detect_sector_size()
        LOGGER.debug(f"{self.sector_size=} {self.sector_offset=}")

    def seek(self, pos, whence=os.SEEK_SET):
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
        LOGGER.debug("tell")
        return self.pos

    def read(self, n=-1):
        length = n
        LOGGER.debug(f"read {length}")
        buffer = []

        while length > 0:
            sector = self.pos // 2048
            pos_in_sector = self.pos % 2048
            sector_read_length = min(length, 2048 - pos_in_sector)

            LOGGER.debug(f"{self.pos=} {sector=} {pos_in_sector=} {sector_read_length=}")
            self.fp.seek(sector * self.sector_size + self.sector_offset + self.pos % 2048)
            buffer.append(self.fp.read(sector_read_length))

            self.pos += sector_read_length
            length -= sector_read_length

        # LOGGER.debug()(buffer)
        buffer = b"".join(buffer)
        if not self.repair_padding:
            return buffer

        # Fool pycdlib to think that the end of a sector is zero-padded
        # even if mastering caused garbage data to be written to the padding section
        lenbyte = bytearray([buffer[0]])[0]
        # Detect if this sector is a directory record
        orig_buffer = buffer
        if lenbyte > 1 and buffer[32:33] == b"\x01":
            offset = 0
            while offset < n:
                lenbyte = bytearray([buffer[offset]])[0]
                # if the directory record is less than 30 bytes (it can't be that small),
                # then it's probably garbage padding. Fill the rest of this sector with zeroes
                if lenbyte < 30:
                    padsize = sector_read_length - (offset % sector_read_length)
                    buffer = buffer[:offset] + b'\x00' * padsize + buffer[offset+padsize:]

                    offset = offset + padsize
                else:
                    file_length = bytearray([buffer[offset+32]])[0]
                    file_name = buffer[offset+33:offset+33+file_length]
                    file_flags = buffer[offset+26]
                    is_dir = file_flags & 2
                    month = buffer[offset + 19]
                    day = buffer[offset + 20]
                    hour = buffer[offset + 21]
                    minute = buffer[offset + 22]
                    second = buffer[offset + 23]
                    # Garbage data detected in this sector (the filename field
                    # is not actually a file), zero pad it
                    is_valid_file = (month <= 12 and
                                     day <= 31 and
                                     hour <= 23 and
                                     minute <= 59 and
                                     second <= 59) and \
                                    (file_name not in [b"\x00", b"\x01"] or (not is_dir and file_name[-2:-1] != b";"))
                    if not is_valid_file:
                        padsize = sector_read_length - (offset % sector_read_length)
                        buffer = buffer[:offset] + b'\x00' * padsize + buffer[offset + padsize:]

                        offset = offset + padsize
                        continue
                    offset += lenbyte
        return buffer

    def length(self):
        self.fp.seek(0, os.SEEK_END)
        return self.fp.tell() // self.sector_size * 2048

    def detect_sector_size(self):
        self.fp.seek(0x8001)
        ident = self.fp.read(5)
        LOGGER.debug(ident)
        if ident == b"CD001":
            self.sector_size = 2048
            self.sector_offset = 0
            return
        
        self.fp.seek(0x9311)
        ident = self.fp.read(5)
        LOGGER.debug(ident)
        if ident == b"CD001":
            self.sector_size = 2352
            self.sector_offset = 16
            return

        self.fp.seek(0x9319)
        ident = self.fp.read(5)
        LOGGER.debug(ident)
        if ident == b"CD001":
            self.sector_size = 2352
            self.sector_offset = 24
            return

        raise BinWrapperException("Cannot detect sector size, is this a disc image?")
