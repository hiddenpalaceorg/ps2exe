import os

print2 = print
print = lambda x: x

class BinWrapperException(Exception):
    pass

class BinWrapper:
    def __init__(self, fp):
        self.fp = fp
        self.pos = 0

        self.detect_sector_size()
        print(f"{self.sector_size=} {self.sector_offset=}")

    def seek(self, pos, whence=os.SEEK_SET):
        print(f"seek {pos} {whence}")
        if whence == os.SEEK_SET:
            self.pos = pos
        elif whence == os.SEEK_CUR:
            self.pos += pos
        elif whence == os.SEEK_END:
            self.pos = self.length() + pos
        else:
            raise BinWrapperException("Unsupported")

    def tell(self):
        print("tell")
        return self.pos

    def read(self, length):
        print(f"read {length}")
        buffer = []

        while length > 0:
            sector = self.pos // 2048
            pos_in_sector = self.pos % 2048
            sector_read_length = min(length, 2048 - pos_in_sector)

            print(f"{self.pos=} {sector=} {pos_in_sector=} {sector_read_length=}")
            self.fp.seek(sector * self.sector_size + self.sector_offset + self.pos % 2048)
            buffer.append(self.fp.read(sector_read_length))

            self.pos += sector_read_length
            length -= sector_read_length

        # print(buffer)
        return b"".join(buffer)

    def length(self):
        self.fp.seek(0, os.SEEK_END)
        return self.fp.tell() // self.sector_size * 2048

    def detect_sector_size(self):
        self.fp.seek(0x8001)
        ident = self.fp.read(5)
        print(ident)
        if ident == b"CD001":
            self.sector_size = 2048
            self.sector_offset = 0
            return
        
        self.fp.seek(0x9311)
        ident = self.fp.read(5)
        print(ident)
        if ident == b"CD001":
            self.sector_size = 2352
            self.sector_offset = 16
            return

        self.fp.seek(0x9319)
        ident = self.fp.read(5)
        print(ident)
        if ident == b"CD001":
            self.sector_size = 2352
            self.sector_offset = 24
            return

        raise BinWrapperException("Cannot detect sector size, is this a disc image?")
