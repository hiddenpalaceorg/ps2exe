from bin_wrapper import BinWrapper


class ChainedSubImgReader(BinWrapper):
    def __init__(self, fps):
        self.fps = fps
        self.fp_sizes = {}
        current_size = 0
        for fp in self.fps:
            with fp:
                current_size += fp.length()
                self.fp_sizes[current_size] = fp
        self.fp = fps[0]
        self.detect_sector_size()

    def close(self):
        [fp.close() for fp in self.fps]

    def tell(self):
        return self.pos

    def peek(self, n=-1):
        cur_pos = self.fp.tell()
        original_pos = self.pos
        buffer = self.read(n)
        self.fp.seek(cur_pos)
        self.pos = original_pos

        return buffer

    def read(self, n=-1):
        length = n
        buffer = bytearray()

        while length > 0:
            sector = self.pos // 2048
            pos_in_sector = self.pos % 2048
            sector_read_length = min(length, 2048 - pos_in_sector)
            pos = sector * self.sector_size + self.sector_offset + self.pos % 2048
            pos_in_fp = pos

            for fp_size, fp in self.fp_sizes.items():
                if fp_size >= pos:
                    break
                pos_in_fp -= fp_size

            fp.seek(pos_in_fp)
            buffer.extend(fp.read(sector_read_length))

            self.pos += sector_read_length
            length -= sector_read_length

        # LOGGER.debug()(buffer)
        return bytes(buffer)

    def length(self):
        return sum(self.fp_sizes) // self.sector_size * 2048