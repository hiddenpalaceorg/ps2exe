import struct

from p3do.operafs.directory import Directory


class Root:
    SIZE = 48
    FMT = ">IIII32s"

    def __init__(self, fp, data):
        self.id, self.block_count, \
        self.block_size, last_copy_number, copy_ptrs =  struct.unpack(self.FMT, data)
        self.num_copies = last_copy_number + 1
        fmt = ">" + "I" * self.num_copies
        self.copy_locations = [
            extent * self.block_size for extent in
            struct.unpack(fmt, copy_ptrs[0:self.num_copies * 4])
        ]

        self.root_copies = []
        for copy_location in self.copy_locations:
            try:
                self.root_copies.append(Directory(fp, copy_location, None))
            except:
                if len(self.root_copies):
                    return
                raise