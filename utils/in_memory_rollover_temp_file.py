import mmap
import tempfile

import psutil

from utils.files import BaseFile


class InMemoryRolloverTempFile(BaseFile):
    """
    In-memory mmap that rolls-over into a temporary file if too large
    """
    def __init__(self, max_size=0):
        self.pos = 0
        self.mmap = None
        self.mmap_size = 0
        if max_size:
            self.mmap = mmap.mmap(-1, max_size, access=mmap.ACCESS_WRITE)
            self.mmap_size = len(self.mmap)
        self.temp_file = None

    def __len__(self):
        # mark the temp file to 80% of free space
        return int(psutil.disk_usage(tempfile.gettempdir()).free * .8) + self.mmap_size

    def _get_data(self, n=None, discard=False):
        data = b""
        mmap_pos = min(self.mmap_size, self.tell())
        if not n:
            n = len(self) - self.tell()
        mmap_read = min(n, self.mmap_size - mmap_pos)
        if mmap_read:
            self.mmap.seek(mmap_pos)
            data += self.mmap.read(mmap_read)
            n -= mmap_read
        if n:
            if not self.temp_file:
                self.temp_file = tempfile.NamedTemporaryFile("r+b")
            tempfile_pos = self.pos + mmap_read - self.mmap_size
            self.temp_file.seek(tempfile_pos)
            data += self.temp_file.read(n)
        return data

    def write(self, data):
        n = len(data)
        mmap_pos = min(self.mmap_size, self.tell())
        mmap_write = min(n, self.mmap_size - mmap_pos)
        if mmap_write:
            self.mmap.seek(mmap_pos)
            self.mmap.write(data[:mmap_write])
            self.pos += mmap_write
        if len(data) > mmap_write:
            if not self.temp_file:
                self.temp_file = tempfile.NamedTemporaryFile("r+b")
            tempfile_pos = self.tell() - self.mmap_size
            self.temp_file.seek(tempfile_pos)
            self.temp_file.write(data[mmap_write:])
            self.pos += len(data) - mmap_write

    def __getitem__(self, item):
        if isinstance(item, slice):
            read_pos = item.start
            read_len = item.stop - item.start
        else:
            read_pos = item
            read_len = 1
        self.seek(read_pos)
        return self._get_data(read_len)

    def close(self):
        try:
            if self.mmap:
                self.mmap.close()
        except ValueError:
            pass
        if self.temp_file:
            self.temp_file.close()

    def finalize(self, size):
        if size < self.mmap_size:
            # Test if we can resize an mmap on this OS first
            try:
                m = mmap.mmap(-1, 2, access=mmap.ACCESS_WRITE)
                m.resize(1)
                m.close()
            except OSError:
                return
            try:
                self.mmap.resize(size)
                self.mmap_size = size
            except OSError:
                return
