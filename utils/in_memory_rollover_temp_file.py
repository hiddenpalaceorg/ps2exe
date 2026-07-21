import logging
import mmap
import tempfile

import psutil

from utils.files import BaseFile, OffsetFile

LOGGER = logging.getLogger(__name__)


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
            except (OSError, SystemError):
                return
            try:
                self.mmap.resize(size)
                self.mmap_size = size
            except (OSError, SystemError):
                return


class DecompressedFile(OffsetFile):
    """
    Eagerly decompresses a stream (GzipFile/BZ2File/LZMAFile) into an
    InMemoryRolloverTempFile so consumers can seek freely without
    re-decompressing from the start on every backwards seek.
    """
    CHUNK_SIZE = 4 * 1024 * 1024

    def __init__(self, fp):
        buffer = InMemoryRolloverTempFile.with_memory_budget()
        LOGGER.debug("Decompressing %s to a rollover temp file", getattr(fp, "name", "stream"))
        fp.seek(0)
        size = 0
        while chunk := fp.read(self.CHUNK_SIZE):
            buffer.write(chunk)
            size += len(chunk)
        buffer.finalize(size)
        buffer.name = getattr(fp, "name", "")
        super().__init__(buffer, 0, size, buffer.name)

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = 0 if item.start is None else item.start
            stop = self.length() if item.stop is None else item.stop
            return super().__getitem__(slice(start, stop, item.step))
        return super().__getitem__(item)[0]

    def close(self):
        self.mmap.close()
