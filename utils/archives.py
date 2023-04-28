import io
import mmap
import os
import sys
import tempfile

import psutil
import rarfile

from utils.files import MmappedFile
from utils.mmap import FakeMemoryMap

try:
    import libarchive
except TypeError:
    libarchive_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib", "libarchive")
    if os.name == "nt":
        if sys.maxsize > 2**32:
            libarchive_path = os.path.join(libarchive_path, "win64", "libarchive.dll")
        else:
            libarchive_path = os.path.join(libarchive_path, "win32", "libarchive.dll")
    elif sys.platform == "linux":
        libarchive_path = os.path.join(libarchive_path, "linux", "libarchive.so")
    elif sys.platform == "darwin":
        libarchive_path = os.path.join(libarchive_path, "macosx", "libarchive.dylib")

    os.environ["LIBARCHIVE"] = libarchive_path
    import libarchive
from libarchive import ArchiveEntry

try:
    rarfile.tool_setup(unrar=True, unar=False, bsdtar=False)
except rarfile.RarCannotExec:
    unrar_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib", "unrar")
    if os.name == "nt":
        if sys.maxsize > 2**32:
            rarfile.UNRAR_TOOL = os.path.join(unrar_path, "win64", "UnRAR.exe")
        else:
            rarfile.UNRAR_TOOL = os.path.join(unrar_path, "win32", "UnRAR.exe")
    elif sys.platform == "linux":
        rarfile.UNRAR_TOOL = os.path.join(unrar_path, "linux", "unrar")

    rarfile.tool_setup(unrar=True, unar=False, bsdtar=False)


class ArchiveWarapper:
    def __init__(self, path, pbar=None):
        self.path = path
        self.reader = None
        self.pbar = pbar
        file_ext = os.path.splitext(path)[1]
        if file_ext.lower() == ".rar":
            self.ctx = rarfile.RarFile(path)
        else:
            try:
                block_size = os.stat(path).st_blksize
            except (OSError, AttributeError):
                block_size = 65536
            self.ctx = libarchive.file_reader(path, block_size=block_size)

    def __enter__(self):
        self.reader = self.ctx.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ctx.__exit__(exc_type, exc_val, exc_tb)

    def __iter__(self):
        return (ArchiveEntryWrapper(self, entry, pbar=self.pbar) for entry in self.reader)

    def __getattr__(self, item):
        return getattr(self.reader, item)


class ArchiveEntryReader(MmappedFile, io.IOBase):
    def __init__(self, entry, archive, pbar=None):
        self.entry = entry
        self.archive = archive
        self.pos = 0
        memory_needed = psutil.virtual_memory().total * .8 # 80% of total physical memory
        if entry.file_size < memory_needed:
            self.mmap = mmap.mmap(-1, entry.file_size or 1, access=mmap.ACCESS_READ | mmap.ACCESS_WRITE)
            self.fp = self.mmap
        else:
            self.fp = tempfile.TemporaryFile("r+b")
            self.mmap = FakeMemoryMap(self.fp)
            self.mmap._size = entry.file_size
        self.read_bytes = 0
        bar_fmt = '{desc}{desc_pad}{percentage:3.0f}%|{bar}| ' \
                  '{count:!.2j}{unit} / {total:!.2j}{unit} ' \
                  '[{elapsed}<{eta}, {rate:!.2j}{unit}/s]'
        self.pbar = pbar.counter(total=float(self.length()), desc="Decompressing", unit='B', leave=False, bar_format=bar_fmt)
        super().__init__(self.mmap)

    def length(self):
        return self.entry.file_size

    def __enter__(self):
        return self

    def close(self):
        self.pbar.enabled = False
        self.pbar.close(True)
        self.mmap.close()

    def __getitem__(self, item):
        if isinstance(item, slice):
            pos = item.start
            length = item.stop - item.start
        else:
            pos = item
            length = 1
        self.seek(pos)
        return self._get_data(length)

    def seek(self, pos, whence=os.SEEK_SET):
        old_pos = self.pos
        super().seek(pos, whence)
        new_pos = self.pos
        self.pos = old_pos
        if new_pos > self.read_bytes:
            self._get_data(new_pos - old_pos, discard=True)
        self.pos = new_pos


class BlockReader(ArchiveEntryReader):
    def __init__(self, entry, archive, **kwargs):
        super().__init__(entry, archive, **kwargs)
        self.name = entry.name
        self.size = entry.file_size

    def _get_data(self, n=None, discard=False):
        amount_need_read = min(self.size, self.pos + n)
        left = n
        if amount_need_read > self.read_bytes:
            self.fp.seek(self.read_bytes)
            for data in self.entry.get_blocks(block_size=min(left, 65536)):
                read = len(data)
                self.fp.write(data)
                left -= read
                self.read_bytes += read
                self.pbar.update(read)
                if left <= 0:
                    break
        if self.read_bytes == self.size and self.pbar in self.pbar.manager.counters:
            self.pbar.enabled = False
            self.pbar.close(True)

        if not discard:
            data = self.mmap[self.pos:self.pos+n]
            return data


class RarFileReader(ArchiveEntryReader):
    def __init__(self, entry, archive, **kwargs):
        super().__init__(entry, archive, **kwargs)
        self.name = self.entry.filename
        self.rarfile = self.archive._file_parser.open(self.entry, None)
        self.size = self.entry.file_size

    def _get_data(self, n, discard=False):
        amount_need_read = min(self.size, self.pos + n)

        if amount_need_read > self.read_bytes:
            self.fp.seek(self.read_bytes)
            size_left = amount_need_read - self.read_bytes
            while size_left > 0:
                chunk_size = min(65536, size_left)
                data = self.rarfile.read(chunk_size)
                read = len(data)
                self.fp.write(data)
                size_left -= read
                self.read_bytes += read
                self.pbar.update(read)
                if size_left <= 0:
                    break
        if self.read_bytes == self.size and self.pbar in self.pbar.manager.counters:
            self.pbar.enabled = False
            self.pbar.close(True)

        if not discard:
          return self.mmap[self.pos:self.pos+n]

    def close(self):
        super().close()
        self.rarfile.close()


class ArchiveEntryWrapper:
    def __init__(self, archive, entry, pbar=None):
        self.archive = archive
        self.entry = entry
        self.pbar = pbar
        self.fp = None
        if isinstance(entry, rarfile.RarInfo):
            self.path = entry.filename
        else:
            self.path = entry.path

    def open(self):
        if isinstance(self.entry, rarfile.RarInfo):
            if self.entry.file_size > rarfile.HACK_SIZE_LIMIT:
                self.entry.filename = self.entry.filename.replace("/", "\\")
            self.fp = RarFileReader(self.entry, self.archive, pbar=self.pbar)
        else:
            self.fp = BlockReader(self, self.archive, pbar=self.pbar)
        return self.fp

    def close(self):
        self.fp.close()

    @property
    def file_size(self):
        if isinstance(self.entry, ArchiveEntry):
            return self.entry.size
        else:
            return self.entry.file_size

    @property
    def is_dir(self):
        if isinstance(self.entry, rarfile.RarInfo):
            return self.entry.is_dir()
        else:
            return self.entry.isdir

    def __getattr__(self, item):
        return getattr(self.entry, item)
