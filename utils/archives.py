import io
import mmap
import os
import sys
import tempfile

import psutil
import rarfile

from utils.common import format_bar_desc
from utils.files import MmappedFile, OffsetFile, get_file_size
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


class ArchiveWrapper:
    def __init__(self, file, pbar=None):
        self.path = file.name
        self.reader = None
        self.pbar = pbar
        self.mmap = None
        self.tempfile = None
        self.mmap_used = 0
        self.tempfile_used = 0
        self.entries = {}
        self._entries_pos = dict()
        file_ext = os.path.splitext(self.path)[1]
        if file_ext.lower() == ".rar":
            self.ctx = rarfile.RarFile(self.path)
            total_size = float(sum([entry.file_size for entry in self.ctx.infolist()]))
        else:
            try:
                block_size = os.stat(self.path).st_blksize
            except (OSError, AttributeError):
                block_size = 65536
            self.ctx = libarchive.file_reader(self.path, block_size=block_size)
            total_size = float(get_file_size(file))

        # 80% of free physical memory
        try:
            self.mmap = mmap.mmap(-1, int(psutil.virtual_memory().available * .8),
                                  access=mmap.ACCESS_READ | mmap.ACCESS_WRITE)
        except OSError:
            # Try 60%
            try:
                self.mmap = mmap.mmap(-1, int(psutil.virtual_memory().available * .6),
                                      access=mmap.ACCESS_READ | mmap.ACCESS_WRITE)
            except OSError:
                # Give up
                pass

        bar_fmt = '{desc} {file_name}{desc_pad}{percentage:3.0f}%|{bar}| ' \
                  '{count:!.2j}{unit} / {total:!.2j}{unit} ' \
                  '[{elapsed}<{eta}, {rate:!.2j}{unit}/s]'

        self.counter = self.pbar.counter(
            total=total_size,
            desc=f"Decompressing",
            unit='B',
            leave=False,
            bar_format=bar_fmt
        )

    def __enter__(self):
        self.reader = self.ctx.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ctx.__exit__(exc_type, exc_val, exc_tb)
        if self.mmap:
            self.mmap.close()
        if self.tempfile:
            self.tempfile.close()

    def __iter__(self):
        for _, entry in self.entries.items():
            yield entry
        if not self.reader:
            return

        for entry in self.reader:
            if isinstance(entry, rarfile.RarInfo):
                file_path = entry.filename
                file_size = entry.file_size
            else:
                file_path = entry.name
                file_size = entry.size

            memory_available = len(self.mmap)
            if not self.mmap or (self.mmap_used + file_size > memory_available):
                if not self.tempfile:
                    self.tempfile = tempfile.TemporaryFile("r+b")
                    self.tempfile_mmap = FakeMemoryMap(self.tempfile)
                    # mark the temp file to 80% of free space
                    self.tempfile_mmap._size = psutil.disk_usage(self.tempfile.name).free

                self._entries_pos[file_path] = (self.tempfile_used, self.tempfile_mmap)
                self.tempfile_used += file_size
                entry_fp = OffsetFile(self.tempfile_mmap, self._entries_pos[file_path][0], self.tempfile_used)
            else:
                self._entries_pos[file_path] = (self.mmap_used, self.mmap)
                self.mmap_used += file_size
                entry_fp = OffsetFile(self.mmap, self._entries_pos[file_path][0], self.mmap_used)

            entry_wrapper = ArchiveEntryWrapper(self, entry, entry_fp, self.reader, pbar=self.counter)
            self.entries[file_path] = entry_wrapper
            self.counter.update(incr=0, file_name=format_bar_desc(entry_wrapper.file_name, 30))
            yield entry_wrapper
            entry_wrapper.close()
        self.reader = []
        self.counter.close()

    def __getattr__(self, item):
        return getattr(self.reader, item)


class ArchiveEntryReader(MmappedFile, io.IOBase):
    def __init__(self, entry, archive, entry_fp, pbar=None):
        self.entry = entry
        self.archive = archive
        self.pos = 0
        self.read_bytes = 0
        self.fp = entry_fp
        self.pbar = pbar

    def length(self):
        return self.entry.file_size

    def __enter__(self):
        return self

    def close(self):
        self.seek(0, io.SEEK_END)

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

    def __len__(self):
        return self.entry.file_size


class BlockReader(ArchiveEntryReader):
    def __init__(self, entry, archive, *args, **kwargs):
        self.name = entry.name
        self.size = entry.file_size
        super().__init__(entry, archive, *args, **kwargs)

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
                if self.pbar:
                    self.pbar.update(self.entry.archive_reader.bytes_read - self.pbar.count)
                if left <= 0:
                    break

        if not discard:
            data = self.fp[self.pos:self.pos+n]
            return data


class RarFileReader(ArchiveEntryReader):
    def __init__(self, entry, archive, *args, **kwargs):
        super().__init__(entry, archive, *args, **kwargs)
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
                if self.pbar:
                    self.pbar.update(read)
                if size_left <= 0:
                    break

        if not discard:
          return self.fp[self.pos:self.pos+n]


class ArchiveEntryWrapper:
    def __init__(self, archive, entry, fp, archive_reader, pbar=None):
        self.fp = fp
        self.archive = archive
        self.archive_reader = archive_reader
        self.entry = entry
        self.pbar = pbar
        self.entry_reader = None
        if isinstance(entry, rarfile.RarInfo):
            self.path = entry.filename
        else:
            self.path = entry.path

    def open(self):
        if self.entry_reader is not None:
            self.entry_reader.seek(0)
            self.fp.seek(0)
            return self.entry_reader

        if isinstance(self.entry, rarfile.RarInfo):
            if self.entry.file_size > rarfile.HACK_SIZE_LIMIT:
                self.entry.filename = self.entry.filename.replace("/", "\\")
            self.entry_reader = RarFileReader(self.entry, self.archive, self.fp, pbar=self.pbar)
        else:
            self.entry_reader = BlockReader(self, self.archive, self.fp, pbar=self.pbar)
        return self.entry_reader

    def close(self):
        if not self.entry_reader:
            self.open()
        self.entry_reader.close()

    @property
    def file_name(self):
        if isinstance(self.entry, rarfile.RarInfo):
            return self.entry.filename
        else:
            return self.entry.name

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
