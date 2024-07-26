import io
import logging
import mmap
import os
import pathlib
import shutil
import sys
import tempfile

import psutil
import rarfile
import zipfile

from utils.InMemoryRolloverTempFile import InMemoryRolloverTempFile
from utils.common import format_bar_desc
from utils.files import MmappedFile, OffsetFile, get_file_size

LOGGER = logging.getLogger(__name__)

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
    rarfile.tool_setup(sevenzip=True, sevenzip2=True, unrar=True, unar=False, bsdtar=False)
except rarfile.RarCannotExec:
    unrar_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib", "unrar")
    if os.name == "nt":
        if sys.maxsize > 2**32:
            rarfile.UNRAR_TOOL = os.path.join(unrar_path, "win64", "UnRAR.exe")
        else:
            rarfile.UNRAR_TOOL = os.path.join(unrar_path, "win32", "UnRAR.exe")
    elif sys.platform == "linux":
        rarfile.UNRAR_TOOL = os.path.join(unrar_path, "linux", "unrar")

    rarfile.tool_setup(sevenzip=True, sevenzip2=True, unrar=True, unar=False, bsdtar=False)


class ArchiveWrapper:
    BAR_FMT = '{desc} {file_name}{desc_pad}{percentage:3.0f}%|{bar}| ' \
              '{count:!.2j}{unit} / {total:!.2j}{unit} ' \
              '[{elapsed}<{eta}, {rate:!.2j}{unit}/s]'

    def __init__(self, file, pbar=None):
        file.seek(0)
        self.fp = file
        self.path = file.name
        self.reader = None
        self.pbar = pbar
        self.mmap = None
        self.tempfile = None
        self.mmap_used = 0
        self.tempfile_used = 0
        self.entries = {}
        self._entries_pos = dict()
        self.rar_tmpfile = None
        self.counter = None
        self.total_size = 0
        file.seek(0)
        try:
            if self.path:
                self.block_size = os.stat(self.path).st_blksize
            else:
                self.block_size = 65536
        except (OSError, AttributeError):
            self.block_size = 65536

        self.fp.seek(0)
        magic = self.fp.read(6)
        if magic == b"Rar\x21\x1A\x07":
            self.fp.seek(0)
            if not os.path.exists(self.path):
                self.rar_tmpfile = tempfile.NamedTemporaryFile("r+b", suffix=".rar", delete=False)
                try:
                    shutil.copyfileobj(self.fp, self.rar_tmpfile, rarfile.BSIZE)
                    self.rar_tmpfile.close()
                except BaseException:
                    self.rar_tmpfile.close()
                    if os.path.exists(self.rar_tmpfile.name):
                        os.unlink(self.rar_tmpfile.name)
                    raise
                self.ctx = rarfile.RarFile(self.rar_tmpfile.name)
            else:
                self.ctx = rarfile.RarFile(self.path)
            if self.ctx.is_solid():
                # Hack unrar to speed up solid archives
                # For solid archives, the default behavior requires
                # decompressing all prior files before getting to the
                # file we want to extract. Since we go through all
                # files in order anyway, just keep the extract process
                # open and extract the whole thing at once
                self.entries = {}
                self.pipereader = None
                def _open_unrar(rar, inf, pwd=None, tmpfile=None, force_file=False):
                    setup = rarfile.tool_setup()

                    if not tmpfile or force_file:
                        inf.filename = inf.filename.replace("\\", os.path.sep)

                    cmd = setup.open_cmdline(pwd, rar, None)
                    if not self.pipereader:
                        self.pipereader = rarfile.PipeReader(self, inf, cmd, tmpfile)
                        self.pipereader.really_close = self.pipereader.close
                        self.pipereader.close = lambda: None
                    else:
                        # Keep the pipe open and just update
                        # the metadata so crc checks can still work
                        self.pipereader._inf = inf
                        self.pipereader.name = inf.filename
                        self.pipereader._md_context = self.pipereader._md_context.__class__()
                        self.pipereader._remain = inf.file_size
                    return self.pipereader

                self.ctx._file_parser._open_unrar = _open_unrar
            self.total_size = float(sum([entry.file_size for entry in self.ctx.infolist()]))
        else:
            self.ctx = libarchive.stream_reader(file, block_size=self.block_size)
            self.total_size = get_file_size(self.fp)

        # 80% of free physical memory
        try:
            self.uncompressed = InMemoryRolloverTempFile(int(psutil.virtual_memory().available * .8))
        except OSError:
            # Try 60%
            try:
                self.uncompressed = InMemoryRolloverTempFile(int(psutil.virtual_memory().available * .6))
            except:
                # Give up
                self.uncompressed = InMemoryRolloverTempFile(0)

    def __enter__(self):
        try:
            self.reader = self.ctx.__enter__()
            if not self.counter:
                self.counter = self.pbar.counter(
                    total=float(self.total_size),
                    desc=f"Decompressing",
                    unit='B',
                    leave=False,
                    bar_format=self.BAR_FMT,
                    file_name=""
                )
            return self
        except libarchive.ArchiveError as e:
            self.recover_decompressor(e)
            self.reader = self.ctx.__enter__()
            return self

    def __exit__(self, *args):
        if self.ctx:
            self.ctx.__exit__(*args)
        if self.uncompressed:
            self.uncompressed.close()

        if self.rar_tmpfile and os.path.exists(self.rar_tmpfile.name):
            self.rar_tmpfile.close()
            os.unlink(self.rar_tmpfile.name)

        if getattr(self, 'pipereader', None):
            self.pipereader.really_close()

    def __iter__(self):
        try:
            yield from self.iter()
        except libarchive.ArchiveError as e:
            self.recover_decompressor(e)
            self.__enter__()
            last_entry = next(reversed(self.entries.keys()), None)
            if last_entry and self.entries[last_entry].entry_reader.read_bytes != self.entries[last_entry].entry_reader.size:
                self.entries.pop(last_entry)
            yield from self.iter(skip_entries=True)

    def iter(self, skip_entries=False):
        if not skip_entries:
            for _, entry in self.entries.items():
                yield entry
        if not self.reader:
            return

        for entry in self.reader:
            if isinstance(entry, (rarfile.RarInfo, zipfile.ZipInfo)):
                file_path = entry.filename
                file_size = entry.file_size
            else:
                file_path = entry.name
                file_size = entry.size

            if file_path in self.entries:
                continue

            if file_size is None or file_path is None:
                last_file = next(reversed(self.entries.keys()), None)
                LOGGER.warning("Archive %s could not be fully extracted. Last file: %s", self.path, last_file)
                break

            if isinstance(file_path, bytes):
                file_path = file_path.decode(errors='replace')

            entry_fp = OffsetFile(self.uncompressed, self.uncompressed.tell(), self.uncompressed.tell() + file_size, file_path)
            entry_wrapper = ArchiveEntryWrapper(self, entry, entry_fp, self.reader, pbar=self.counter)
            self.entries[file_path] = entry_wrapper
            self.counter.update(incr=0, file_name=format_bar_desc(entry_wrapper.file_name, 30))
            yield entry_wrapper
            entry_wrapper.close()
            self.entries[file_path] = CompletedEntryWrapper(entry_wrapper)
            del entry_wrapper
        self.ctx.__exit__(None, None, None)
        self.ctx = None
        self.reader = []
        self.counter.update(incr=0, file_name="")
        self.counter.close()

    def recover_decompressor(self, libarchive_exception):
        self.ctx.__exit__(None, None, None)
        self.fp.seek(0)
        magic = self.fp.read(6)
        if magic[0:4] == b"PK\x03\x04":
            # Attempt to recover using zipfile
            self.fp.seek(0)
            zipfile.ZipFile.__iter__ = lambda s: iter(s.filelist)
            self.ctx = zipfile.ZipFile(io.BytesIO(), "w")
            self.ctx.fp = self.fp
            self.ctx.mode = "rb"
            try:
                self.ctx._RealGetContents()
            except zipfile.BadZipFile:
                pass
            finally:
                if not len(self.ctx.filelist):
                    raise libarchive_exception
        else:
            raise libarchive_exception

    def __getattr__(self, item):
        return getattr(self.reader, item)

    def __del__(self):
        self.__exit__(None, None, None)


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
            # Hack: store the file name inside the module globally for loging purposes
            libarchive.current_file_path = self.entry.path
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


class CompressedFileAsFileIoReader(ArchiveEntryReader):
    def __init__(self, entry, archive, *args, **kwargs):
        super().__init__(entry, archive, *args, **kwargs)
        self.name = self.entry.filename
        self.archive_file = self.open(self.entry)
        self.size = self.entry.file_size

    def open(self, entry):
        raise NotImplementedError

    def _get_data(self, n, discard=False):
        amount_need_read = min(self.size, self.pos + n)

        if amount_need_read > self.read_bytes:
            self.fp.seek(self.read_bytes)
            size_left = amount_need_read - self.read_bytes
            while size_left > 0:
                chunk_size = min(65536, size_left)
                data = self.archive_file.read(chunk_size)
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

    def close(self):
        super().close()
        self.archive_file.close()


class ZipFileReader(CompressedFileAsFileIoReader):
    def open(self, entry):
        return self.archive.open(entry, "r")


class RarFileReader(CompressedFileAsFileIoReader):
    def _get_data(self, n=None, discard=False):
        try:
            return super()._get_data(n, discard)
        except rarfile.BadRarFile as e:
            if str(e).startswith("Failed the read enough data"):
                # Hack to get the amount of data on the previous read
                readback = int(str(e).split("got=")[1])
                self.archive_file._fd.seek(-readback, io.SEEK_CUR)
                self.fp.write(self.archive_file._fd.read(readback))
                if self.pbar:
                    self.pbar.update(readback)
                self.read_bytes = self.size
                LOGGER.warning(e)
                return super()._get_data(n, discard)

    def open(self, entry):
        return self.archive._file_parser.open(entry, None)


class ArchiveEntryWrapper:
    def __init__(self, archive, entry, fp, archive_reader, pbar=None):
        self.fp = fp
        self.archive = archive
        self.archive_reader = archive_reader
        self.entry = entry
        self.pbar = pbar
        self.entry_reader = None
        if isinstance(entry, (rarfile.RarInfo, zipfile.ZipInfo)):
            self.path = entry.filename
        else:
            self.path = entry.path

        if isinstance(self.path, bytes):
            self.path = self.path.decode(errors='replace')

    def open(self):
        if self.entry_reader is not None:
            self.entry_reader.seek(0)
            self.fp.seek(0)
            return self.entry_reader

        if isinstance(self.entry, rarfile.RarInfo):
            if self.entry.file_size > rarfile.HACK_SIZE_LIMIT:
                self.entry.filename = self.entry.filename.replace("/", "\\")
            self.entry_reader = RarFileReader(self.entry, self.archive, self.fp, pbar=self.pbar)
        elif isinstance(self.entry, zipfile.ZipInfo):
            self.entry_reader = ZipFileReader(self.entry, self.archive, self.fp, pbar=self.pbar)
        else:
            self.entry_reader = BlockReader(self, self.archive, self.fp, pbar=self.pbar)
        return self.entry_reader

    def close(self):
        if not self.entry_reader:
            self.open()
        self.entry_reader.close()

    @property
    def file_name(self):
        if isinstance(self.entry, (rarfile.RarInfo, zipfile.ZipInfo)):
            if isinstance(self.entry.filename, bytes):
                return self.entry.filename.decode(errors='replace')
            return self.entry.filename
        else:
            if isinstance(self.entry.name, bytes):
                return self.entry.name.decode(errors='replace')
            return self.entry.name

    @property
    def file_size(self):
        if isinstance(self.entry, ArchiveEntry):
            return self.entry.size
        else:
            return self.entry.file_size

    @property
    def is_dir(self):
        if isinstance(self.entry, (rarfile.RarInfo, zipfile.ZipInfo)):
            return self.entry.is_dir()
        else:
            return self.entry.isdir

    def __getattr__(self, item):
        return getattr(self.entry, item)


class CompletedEntryWrapper(io.IOBase):
    def __init__(self, entry_wrapper):
        self.file_name = entry_wrapper.file_name
        self.file_size = entry_wrapper.file_size
        self.is_dir = entry_wrapper.is_dir
        self.path = entry_wrapper.path
        if getattr(entry_wrapper, "date_time", None):
            self.date_time = entry_wrapper.date_time
        elif getattr(entry_wrapper, "mtime", None):
            self.mtime = entry_wrapper.mtime
        self.entry_fp = entry_wrapper.fp
        del entry_wrapper

    def __enter__(self):
        self.entry_fp.seek(0)
        return self

    def __exit__(self, *args):
        return

    def __getattr__(self, item):
        return getattr(self.entry_fp, item)

    def open(self):
        return self

    def close(self):
        return

    def seek(self, *args, **kwargs):
        return self.entry_fp.seek(*args, **kwargs)

    def tell(self):
        return self.entry_fp.tell()
