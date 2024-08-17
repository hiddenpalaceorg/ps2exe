import gc
import io
import logging
import os
import pathlib
import re
import shutil
import struct
import sys
import tempfile

import psutil
import rarfile
import zipfile

from utils.in_memory_rollover_temp_file import InMemoryRolloverTempFile
from utils.common import format_bar_desc
from utils.files import AccessBySliceFile, OffsetFile, get_file_size, iterate_patterns
from utils.zip_explode import ExplodingInputStream

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
import libarchive.ffi
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

try:
    import inflate64
except ImportError:
    from stream_inflate import stream_inflate64


class ArchiveWrapper:
    BAR_FMT = '{desc} {file_name}{desc_pad}{percentage:3.0f}%|{bar}| ' \
              '{count:!.2j}{unit} / {total:!.2j}{unit} ' \
              '[{elapsed}<{eta}, {rate:!.2j}{unit}/s]'

    def __init__(self, file, parent_container, pbar=None):
        file.seek(0)
        self.ctx = None
        self.uncompressed = None
        self.fp = file
        self.path = file.name
        self.reader = None
        self.pbar = pbar
        self.tempfile = None
        self.tempfile_used = 0
        self.entries = {}
        self._entries_pos = dict()
        self.rar_tmpfile = None
        self.counter = None
        self.total_size = get_file_size(self.fp)
        self.parent_container = parent_container
        libarchive.current_file_path = None
        file.seek(0)
        magic = file.read(6)
        if magic == b"Rar\x21\x1A\x07":
            # If this a rar, check if it's header is parseable (ex not part of a multipart archive)
            file.seek(0)
            rarfile.RarFile(file)
        file.seek(0)
        try:
            if self.path:
                self.block_size = os.stat(self.path).st_blksize
            else:
                self.block_size = 65536
        except (OSError, AttributeError):
            self.block_size = 65536
        self.ctx = libarchive.stream_reader(file, block_size=self.block_size)

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
            self.ctx = None
        if self.uncompressed:
            self.uncompressed.close()
        if self.counter:
            try:
                self.counter.update(incr=0, file_name="")
            except KeyError:
                pass
            try:
                if not self.counter._closed:
                    self.counter.close()
            except KeyError:
                pass
            self.counter = None
        self.close_readers()
        libarchive.current_file_path = None
        gc.collect()

    def __iter__(self):
        try:
            yield from self.iter()
        except libarchive.ArchiveError as e:
            try:
                self.recover_decompressor(e)
            except libarchive.ArchiveError:
                self.recover_partial_data(e)
                return
            except Exception:
                if self.entries:
                    last_entry = next(reversed(self.entries))
                    if not isinstance(self.entries[last_entry], CompletedEntryWrapper):
                        self.entries[last_entry].closed = True
                        self.entries[last_entry].close()
                gc.collect()
                raise
            self.__enter__()
            if self.entries:
                if not isinstance(self.entries[next(reversed(self.entries))], CompletedEntryWrapper):
                    self.entries.pop(next(reversed(self.entries)))
            try:
                yield from self.iter(skip_entries=True)
            except Exception as e:
                return self.recover_partial_data(e)

    def iter(self, skip_entries=False):
        if not skip_entries:
            for _, entry in self.entries.items():
                yield entry
        if not self.reader:
            return

        entry = None
        for entry in self.reader:
            if isinstance(entry, (rarfile.RarInfo, zipfile.ZipInfo)):
                file_path = entry.filename
                file_size = entry.file_size
            else:
                file_path = entry.name
                file_size = entry.size

            if file_path in self.entries:
                continue

            if file_size is None or file_path in [None, '']:
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
            try:
                entry_wrapper.close()
            except Exception:
                entry_wrapper.closed = True
                raise
            self.entries[file_path] = CompletedEntryWrapper(entry_wrapper)
            del entry_wrapper
        self.ctx.__exit__(None, None, None)
        self.ctx = None
        entry = None
        self.close_readers()
        self.reader = []
        self.counter.update(incr=0, file_name="")
        self.counter.close()
        self.counter = None
        if self.entries:
            last_entry = next(reversed(self.entries))
            self.uncompressed.finalize(self.entries[last_entry].end_pos)
        gc.collect()

    def recover_decompressor(self, libarchive_exception):
        self.ctx.__exit__(None, None, None)
        self.ctx = None
        gc.collect()
        self.fp.seek(0)
        magic = self.fp.read(6)
        if magic == b"Rar\x21\x1A\x07":
            self.fp.seek(0)
            if not os.path.exists(self.path):
                rar_tmpfile = tempfile.NamedTemporaryFile("r+b", suffix=os.path.basename(self.path), delete=False)
                try:
                    shutil.copyfileobj(self.fp, rar_tmpfile, rarfile.BSIZE)
                    rar_tmpfile.close()
                except BaseException:
                    rar_tmpfile.close()
                    if os.path.exists(rar_tmpfile.name):
                        os.unlink(rar_tmpfile.name)
                    raise
                path = rar_tmpfile.name
                self.rar_tmpfile = [rar_tmpfile]
            else:
                path = self.path

            self.ctx = rarfile.RarFile(path)

            if self.ctx.strerror() and self.ctx.strerror().startswith("Cannot open next volume"):
                # Hack to allow multi-volume rars to work in subcontainers
                next_vol_fn = self.ctx._file_parser._next_volname
                def patched_next_vol(volname):
                    next_volname = next_vol_fn(volname)
                    if next_volname == volname:
                        return next_volname
                    orig_filename = os.path.basename(self.path)
                    tmp_position = os.path.basename(volname).index(orig_filename)
                    new_file = os.path.basename(next_volname)[tmp_position:]
                    try:
                        nextvol_real_path = str(pathlib.Path(self.path).parent / new_file)
                        next_vol = self.parent_container.get_file(nextvol_real_path)
                        next_vol_tmp_fp = open(next_volname, "wb")
                        self.path = nextvol_real_path
                        try:
                            with self.parent_container.open_file(next_vol) as next_vol_fp:
                                shutil.copyfileobj(next_vol_fp, next_vol_tmp_fp, rarfile.BSIZE)
                                next_vol_tmp_fp.close()
                        except BaseException:
                            next_vol_fp.close()
                            if os.path.exists(next_vol_fp.name):
                                os.unlink(next_vol_fp.name)
                            raise
                        self.rar_tmpfile.append(next_vol_tmp_fp)
                    except FileNotFoundError:
                        pass
                    return next_volname
                self.ctx._file_parser._next_volname = patched_next_vol
                self.ctx._file_parser._parse_error = None
                self.ctx._file_parser.parse()
                if self.ctx.strerror():
                    LOGGER.warning(self.ctx.strerror())
                # Hack to make sure there's no dupes in the file listing
                self.ctx._file_parser._info_list = list(self.ctx._file_parser._info_map.values())
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

            if self.entries:
                last_entry = next(reversed(self.entries))
                if not isinstance(self.entries[last_entry], CompletedEntryWrapper):
                    self.entries[last_entry].closed = True
                    self.entries[last_entry].close()
                    self.entries.pop(last_entry)
                if self.ctx.is_solid():
                    self.entries.pop(last_entry)
            self.total_size = float(sum([entry.file_size for entry in self.ctx.infolist()]))
            self.counter.total = self.total_size
            self.counter.count = sum([entry.file_size for entry in self.entries.values()])
        elif magic[0:4] == b"PK\x03\x04":
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
            # Verify that the zip file headers match the central directory (if available)
            # If we find any file headers that are not in the central directory, add them to the list
            # If we find any file headers that mismatch the central dir, update the file list and warn
            num_entries = 0
            self.fp.seek(0)
            deep_scanned_entries = []
            while (pos := next(iterate_patterns(self.fp, b"PK\003\004", 65536), None)) is not None:
                fake_central_dir = io.BytesIO()
                self.fp.seek(pos)
                local_header = self.fp.read(0x1E)
                filename_raw = self.fp.read(struct.unpack("<H", local_header[0x1A:0x1C])[0])

                if self.ctx.filelist:
                    flags = struct.unpack("<H", local_header[0x06:0x08])[0]
                    if flags & 0x800:
                        filename = filename_raw.decode('utf-8')
                    else:
                        filename = filename_raw.decode('cp437')
                    zip_entry = None
                    for name_to_try in [filename, filename.replace("/", "\\"), filename.replace("\\", "/")]:
                        try:
                            zip_entry = self.ctx.NameToInfo[name_to_try]
                            break
                        except KeyError:
                            continue
                    if zip_entry:
                        if filename_raw not in deep_scanned_entries and zip_entry.header_offset != pos:
                            LOGGER.warning("Header location in central directory "
                                           "does not match actual header location for file %s", filename)
                            self.ctx.filelist.pop(self.ctx.filelist.index(zip_entry))
                            self.ctx.NameToInfo.pop(zip_entry.filename)
                        else:
                            compress_size = struct.unpack("<L", local_header[0x12:0x16])[0]
                            if not compress_size:
                                compress_size = zip_entry.compress_size
                            self.fp.seek(compress_size, 1)
                            continue
                    else:
                        num_entries += 1
                else:
                    num_entries += 1
                deep_scanned_entries.append(filename_raw)
                # Write signature and version
                fake_central_dir.write(b"PK\x01\x02\xFF\x00")
                # write pkzip version, flags, compression type, time/date, crc32,
                # compressed size, uncompressed size, file name len and extra field len
                fake_central_dir.write(local_header[0x04:])
                fake_central_dir.write(b"\x00" * 10)
                fake_central_dir.write(struct.pack("<L", pos))
                fake_central_dir.write(filename_raw)
                extra_field_len = struct.unpack("<H", local_header[0x1C:0x1E])[0]
                if extra_field_len:
                    fake_central_dir.write(self.fp.read(extra_field_len))
                fake_central_dir.write(b"PK\x05\x06\x00\x00\x00\x00")
                fake_central_dir.write(struct.pack("<H", min(num_entries, 0xFFFF)) * 2)
                fake_central_dir.write(struct.pack("<I", fake_central_dir.tell() - 12))
                fake_central_dir.write(b"\x00\x00\x00\x00\x00\x00")
                fake_central_dir.seek(0)
                self.ctx.fp = fake_central_dir
                self.ctx._RealGetContents()
                if not len(self.ctx.filelist):
                    raise libarchive_exception
                self.fp.seek(struct.unpack("<L", local_header[0x12:0x16])[0], 1)
            if not len(self.ctx.filelist):
                raise libarchive_exception

            if num_entries:
                LOGGER.info("Found %d entries via deep scanning", num_entries)
            self.fp.seek(0)
            self.ctx.fp = self.fp

            if self.entries:
                last_entry = next(reversed(self.entries))
                if not isinstance(self.entries[last_entry], CompletedEntryWrapper):
                    self.entries[last_entry].closed = True
                    self.entries[last_entry].close()
                    self.entries.pop(last_entry)
            self.total_size = sum([entry.file_size for entry in self.ctx.infolist()])
            self.counter.total = float(self.total_size)
            self.counter.count = sum([entry.file_size for entry in self.entries.values()])
        else:
            gc.collect()
            raise libarchive_exception

    def recover_partial_data(self, exception):
        self.reader = []
        if self.ctx:
            self.ctx.__exit__(None, None, None)
            self.ctx = None
        gc.collect()
        if len(self.entries):
            if not any(entry for entry in self.entries.values() if not entry.is_dir and (
                    isinstance(entry, CompletedEntryWrapper) or
                    (entry.entry_reader and entry.entry_reader.read_bytes)
            )):
                self.entries = dict()
                gc.collect()
                raise exception
            last_entry = next(reversed(self.entries))
            if not isinstance(self.entries[last_entry], CompletedEntryWrapper):
                self.entries[last_entry].closed = True
                self.entries[last_entry].close()
                self.entries[last_entry] = CompletedEntryWrapper(self.entries[last_entry])
            self.close_readers()
            self.reader = []
            self.counter.update(incr=0, file_name="")
            self.counter.close()
            LOGGER.warning("Archive %s could not be fully extracted. Last file: %s", self.path, last_entry)
            return
        else:
            self.ctx = None
            self.entries = dict()
            gc.collect()
            raise exception

    def close_readers(self):
        if self.rar_tmpfile:
            for tempfile in self.rar_tmpfile:
                if os.path.exists(tempfile.name):
                    tempfile.close()
                    os.unlink(tempfile.name)
            self.rar_tmpfile = []

        if getattr(self, 'pipereader', None):
            self.pipereader.really_close()

    def __getattr__(self, item):
        return getattr(self.reader, item)

    def __del__(self):
        self.__exit__(None, None, None)


class ArchiveEntryReader(AccessBySliceFile, io.IOBase):
    def __init__(self, entry, archive, entry_fp, pbar=None):
        self.entry = entry
        self.archive = archive
        self.pos = 0
        self.read_bytes = 0
        self.fp = entry_fp
        self.pbar = pbar
        self._closed = False

    def length(self):
        return self.entry.file_size

    def __enter__(self):
        return self

    def close(self):
        if not self._closed:
            self.seek(0, io.SEEK_END)
            self._closed = True

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
            # Hack: store the file name inside the module globally for logging purposes
            libarchive.current_file_path = self.entry.path
            self.fp.seek(self.read_bytes)
            try:
                for data in self.entry.get_blocks(block_size=min(left, 65536)):
                    read = len(data)
                    self.fp.write(data)
                    left -= read
                    self.read_bytes += read
                    if self.pbar:
                        self.pbar.update(self.entry.archive_reader.bytes_read - self.pbar.count)
                    if left <= 0:
                        break
            except libarchive.ArchiveError as e:
                if str(e).startswith("Damaged 7-Zip archive file"):
                    self.fp.end_pos = self.fp.offset + self.read_bytes
                    self.read_bytes = self.size
                    LOGGER.warning(e)
                    return self._get_data(n, discard)
                raise

        if not discard:
            data = self.fp[self.pos:self.pos+n]
            return data


class CompressedFileAsFileIoReader(ArchiveEntryReader):
    def __init__(self, entry, archive, *args, **kwargs):
        super().__init__(entry, archive, *args, **kwargs)
        self.name = self.entry.filename
        self.archive_file = self.open(self.entry)
        self.size = self.entry.file_size
        self.recovery_buf = b""

    def open(self, entry):
        raise NotImplementedError

    def _get_data(self, n, discard=False):
        amount_need_read = min(self.size, self.pos + n)
        if amount_need_read > self.read_bytes:
            self.fp.seek(self.read_bytes)
            size_left = amount_need_read - self.read_bytes
            while size_left > 0:
                chunk_size = min(65536, size_left)
                try:
                    data = self.archive_file.read(chunk_size)
                except EOFError:
                    self.fp.end_pos = self.fp.offset + self.read_bytes
                    raise
                read = len(data)
                self.fp.write(data)
                self.recovery_buf = b""
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

    def _recover_buf(self):
        # Hack to get partial data from a failed read
        if self.recovery_buf:
            self.fp.write(self.recovery_buf)
            if self.pbar:
                self.pbar.update(len(self.recovery_buf))
            self.fp.end_pos = self.fp.offset + self.read_bytes + len(self.recovery_buf)
            self.read_bytes = self.size


class ZipFileReader(CompressedFileAsFileIoReader):
    def __init__(self, entry, archive, *args, **kwargs):
        super().__init__(entry, archive, *args, **kwargs)
        if not self.archive_file:
            self.archive_file = io.BytesIO()
            self.fp.end_pos = self.fp.offset + self.read_bytes + len(self.recovery_buf)
            self.read_bytes = self.size
            return
        orig_update_crc = self.archive_file._update_crc

        def _update_crc(newdata):
            # Ignore 0 crc
            if self.archive_file._expected_crc == 0:
                return
            try:
                return orig_update_crc(newdata)
            except zipfile.BadZipFile as e:
                self.recovery_buf = newdata
                raise

        self.archive_file._update_crc = _update_crc

    def open(self, entry):
        try:
            return self.archive.open(entry, "r")
        except zipfile.BadZipFile as e:
            if str(e).startswith("File name in directory"):
                if "/" in entry.orig_filename:
                    entry.orig_filename = entry.orig_filename.replace("/", "\\")
                elif "\\" in entry.orig_filename:
                    entry.orig_filename = entry.orig_filename.replace("\\", "//")
                else:
                    raise
                return self.archive.open(entry, "r")
            LOGGER.warning(str(e) + " file: %s", self.name)

    def _get_data(self, n, discard=False):
        try:
            super()._get_data(n, discard)
        except zipfile.BadZipFile as e:
            if str(e).startswith("Bad CRC-32"):
                self._recover_buf()
                LOGGER.warning(e)
                return super()._get_data(n, discard)
            raise


class RarFileReader(CompressedFileAsFileIoReader):
    def __init__(self, entry, archive, *args, **kwargs):
        super().__init__(entry, archive, *args, **kwargs)
        orig_read = getattr(self.archive_file, "orig_read", self.archive_file._read)
        self.archive_file.orig_read = orig_read

        def patched_read(cnt):
            buf = orig_read(cnt)

            if match := re.search(rb'ERROR: Data Error.+?\r?\n$', buf):
                loc = match.start()
                buf = buf[:loc]

            self.recovery_buf += buf
            return buf
        self.archive_file._read = patched_read

    def _get_data(self, n=None, discard=False):
        try:
            return super()._get_data(n, discard)
        except rarfile.BadRarFile as e:
            if str(e).startswith("Failed the read enough data"):
                self._recover_buf()
                LOGGER.warning(e)
                return super()._get_data(n, discard)

    def open(self, entry):
        return self.archive._file_parser.open(entry, None)


class StreamInflate64Reader(ArchiveEntryReader):
    def __init__(self, entry, archive, *args, **kwargs):
        super().__init__(entry, archive, *args, **kwargs)
        self.name = self.entry.filename
        self.decomp = None
        self.open(self.entry)
        self.size = self.entry.file_size
        self.start_pos = 0
        self._running_crc = None

    def _get_data(self, n=None, discard=False):
        amount_need_read = min(self.size, self.pos + n)
        left = n
        if amount_need_read > self.read_bytes:
            self.fp.seek(self.read_bytes)
            for data in self.decomp:
                read = len(data)
                self.fp.write(data)
                left -= read
                self.read_bytes += read
                self._update_crc(data)
                if self.pbar:
                    self.pbar.update(read)
                if left <= 0:
                    break

        if not discard:
            data = self.fp[self.pos:self.pos+n]
            return data

    def compressed_chunks(self, chunk_size):
        while data := self.archive.fp.read(chunk_size):
            yield data

    def _update_crc(self, newdata):
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        self._running_crc = zipfile.crc32(newdata, self._running_crc)
        # Check the CRC if we're at the end of the file
        if self.is_done() and self._running_crc != self._expected_crc:
            raise zipfile.BadZipFile("Bad CRC-32 for file %r" % self.name)

    def open(self, entry):
        try:
            self.archive.open(entry, "r")
        except NotImplementedError:
            if hasattr(self.entry, 'CRC'):
                self._expected_crc = self.entry.CRC
                self._running_crc = zipfile.crc32(b'')
            else:
                self._expected_crc = None
            self.start_pos = self.archive.fp.tell()
            self.decomp = self.decompresser(self.compressed_chunks(65536))


class Inflate64Reader(ArchiveEntryReader):
    def __init__(self, entry, archive, *args, **kwargs):
        super().__init__(entry, archive, *args, **kwargs)
        self.name = self.entry.filename
        self.decomp = inflate64.Inflater()
        self._running_crc = None
        self.open(self.entry)
        self.size = self.entry.file_size
        self.start_pos = 0

    def _get_data(self, n=None, discard=False):
        amount_need_read = min(self.size, self.pos + n)
        if amount_need_read > self.read_bytes:
            self.fp.seek(self.read_bytes)
            size_left = amount_need_read - self.read_bytes
            while size_left > 0:
                chunk_size = min(65536, size_left)
                chunk = self.archive.fp.read(chunk_size)
                data = self.decomp.inflate(chunk)
                read = len(data)
                self._update_crc(data)
                self.fp.write(data)
                size_left -= read
                self.read_bytes += read
                if self.pbar:
                    self.pbar.update(read)
                if size_left <= 0:
                    break

        # Check the CRC if we're at the end of the file
        if self.read_bytes == self.size and self._running_crc != self._expected_crc:
            raise zipfile.BadZipFile("Bad CRC-32 for file %r" % self.name)

        if not discard:
            return self.fp[self.pos:self.pos+n]

    def _update_crc(self, newdata):
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        self._running_crc = zipfile.crc32(newdata, self._running_crc)

    def open(self, entry):
        try:
            self.archive.open(entry, "r")
        except NotImplementedError:
            if hasattr(self.entry, 'CRC'):
                self._expected_crc = self.entry.CRC
                self._running_crc = zipfile.crc32(b'')
            else:
                self._expected_crc = None
            self.start_pos = self.archive.fp.tell()


class ImplodedReader(ArchiveEntryReader):
    def __init__(self, entry, archive, *args, **kwargs):
        super().__init__(entry, archive, *args, **kwargs)
        self.name = self.entry.filename
        self._running_crc = None
        self.decomp = None
        self.open(self.entry)
        self.size = self.entry.file_size
        self.start_pos = 0

    def _get_data(self, n=None, discard=False):
        amount_need_read = min(self.size, self.pos + n)
        if amount_need_read > self.read_bytes:
            self.fp.seek(self.read_bytes)
            size_left = amount_need_read - self.read_bytes
            while size_left > 0:
                chunk_size = min(65536, size_left)
                data = self.decomp.read(chunk_size)
                read = len(data)
                self._update_crc(data)
                self.fp.write(data)
                size_left -= read
                self.read_bytes += read
                if self.pbar:
                    self.pbar.update(read)
                if size_left <= 0:
                    break

        # Check the CRC if we're at the end of the file
        if self.read_bytes == self.size and self._running_crc != self._expected_crc:
            raise zipfile.BadZipFile("Bad CRC-32 for file %r" % self.name)

        if not discard:
            return self.fp[self.pos:self.pos+n]

    def _update_crc(self, newdata):
        if self._expected_crc is None:
            # No need to compute the CRC if we don't have a reference value
            return
        self._running_crc = zipfile.crc32(newdata, self._running_crc)

    def open(self, entry):
        try:
            self.archive.open(entry, "r")
        except NotImplementedError:
            if hasattr(self.entry, 'CRC'):
                self._expected_crc = self.entry.CRC
                self._running_crc = zipfile.crc32(b'')
            else:
                self._expected_crc = None
            dictionary_size = 4096
            number_of_trees = 2
            if entry.flag_bits & 0x2 != 0:
                dictionary_size = 8192
            if entry.flag_bits & 0x4 != 0:
                number_of_trees = 3

            self.decomp = ExplodingInputStream(dictionary_size, number_of_trees, self.archive.fp)

            self.start_pos = self.archive.fp.tell()


class ArchiveEntryWrapper:
    def __init__(self, archive, entry, fp, archive_reader, pbar=None):
        self.fp = fp
        self.archive = archive
        self.archive_reader = archive_reader
        self.entry = entry
        self.pbar = pbar
        self.entry_reader = None
        self.closed = False
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
            if self.entry.compress_type == 9:
                if "inflate64" in sys.modules:
                    self.entry_reader = Inflate64Reader(self.entry, self.archive, self.fp, pbar=self.pbar)
                else:
                    self.entry_reader = StreamInflate64Reader(self.entry, self.archive, self.fp, pbar=self.pbar)
            elif self.entry.compress_type == 6:
                self.entry_reader = ImplodedReader(self.entry, self.archive, self.fp, pbar=self.pbar)
            else:
                self.entry_reader = ZipFileReader(self.entry, self.archive, self.fp, pbar=self.pbar)
        else:
            self.entry_reader = BlockReader(self, self.archive, self.fp, pbar=self.pbar)
        return self.entry_reader

    def close(self):
        if not self.closed:
            if not self.entry_reader:
                self.open()
            self.entry_reader.close()
        elif self.entry_reader:
            self.entry_reader._closed = True

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

    def __getitem__(self, item):
        return self.entry_fp.__getitem__(item)

    def open(self):
        return self

    def close(self):
        return

    def seek(self, *args, **kwargs):
        return self.entry_fp.seek(*args, **kwargs)

    def seekable(self):
        return True

    def tell(self):
        return self.entry_fp.tell()
