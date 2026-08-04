import contextlib
import logging
import pathlib

import pycdlib.inode
import pycdlib.pycdlibio
import pycdlib.udf
from pycdlib.pycdlib import _yield_children
from pycdlib.pycdlibexception import PyCdlibInvalidInput

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait
from common.iso_path_reader.namespace_index import MISS, NamespaceIndex, NamespaceLog, normalize_path
from dates import datetime_from_iso_date
from utils.files import ConcatenatedFile
from utils.mmap import FakeMemoryMap

LOGGER = logging.getLogger(__name__)


class PyCdLibPathReader(ChunkedHashTrait, IsoPathReader):
    # Set while a container found inside this volume is being scanned, so every
    # name that container resolves here is written down (see namespace_replays)
    _namespace_log = None
    _namespace_index = None

    def __init__(self, iso, fp, *args, volume_type, **kwargs):
        super().__init__(iso, fp, *args, **kwargs)
        self.volume_type = volume_type
        self._path_index = None

    def begin_namespace_recording(self):
        self._namespace_log = NamespaceLog()
        return self._namespace_log

    def end_namespace_recording(self):
        self._namespace_log = None

    @contextlib.contextmanager
    def _namespace_recording_suspended(self):
        log, self._namespace_log = self._namespace_log, None
        try:
            yield
        finally:
            self._namespace_log = log

    @property
    def namespace_index(self):
        if self._namespace_index is None:
            with self._namespace_recording_suspended():
                self._namespace_index = NamespaceIndex(self)
        return self._namespace_index

    def _namespace_scope(self, base_dir):
        try:
            with self._namespace_recording_suspended():
                return normalize_path(self._file_path(base_dir))
        except Exception:
            return None

    def _record_lookup(self, kind, file, value):
        # A nested container resolved this file through our namespace; write
        # the outcome down, or give up replaying if it has no extents to
        # express it with
        log = self._namespace_log
        if log is None:
            return
        extents = self.get_file_extents(file)
        if extents is None:
            log.give_up()
        elif kind == "get":
            log.record(("get", value, extents))
        else:
            log.record((kind, extents, value))

    def namespace_replays(self, log, source_reader):
        # Would every name source_reader resolved while scanning a container also
        # resolve the same way here? If so both views see identical content and
        # that scan can be reused for this one
        if log is None or not log.replayable:
            return False
        if not log.entries:
            return True
        source_index = source_reader.namespace_index
        if not source_index.complete or not self.namespace_index.complete:
            return False
        # The index has to be able to explain the source's own lookups, otherwise
        # it doesn't model name resolution well enough to be trusted here
        if not source_index.explains(log.entries):
            LOGGER.debug("Namespace index disagrees with the recorded lookups of %s, rescanning",
                         source_reader.volume_type)
            return False
        if not self.namespace_index.explains(log.entries):
            return False
        for entry in log.entries:
            if entry[0] != "iter":
                continue
            _, scope, recursive, include_dirs = entry
            if source_index.digest(scope, recursive, include_dirs) != \
                    self.namespace_index.digest(scope, recursive, include_dirs):
                return False
        return True

    @property
    def pycdlib_volume_type(self):
        if "iso9660" in self.volume_type:
            return "iso"
        elif "rock_ridge" in self.volume_type:
            return "rr"
        elif "joliet" in self.volume_type:
            return "joliet"
        elif "udf" in self. volume_type:
            return "udf"
        return self.volume_type

    def get_root_dir(self):
        return self.iso.get_record(**{f"{self.pycdlib_volume_type}_path":"/"})

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        log = self._namespace_log
        if log is not None:
            scope = self._namespace_scope(base_dir)
            if scope is None:
                log.give_up()
            else:
                log.record(("iter", scope, recursive, include_dirs))
                log.iter_scopes.append((scope, recursive))
        yield from self._iterate(base_dir, recursive, include_dirs)

    def _iterate(self, base_dir, recursive=False, include_dirs=False):
        for file in _yield_children(base_dir, rr=self.volume_type=="rock_ridge") if not self.volume_type == "udf" else base_dir.fi_descs:
            if self.volume_type == "udf":
                file = file.file_entry

            if not file or file.is_dot() or file.is_dotdot():
                continue

            if self.volume_type != "udf" and file.is_associated_file():
                # ISO9660 associated files (Mac resource forks on hybrid discs)
                # sort directly before the same-named data-fork record, which
                # _yield_children then hides as a same-name duplicate. Yield the
                # data fork instead; a fork with no data sibling stays as-is.
                for sibling in file.parent.children:
                    if sibling.file_ident == file.file_ident and not sibling.is_associated_file():
                        file = sibling
                        break

            if file.is_dir():
                if recursive:
                    if include_dirs:
                        yield file
                    yield from self._iterate(file, recursive, include_dirs)
                continue

            yield file

    def get_file_path(self, file):
        path = self._file_path(file)
        log = self._namespace_log
        # names inside an already logged listing are covered by its digest
        if log is not None and not log.covered_by_iteration(normalize_path(path)):
            self._record_lookup("path", file, path)
        return path

    def _file_path(self, file):
        try:
            return self.iso.full_path_from_dirrecord(
                file, rockridge=self.volume_type == "rock_ridge"
            ).replace(";1", "").rstrip(".")
        except UnicodeDecodeError:
            path = []
            while file.parent:
                ident = file.file_identifier()
                if hasattr(file, "file_ident") and hasattr(file.file_ident, "encoding"):
                    path.append(f"{ident.decode(file.file_ident.encoding, errors='replace')}")
                else:
                    path.append(ident.decode(errors="replace").replace(";1", ""))
                file = file.parent
            return "/" + "/".join(reversed(path))

    def get_file_date(self, file):
        date = datetime_from_iso_date(file.date if not self.volume_type == "udf" else file.mod_time)
        self._record_lookup("date", file, date)
        return date

    def get_file_size(self, file):
        size = 0
        try:
            size += file.data_length
        except AttributeError:
            try:
                size += file.inode.data_length
            except AttributeError:
                size += file.get_data_length()
        if getattr(file, "data_continuation", None):
            while file.data_continuation:
                file = file.data_continuation
                size += file.get_data_length()
        return size

    def get_file_sector(self, file):
        return file.orig_extent_loc

    def get_file_extents(self, file):
        # Must mirror the read paths in open_file exactly: two files dedup only
        # if open_file would read the same byte ranges for both
        try:
            if self.volume_type == "udf":
                alloc_descs = getattr(file, "alloc_descs", None)
                if not alloc_descs:
                    return None
                if any(isinstance(desc, pycdlib.udf.UDFInlineAD) for desc in alloc_descs):
                    # inline data sits at an offset inside the file entry's block,
                    # which an (lba, length) pair can't distinguish
                    return None
                if len(alloc_descs) > 1:
                    part_start = self.iso.udf_main_descs.partitions[0].part_start_location
                    return tuple(
                        (part_start + desc.log_block_num, desc.extent_length)
                        for desc in alloc_descs
                    )
                if not file.inode:
                    return None
                return ((file.inode.extent_location(), file.get_data_length()),)

            extents = [(file.extent_location(), file.data_length)]
            while getattr(file, "data_continuation", None):
                file = file.data_continuation
                extents.append((file.extent_location(), file.get_data_length()))
            return tuple(extents)
        except Exception:
            return None

    def is_directory(self, file):
        return file.is_dir()

    def path_index(self):
        """
        Builds a path table so repeated directory tree lookups for
        files that don't exist don't kill performance
        """
        if self._path_index is not None:
            return self._path_index
        index = {}
        try:
            for file in self._iterate(self.get_root_dir(), recursive=True):
                # First record wins, as in the linear scan this replaced
                index.setdefault(self._file_path(file).lower(), file)
        except Exception:
            # don't cache a messed up tree
            return index
        self._path_index = index
        return index

    def get_file(self, path):
        try:
            file = self._lookup_file(path)
        except Exception:
            log = self._namespace_log
            if log is not None:
                log.record(("get", normalize_path(path), MISS))
            raise
        self._record_lookup("get", file, normalize_path(path))
        return file

    def _lookup_file(self, path):
        if path[0] == "\\":
            path = pathlib.Path(path).as_posix()
        if path[0] != "/":
            path = "/" + path
        try:
            f = self.iso.get_record(**{f"{self.pycdlib_volume_type}_path": path})
        except (PyCdlibInvalidInput, IndexError) as e:
            try:
                f = self.iso.get_record(**{f"{self.pycdlib_volume_type}_path":path + ";1"})
            except (PyCdlibInvalidInput, IndexError):
                file = self.path_index().get(path.lower())
                if file is not None:
                    return file
                raise FileNotFoundError(e)
        if not f:
            raise FileNotFoundError
        return f

    def open_file(self, file, file_io_cls=pycdlib.pycdlibio.PyCdlibIO):
        # Hack: If multiple files reference the same LBA but with different
        # sizes, update the inode's data size to be correct for this file
        if hasattr(file, "data_length"):
            if not file.inode:
                inode = pycdlib.inode.Inode()
                inode.parse(file.extent_location(), file.data_length, self.fp,
                          self.iso.logical_block_size)
                f = file_io_cls(inode, self.iso.logical_block_size)
                f.name = self._file_path(file)
                return f

            if len(file.inode.linked_records) > 1 and file.inode.data_length != file.data_length:
                LOGGER.warning("File %s marked at LBA %d, which was already marked for file %s",
                               self._file_path(file), file.orig_extent_loc, self._file_path(file.inode.linked_records[0][0]))
                for dr, _ in file.inode.linked_records:
                    if file == dr:
                        file.inode.data_length = dr.data_length
            # Hack #2. If the inode reports a negative or truncated value, force it to be the original size
            if hasattr(file, "data_length") and file.inode.data_length < file.data_length:
                file.inode.data_length = file.data_length

        if self.volume_type == "udf" and len(file.alloc_descs) > 1:
            part_start = self.iso.udf_main_descs.partitions[0].part_start_location
            readers = []
            offsets = [0]
            for alloc_desc in file.alloc_descs:
                inode = pycdlib.inode.Inode()
                inode.parse(part_start + alloc_desc.log_block_num, alloc_desc.extent_length, self.fp,
                            self.iso.logical_block_size)
                f = file_io_cls(inode, self.iso.logical_block_size)
                f.__enter__()
                readers.append(FakeMemoryMap(f))
                offsets.append(alloc_desc.extent_length + offsets[-1])
            f = ConcatenatedFile(readers, offsets[0:-1])
            f.starting_sector = offsets[0] // self.iso.logical_block_size
        elif getattr(file, "data_continuation", None):
            f = file_io_cls(file.inode, self.iso.logical_block_size)
            f.__enter__()
            readers = [FakeMemoryMap(f)]
            offsets = [0]
            while file.data_continuation:
                offsets.append(file.get_data_length())
                file = file.data_continuation
                f = file_io_cls(file.inode, self.iso.logical_block_size)
                f.__enter__()
                readers.append(FakeMemoryMap(f))
            f = ConcatenatedFile(readers, offsets)
        else:
            f = file_io_cls(file.inode, self.iso.logical_block_size)
        f.name = self._file_path(file)
        return f

    def get_pvd(self):
        if self.volume_type == "joliet":
            return self.iso.joliet_vd
        return self.iso.pvd

    @staticmethod
    def _decode_dstring(dstring):
        if not dstring or not dstring[-1]:
            return ""
        encoding = "utf-16-be" if dstring[0] == 16 else "latin-1"
        result = dstring[1:dstring[-1]].decode(encoding, errors='replace')
        return result.replace("\x00", "").strip()

    def get_pvd_info(self):
        if not self.volume_type == "udf":
            return super().get_pvd_info()

        pvd = self.iso.udf_main_descs.pvds[0]

        info = {}

        info["volume_identifier"] = self._decode_dstring(pvd.vol_ident)
        info["volume_set_identifier"] = self._decode_dstring(pvd.vol_set_ident)
        info["volume_creation_date"] = datetime_from_iso_date(pvd.recording_date)

        return info
