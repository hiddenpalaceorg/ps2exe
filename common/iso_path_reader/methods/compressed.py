import datetime
import io
from collections import namedtuple

from common.iso_path_reader.methods.base import IsoPathReader


class CompressedPathReader(IsoPathReader):
    def __init__(self, iso, fp):
        super().__init__(iso, fp)
        self.files = {}
        self.entries = {}
        from libarchive import ArchiveEntry
        ArchiveEntryCopy = namedtuple(
            "ArchiveEntryCopy",
            [field for field in dir(ArchiveEntry) if not field.startswith("_")]
        )
        for entry in iso:
            if entry.isdir:
                continue
            self.entries[entry.path] = ArchiveEntryCopy(
                *[getattr(entry, field) for field in dir(entry) if not field.startswith("_")]
            )
            self.files[entry.path] = io.BytesIO()
            for block in entry.get_blocks():
                self.files[entry.path].write(block)
            self.files[entry.path].seek(0)

    def get_root_dir(self):
        return self.entries

    def iso_iterator(self, base_dir, recursive=True):
        # always recursive
        for path, file in self.entries.items():
            yield file

    def get_file(self, path):
        try:
            return self.entries[path]
        except KeyError:
            raise FileNotFoundError

    def get_file_date(self, file):
        return None

    def get_file_path(self, file):
        return file.path

    def get_file_hash(self, file, algo):
        hash = algo()
        f = self.open_file(file)
        while chunk := f.read(65535):
            hash.update(chunk)
        return hash

    def open_file(self, file):
        with self.files[file.path] as f:
            f.seek(0)
            f.close = lambda: None

        return self.files[file.path]

    # noinspection PyRedeclaration
    def get_file_date(self, file):
        return datetime.datetime.fromtimestamp(self.entries[file.path].mtime, tz=datetime.timezone.utc)

    def get_pvd_info(self):
        return {}

    def get_pvd(self):
        return {}