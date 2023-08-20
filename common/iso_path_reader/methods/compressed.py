import datetime
import io

from common.iso_path_reader.methods.base import IsoPathReader


class CompressedPathReader(IsoPathReader):
    def __init__(self, iso, fp):
        super().__init__(iso, fp)
        self.files = {}
        self.entries = {}
        for entry in iso:
            if entry.is_dir:
                continue

            self.entries[entry.path] = entry
            with entry.open() as f:
                self.files[entry.path] = io.BytesIO(f.read())
            self.files[entry.path].seek(0)

    def get_root_dir(self):
        return self.entries

    def iso_iterator(self, base_dir, **kwargs):
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

    def get_file_size(self, file):
        return file.file_size

    def get_file_hash(self, file, algo):
        hash = algo()
        f = self.open_file(file)
        while chunk := f.read(65536):
            hash.update(chunk)
        return hash

    def open_file(self, file):
        path = self.get_file_path(file)
        with self.files[path] as f:
            f.seek(0)
            f.close = lambda: None
        return self.files[path]

    # noinspection PyRedeclaration
    def get_file_date(self, file):
        path = self.get_file_path(file)
        if getattr(self.entries[path], "date_time", None):
            return datetime.datetime(*file.date_time, tzinfo=datetime.timezone.utc)
        if isinstance(self.entries[path].mtime, datetime.datetime):
            return self.entries[path].mtime
        return datetime.datetime.fromtimestamp(self.entries[path].mtime, tz=datetime.timezone.utc)

    def get_pvd_info(self):
        return {}

    def get_pvd(self):
        return {}
