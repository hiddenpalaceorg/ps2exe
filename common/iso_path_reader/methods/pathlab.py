from common.iso_path_reader.methods.base import IsoPathReader
from dates import datetime_from_iso_date


class PathlabPathReader(IsoPathReader):
    def __init__(self, *args, pvd, **kwargs):
        self.pvd = pvd
        super().__init__(*args, **kwargs)

    def get_root_dir(self):
        return self.iso.IsoPath("/")

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        if recursive:
            method = base_dir.rglob
        else:
            method = base_dir.glob

        for file in method("*"):
            if file.is_dir() and not include_dirs:
                continue

            yield file

    def get_file_path(self, file):
        return file.path

    def get_file_date(self, file):
        return file.stat().create_time

    def get_file(self, path):
        if path[0] != "/":
            path = "/" + path

        return self.iso.IsoPath(path.replace(";1", ""))

    def open_file(self, file):
        return file.open(mode='rb')

    def get_file_hash(self, file, algo):
        hash = algo()
        with self.open_file(file) as f:
            while chunk := f.read(65536):
                hash.update(chunk)
        return hash

    def get_file_size(self, file):
        return file.stat().size

    def get_file_sector(self, file):
        return self.iso._load_record(file)['sector']

    def is_directory(self, file):
        return file.is_dir()

    def get_pvd(self):
        return self.pvd