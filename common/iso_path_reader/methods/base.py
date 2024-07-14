from dates import datetime_from_iso_date


class IsoPathReader:
    def __init__(self, iso, fp):
        self.iso = iso
        self.fp = fp

    def get_root_dir(self):
        raise NotImplementedError

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        raise NotImplementedError

    def get_file(self, path):
        raise NotImplementedError

    def open_file(self, file):
        raise NotImplementedError

    def get_file_path(self, file):
        raise NotImplementedError

    def get_file_date(self, file):
        raise NotImplementedError

    def get_file_hash(self, file, algo):
        raise NotImplementedError

    def get_pvd(self):
        raise NotImplementedError

    def get_file_sector(self, file):
        raise NotImplementedError

    def is_directory(self, file):
        raise NotImplementedError

    def get_file_size(self, file):
        return file.size

    def get_pvd_info(self):
        pvd = self.get_pvd()

        info = {}

        encoding = getattr(pvd, "encoding", "utf-8")

        for field in ("system_identifier", "volume_identifier", "volume_set_identifier"):
            info[field] = getattr(pvd, field).rstrip(b"\x00"). \
                decode(encoding=encoding, errors='replace').strip()

        for field in (
                "volume_creation_date",
                "volume_modification_date",
                "volume_expiration_date",
                "volume_effective_date",
        ):
            info[field] = datetime_from_iso_date(getattr(pvd, field))

        return info