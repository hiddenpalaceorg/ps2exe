from dates import datetime_from_iso_date


class IsoPathReader:
    def __init__(self, iso, fp, parent_container, *, extent_cache=None):
        self.iso = iso
        self.fp = fp
        self.parent_container = parent_container
        self.extent_cache = extent_cache

    @property
    def volume_type_chain(self):
        # e.g. "directory->iso9660" for the iso9660 view of a top level image
        chain = []
        container = self
        while container:
            chain.append(container.volume_type)
            container = container.parent_container
        return "->".join(reversed(chain))

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

    def get_file_extents(self, file):
        # (lba, byte_length) pairs describing exactly what open_file would read,
        # or None when the filesystem can't express that (disables extent dedup)
        return None

    def begin_namespace_recording(self):
        # Only volumes that can expose the same file under several views need to
        # record how containers inside them resolve names (see PyCdLibPathReader)
        return None

    def end_namespace_recording(self):
        pass

    def namespace_replays(self, log, source_reader):
        return False

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
                decode(encoding=encoding, errors='replace').replace("\x00", "").strip()

        for field in (
                "volume_creation_date",
                "volume_modification_date",
                "volume_expiration_date",
                "volume_effective_date",
        ):
            info[field] = datetime_from_iso_date(getattr(pvd, field))

        return info

    def close(self):
        self.fp.close()
