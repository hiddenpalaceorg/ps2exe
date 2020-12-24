import datetime
import hashlib
import logging

import xxhash

from cdi.path_reader import CdiPathReader

LOGGER = logging.getLogger(__name__)

class BaseIsoProcessor:
    def get_file_list(self):
        return [self.iso_path_reader.get_file_path(file) for file in
                self.iso_path_reader.iso_iterator(self.iso_path_reader.get_root_dir())]

    @staticmethod
    def get_system_type(iso_path_reader):
        if isinstance(iso_path_reader, CdiPathReader):
            return "cdi"

        fp = iso_path_reader.fp
        fp.seek(0)
        if fp.read(15) == b"SEGA SEGASATURN":
            return "saturn"

        try:
            system_cnf = iso_path_reader.get_file("/SYSTEM.CNF")
            with iso_path_reader.open_file(system_cnf) as f:
                system_cnf = f.read().decode(errors="ignore")
                if "BOOT2" in system_cnf:
                    return "ps2"
                elif "BOOT" in system_cnf:
                    return "ps1"
        except FileNotFoundError:
            try:
                psx_exe = iso_path_reader.get_file("/PSX.EXE")
                with iso_path_reader.open_file(psx_exe):
                    return "ps1"
            except FileNotFoundError:
                pass

        fp.seek(0x8008)
        if fp.peek(17) == b'CD-RTOS CD-BRIDGE':
            return "cdi"

        fp.seek(0x8001)
        if fp.peek(5) == b'CD-I ':
            return "cdi"

    def __init__(self, iso_path_reader, filename):
        self.iso_path_reader = iso_path_reader
        self.filename = filename

    def get_exe_filename(self):
        raise NotImplementedError

    def hash_exe(self):
        exe_filename = self.get_exe_filename()

        if exe_filename is None:
            LOGGER.warning(f"Executable file not found. Files: %s, iso: %s",
                           self.get_file_list(), self.filename)
            return {}

        LOGGER.info("Found exe: %s", exe_filename)
        exe_filename = exe_filename.strip()

        if exe_filename is None:
            LOGGER.warning(f"Executable file not found. Files: %s, iso: %s",
                           self.get_file_list(), self.filename)
            return {}

        try:
            exe = self.iso_path_reader.get_file(exe_filename)
            md5 = self.iso_path_reader.get_file_hash(exe, algo=hashlib.md5).hexdigest()
            LOGGER.info("md5 %s", md5)
            datetime = self.iso_path_reader.get_file_date(exe)
        except:
            LOGGER.warning(f"Executable not found. exe filename: %s, files: %s,  iso: %s",
                           exe_filename, self.get_file_list(), self.filename)
            return {}

        return {
            "exe_filename": self.iso_path_reader.get_file_path(exe).replace(";1", ""),
            "exe_date": datetime,
            "md5": md5,
        }

    def get_file_hashes(self):
        file_hashes = {}
        root = self.iso_path_reader.get_root_dir()
        for file in self.iso_path_reader.iso_iterator(root, recursive=True):
            file_path = self.iso_path_reader.get_file_path(file)
            if file_hash := self.iso_path_reader.get_file_hash(file, xxhash.xxh64):
                file_hashes[file_path] = file_hash.digest()
        return file_hashes

    def get_all_files_hash(self):
        file_hashes = self.get_file_hashes()

        all_hashes = hashlib.md5()
        for file, file_hash in sorted(file_hashes.items()):
            all_hashes.update(file_hash)

        return {
            "all_files_hash": all_hashes.hexdigest(),
        }

    def get_most_recent_file(self):
        most_recent_file_date = datetime.datetime.min
        most_recent_file_date = most_recent_file_date.replace(tzinfo=datetime.timezone.utc)
        most_recent_file = None
        root = self.iso_path_reader.get_root_dir()
        for file in self.iso_path_reader.iso_iterator(root, recursive=True):
            file_date = self.iso_path_reader.get_file_date(file)

            if file_date > most_recent_file_date:
                most_recent_file = file
                most_recent_file_date = file_date
        return most_recent_file

    def get_most_recent_file_info(self, exe_date):
        most_recent_file = self.get_most_recent_file()
        if not most_recent_file:
            return {}
        most_recent_file_date = self.iso_path_reader.get_file_date(most_recent_file)

        if exe_date and most_recent_file_date <= exe_date:
            return {}

        most_recent_path = self.iso_path_reader.get_file_path(most_recent_file)
        most_recent_file_hash = self.iso_path_reader.get_file_hash(most_recent_file, hashlib.md5)

        return {
            "most_recent_file": most_recent_path.replace(";1", ""),
            "most_recent_file_date": most_recent_file_date,
            "most_recent_file_hash": most_recent_file_hash.hexdigest()
        }

    def get_extra_fields(self):
        return {}


class GenericIsoProcessor(BaseIsoProcessor):
    def hash_exe(self):
        return {}