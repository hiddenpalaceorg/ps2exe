import datetime
import hashlib
import logging
import os
import re

import xxhash

from cdi.path_reader import CdiPathReader
from common.iso_path_reader.methods.compressed import CompressedPathReader
from common.iso_path_reader.methods.pycdlib import PyCdLibPathReader
from utils.common import format_bar_desc
from utils.hash_progress_wrapper import HashProgressWrapper
from xbox.path_reader import XboxPathReader, XboxStfsPathReader

LOGGER = logging.getLogger(__name__)

class BaseIsoProcessor:
    globally_ignored_paths = [
        re.compile(".*\.nfo$", re.IGNORECASE),
        re.compile(".*\.diz$", re.IGNORECASE),
    ]
    ignored_paths = []
    _hash_bar_fmt = '    Hashing {file_name} {desc_pad}{percentage:3.0f}%|{bar}| ' \
                    '{count:!.2k}{unit} / {total:!.2k}{unit} ' \
                    '[{elapsed}<{eta}, {rate:!.2k}{unit}/s]'

    def get_disc_type(self):
        return {"disc_type": "unknown"}

    def get_file_list(self):
        return [self.iso_path_reader.get_file_path(file) for file in
                self.iso_path_reader.iso_iterator(self.iso_path_reader.get_root_dir())]

    @staticmethod
    def get_system_type(iso_path_reader):
        if isinstance(iso_path_reader, CdiPathReader):
            return "cdi"

        if isinstance(iso_path_reader, XboxStfsPathReader):
            return "xbla"

        if not isinstance(iso_path_reader, CompressedPathReader):
            fp = iso_path_reader.fp
            fp.seek(0)
            if fp.read(15) == b"SEGA SEGASATURN":
                return "saturn"

            fp.seek(0)
            if fp.read(14) == b"SEGADISCSYSTEM":
                return "megacd"

            fp.seek(0)
            if fp.read(15) == b"SEGA SEGAKATANA":
                return "dreamcast"

            fp.seek(0)
            if fp.read(7) == b"\x01\x5A\x5A\x5A\x5A\x5A\x01":
                return "3do"

            fp.seek(0x1C)
            if fp.read(4) == b"\xC2\x33\x9F\x3D":
                return "gamecube"

            fp.seek(0)
            if fp.read(64) == b"\x30\x30\x00\x45\x30\x31" + b"\x00" * 26 + \
                              b"\x4E\x44\x44\x45\x4D\x4F" + b"\x00" * 26:
                return "gamecube"

            fp.seek(0x18)
            if fp.read(4) == b"\x5D\x1C\x9E\xA3":
                return "wii"

            fp.seek(0x8001)
            if fp.read(5) == b'CD-I ':
                return "cdi"

        if isinstance(iso_path_reader, (XboxPathReader, CompressedPathReader, PyCdLibPathReader)):
            for sys_type, exe_type, expected_header in (("xbox360", ".xex", b"XEX"), ("xbox", ".xbe", b"XBE")):
                for file in iso_path_reader.iso_iterator(iso_path_reader.get_root_dir(), recursive=False):
                    file_path = iso_path_reader.get_file_path(file)
                    if file_path.lower() == f"/default{exe_type}":
                        with iso_path_reader.open_file(file) as f:
                            if f.read(3).startswith(expected_header):
                                return sys_type

                # could not find default exe in root, use first exe we can find
                for file in iso_path_reader.iso_iterator(iso_path_reader.get_root_dir(), recursive=True):
                    file_path = iso_path_reader.get_file_path(file)
                    if file_path.lower().endswith(exe_type):
                        with iso_path_reader.open_file(file) as f:
                            if f.read(3).startswith(expected_header):
                                return sys_type
                    # Also look for EXE files if they have an xex header
                    elif exe_type == ".xex" and file_path.lower().endswith(".exe"):
                        with iso_path_reader.open_file(file) as f:
                            if f.read(4) in [b"XEX2", b"XEX1", b"XEX%", b"XEX-", b"XEX?"]:
                                return "xbox360"

        pvd = iso_path_reader.get_pvd()
        if pvd and pvd.system_identifier.strip() == b'PSP GAME':
            return "psp"

        try:
            ps3_exe = iso_path_reader.get_file("/PS3_GAME/USRDIR/EBOOT.BIN")
            with iso_path_reader.open_file(ps3_exe):
                return "ps3"
        except FileNotFoundError:
            pass

        for dir in ["/S", "/s"]:
            try:
                for file in iso_path_reader.iso_iterator(iso_path_reader.get_file(dir)):
                    file_path = iso_path_reader.get_file_path(file)
                    if file_path.lower() == "/s/startup-sequence":
                        return "cd32"
            except FileNotFoundError:
                pass

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

        try:
            psx_exe = iso_path_reader.get_file("/DEFAULT.XBE")
            with iso_path_reader.open_file(psx_exe):
                return "xbox"
        except FileNotFoundError:
            pass

        # Look for a windows EXE
        for file in iso_path_reader.iso_iterator(iso_path_reader.get_root_dir(), recursive=True):
            file_path = iso_path_reader.get_file_path(file)
            if file_path.lower().endswith(".exe"):
                with iso_path_reader.open_file(file) as f:
                    if f.read(2) == b"MZ":
                        return "pc"


    def __init__(self, iso_path_reader, filename, system_type, progress_manager):
        self.iso_path_reader = iso_path_reader
        self.filename = filename
        self.system_type = system_type
        self.progress_manager = progress_manager

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

    def get_file_hashes(self, hash_type=xxhash.xxh64):
        file_hashes = {}
        file_hashes_excluding_ignored = {}
        root = self.iso_path_reader.get_root_dir()
        ignored_paths = self.ignored_paths + self.globally_ignored_paths
        file_list = list(self.iso_path_reader.iso_iterator(root, recursive=True))

        with self.progress_manager.counter(total=len(file_list), desc="Getting file hashes", unit='files') as pbar:
            with self.progress_manager.counter(total=0.0,
                                               file_name="", unit='B',
                                               leave=False, bar_format=self._hash_bar_fmt) as hash_bar:
                for file in file_list:
                    file_path = self.iso_path_reader.get_file_path(file)
                    hash_bar.update(incr=0, file_name=format_bar_desc(file_path, 25))
                    hash_bar.total = float(self.iso_path_reader.get_file_size(file))
                    hash_bar.count = 0.0
                    hash_wrapper = HashProgressWrapper(hash_bar, hash_type)
                    if file_hash := self.iso_path_reader.get_file_hash(file, hash_wrapper):
                        file_hashes[file_path] = file_hash.digest()
                        if not any(regex.match(file_path) for regex in ignored_paths):
                            file_hashes_excluding_ignored[file_path] = file_hash.digest()
                    pbar.update()
        return file_hashes, file_hashes_excluding_ignored

    def get_all_files_hash(self):
        LOGGER.info("Getting hash of all files")
        file_hashes, file_hashes_excluding_ignored = self.get_file_hashes()

        all_hashes = hashlib.md5()
        hashes_excluding_ignored = hashlib.md5()
        for file, file_hash in sorted(file_hashes.items()):
            all_hashes.update(file_hash)
            hashes_excluding_ignored.update(file_hashes_excluding_ignored.get(file, b''))

        hashes = {
            "all_files_hash": all_hashes.hexdigest(),
            "alt_all_files_hash": ""
        }
        if hashes_excluding_ignored.hexdigest() != all_hashes.hexdigest():
            hashes["alt_all_files_hash"] = hashes_excluding_ignored.hexdigest()

        all_hashes = hashlib.md5()
        hashes_excluding_ignored = hashlib.md5()
        for file, file_hash in sorted(file_hashes.items(), key=lambda item: item[1]):
            all_hashes.update(file_hash)
        for file, file_hash in sorted(file_hashes_excluding_ignored.items(), key=lambda item: item[1]):
            hashes_excluding_ignored.update(file_hash)


        hashes["new_all_files_hash"] = all_hashes.hexdigest()
        hashes["new_alt_all_files_hash"] = ""
        if hashes_excluding_ignored.hexdigest() != all_hashes.hexdigest():
            hashes["new_alt_all_files_hash"] = hashes_excluding_ignored.hexdigest()
        return hashes

    def get_most_recent_file(self):
        ignored_paths = [re.compile(path) for path in self.ignored_paths + self.globally_ignored_paths]
        most_recent_file_date = datetime.datetime.min
        most_recent_file_date = most_recent_file_date.replace(tzinfo=datetime.timezone.utc)
        most_recent_file = None
        root = self.iso_path_reader.get_root_dir()
        file_list = list(self.iso_path_reader.iso_iterator(root, recursive=True))
        with self.progress_manager.counter(total=len(file_list), desc="Finding latest file", unit='files', leave=False) as pbar:
            for file in file_list:
                file_path = self.iso_path_reader.get_file_path(file)
                if any(regex.match(file_path) for regex in ignored_paths):
                    pbar.update()
                    continue

                file_date = self.iso_path_reader.get_file_date(file)
                if file_date and file_date > most_recent_file_date:
                    most_recent_file = file
                    most_recent_file_date = file_date
                pbar.update()
        return most_recent_file

    def get_most_recent_file_info(self, exe_date):
        LOGGER.info("Getting most recent file")
        most_recent_file = self.get_most_recent_file()
        if not most_recent_file:
            return {}
        most_recent_path = self.iso_path_reader.get_file_path(most_recent_file)
        most_recent_file_date = self.iso_path_reader.get_file_date(most_recent_file)
        if most_recent_file:
            LOGGER.info("Most recent file: %s, date: %s", most_recent_path, most_recent_file_date)
        else:
            LOGGER.info("Most recent file: %s", most_recent_path)

        if exe_date and most_recent_file_date <= exe_date:
            return {}

        with self.progress_manager.counter(total=0.0,
                                           file_name="", unit='B',
                                           leave=False, bar_format=self._hash_bar_fmt) as hash_bar:
            hash_bar.update(incr=0, file_name=format_bar_desc(most_recent_path, 25))
            hash_bar.total = float(self.iso_path_reader.get_file_size(most_recent_file))
            hash_bar.count = 0.0
            hash_wrapper = HashProgressWrapper(hash_bar, hashlib.md5)
            most_recent_file_hash = self.iso_path_reader.get_file_hash(most_recent_file, hash_wrapper)

        if most_recent_file_hash:
            most_recent_file_hash = most_recent_file_hash.hexdigest()

        return {
            "most_recent_file": most_recent_path.replace(";1", ""),
            "most_recent_file_date": most_recent_file_date,
            "most_recent_file_hash": most_recent_file_hash
        }

    def get_extra_fields(self):
        return {}

    def get_pvd_info(self):
        return self.iso_path_reader.get_pvd_info()

    def close(self):
        self.iso_path_reader.close()

class GenericIsoProcessor(BaseIsoProcessor):
    def hash_exe(self):
        return {}
