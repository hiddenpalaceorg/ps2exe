import logging
import os
import datetime

import pefile

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)


class PcIsoProcessor(BaseIsoProcessor):
    def get_exe_filename(self):
        found_exes = {}
        for file in self.iso_path_reader.iso_iterator(self.iso_path_reader.get_root_dir(), recursive=True):
            file_path = self.iso_path_reader.get_file_path(file)
            file_path_lower = file_path.lower()
            if file_path_lower.endswith(".exe"):
                if not (exe_info := self._parse_exe(file_path)):
                    continue
                if "alt_exe_date" in exe_info:
                    LOGGER.info("exe date (filesystem): %s, exe date (internal): %s",
                                exe_info["exe_date"], exe_info["alt_exe_date"])
                else:
                    LOGGER.info("exe date: %s", exe_info["exe_date"])
                found_exes[file_path] = exe_info

        if not found_exes:
            return

        exe = max(found_exes.items(), key=lambda x: getattr(
            x[1], "exe_date", getattr(x[1], "alt_exe_date", datetime.datetime.min)
        ))[0]
        LOGGER.info("Found latest exe: %s", exe)
        self.exe_info = found_exes[exe]
        return exe

    def _parse_exe(self, exe_filename):
        LOGGER.info("Parsing EXE file: %s", exe_filename)
        file = self.iso_path_reader.get_file(exe_filename)
        result = {
            "exe_date": self.iso_path_reader.get_file_date(file)
        }
        with self.iso_path_reader.open_file(file) as f:
            f.seek(0)
            try:
                pe_headers = pefile.PE(name=None, data=f.read(), fast_load=True)
                LOGGER.info("Found PE file: %s", exe_filename)
                result["alt_exe_date"] = datetime.datetime.fromtimestamp(
                    pe_headers.FILE_HEADER.TimeDateStamp,
                    tz=datetime.timezone.utc
                )
            except pefile.PEFormatError:
                f.seek(0)
                if f.read(2) != b"MZ":
                    return None
                LOGGER.info("Found 16-bit EXE file: %s", exe_filename)
            return result
