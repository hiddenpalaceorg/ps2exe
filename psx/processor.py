import logging
import re

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)


class PsxIsoProcessor(BaseIsoProcessor):
    def get_disc_type(self):
        if self.system_type == "ps1":
            return {"disc_type": "cdr"}
        return {"disc_type": "unknown"}

    def get_exe_filename(self):
        exe_filename = None
        try:
            system_cnf = self.iso_path_reader.get_file("/SYSTEM.CNF")
            with self.iso_path_reader.open_file(system_cnf) as f:
                system_cnf = f.read().decode(errors="ignore")

            for line in system_cnf.splitlines():
                if "BOOT" in line:
                    match = re.match(r"BOOT.?\s*=\s*cdrom0?:\\?\\?([^;]*)", line)
                    if match:
                        exe_filename = match.group(1).replace("\\", "/")
                    break

            if exe_filename is None:
                LOGGER.warning(f"exe not found, SYSTEM.CNF: {system_cnf}")
        except FileNotFoundError:
            try:
                psx_exe = self.iso_path_reader.get_file("/PSX.EXE")
                with self.iso_path_reader.open_file(psx_exe):
                    exe_filename = "PSX.EXE"
            except FileNotFoundError:
                pass

        if exe_filename:
            exe_filename = exe_filename.upper()

        return exe_filename

