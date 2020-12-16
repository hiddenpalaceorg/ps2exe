import logging
import re
import hashlib
import pycdlib
from dates import datetime_from_iso_date


LOGGER = logging.getLogger(__name__)


def get_file_list(root):
    return [child.path for child in root.glob("*")]



def hash_exe(iso):
    root = iso.IsoPath("/")
    file_list = get_file_list(root)
    if "/SYSTEM.CNF" in file_list:
        with iso.IsoPath("/SYSTEM.CNF").open() as f:
            system_cnf = f.read()

        exe_filename = None
        system = None
        for line in system_cnf.splitlines():
            if "BOOT" in line:
                if "BOOT2" in line:
                    system = "ps2"
                else:
                    system = "ps1"
                match = re.match(r"BOOT.?\s*=\s*cdrom0?:\\?\\?([^;]*)", line)
                if match:
                    exe_filename = match.group(1).replace("\\", "/")

                break

        if exe_filename is None:
            raise Exception(f"exe not found, SYSTEM.CNF: {system_cnf}")

    elif "/PSX.EXE" in file_list:
        system = "ps1"
        exe_filename = "PSX.EXE"
    else:
        LOGGER.error(f"SYSTEM.CNF or PSX.EXE not found, might not be a PS1/PS2 iso. Files: %s, iso: %s",
                     file_list, iso.file.fp.name)
        return

    LOGGER.info("Found exe: %s", exe_filename)
    exe_filename = exe_filename.upper().strip()
    exe_path = iso.IsoPath("/" + exe_filename)

    try:
        with exe_path.open(mode='rb') as f:
            exe = f.read()
    except Exception:
        LOGGER.exception(f"Could not read exe %s, file list: %s iso: %s", exe_filename, file_list, iso.file.fp.name)
        return

    md5 = hashlib.md5(exe).hexdigest()
    LOGGER.info("md5 %s", md5)

    datetime = exe_path.stat().create_time

    return {
        "system": system,
        "exe_filename": exe_filename,
        "exe_date": datetime,
        "md5": md5,
    }

