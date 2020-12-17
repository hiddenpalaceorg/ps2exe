import logging
import re
import hashlib
import pycdlib
from dates import datetime_from_iso_date


LOGGER = logging.getLogger(__name__)


def get_file_list(root):
    return [child.path for child in root.glob("*")]



def hash_exe(iso, system_type):
    root = iso.IsoPath("/")
    exe_filename = None
    if system_type in ["ps2", "ps1"]:
        try:
            with iso.IsoPath("/SYSTEM.CNF").open() as f:
                system_cnf = f.read()

            for line in system_cnf.splitlines():
                if "BOOT" in line:
                    match = re.match(r"BOOT.?\s*=\s*cdrom0?:\\?\\?([^;]*)", line)
                    if match:
                        exe_filename = match.group(1).replace("\\", "/")
                    break

            if exe_filename is None:
                raise Exception(f"exe not found, SYSTEM.CNF: {system_cnf}")
        except FileNotFoundError:
            if system_type == "ps1":
                try:
                    with iso.IsoPath("/PSX.EXE").open():
                        exe_filename = "PSX.EXE"
                except FileNotFoundError:
                    pass
        if exe_filename:
            exe_filename = exe_filename.upper()
    elif system_type == "saturn":
        exe_filename = next(root.iterdir()).name

    if exe_filename is None:
        file_list = get_file_list(root)
        LOGGER.warning(f"Executable file not found. Files: %s, iso: %s",
                       file_list, iso.file.fp.name)
        return

    LOGGER.info("Found exe: %s", exe_filename)
    exe_filename = exe_filename.strip()
    exe_path = iso.IsoPath("/" + exe_filename)

    try:
        with exe_path.open(mode='rb') as f:
            exe = f.read()
    except Exception:
        file_list = get_file_list(root)
        LOGGER.exception(f"Could not read exe %s, file list: %s iso: %s", exe_filename, file_list, iso.file.fp.name)
        return

    md5 = hashlib.md5(exe).hexdigest()
    LOGGER.info("md5 %s", md5)

    datetime = exe_path.stat().create_time

    return {
        "exe_filename": exe_filename,
        "exe_date": datetime,
        "md5": md5,
    }

