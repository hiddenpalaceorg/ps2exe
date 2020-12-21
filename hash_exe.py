import logging
import re
import hashlib
from os.path import basename

import pycdlib

import cdi
from dates import datetime_from_iso_date


LOGGER = logging.getLogger(__name__)


def get_file_list(root):
    return [child.path for child in root.glob("*")]


def get_cdi_file_list(root):
    return [file.name for file in root if file.name not in [b"\x00", b"\x01"]]


def hash_cdi_exe(iso):
    exe_filename = getattr(iso.disclabels[0], "app_id")
    root = iso.path_tbl[0]

    if exe_filename is None:
        file_list = get_cdi_file_list(root)
        LOGGER.warning(f"Executable file not found. Files: %s",
                       file_list)
        return
    LOGGER.info("Found exe: %s", exe_filename)

    exe_basename = basename(exe_filename)
    exe_file = None
    for directory in iso.path_tbl.directories:
        for file in directory.contents:
            if file.name == exe_basename:
                exe_file = file
                break
        if exe_file:
            break

    if exe_file is None:
        file_list = get_cdi_file_list(root)
        LOGGER.warning(f"Executable file not found. Files: %s",
                       file_list)
        return
    md5 = cdi.get_file_hash(iso, exe_file).hexdigest()
    LOGGER.info("md5 %s", md5)

    datetime = exe_file.creation_date

    return {
        "exe_filename": exe_filename.decode(),
        "exe_date": datetime,
        "md5": md5,
    }


def hash_exe(iso, system_type):
    if system_type == 'cdi':
        return hash_cdi_exe(iso)
    root = iso.IsoPath("/")
    exe_filename = None
    if system_type in ["ps2", "ps1"]:
        try:
            with iso.IsoPath("/SYSTEM.CNF").open(mode="rb") as f:
                system_cnf = f.read().decode(errors="ignore")

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
                       file_list, iso.file.file)
        return

    LOGGER.info("Found exe: %s", exe_filename)
    exe_filename = exe_filename.strip()
    exe_path = iso.IsoPath("/" + exe_filename)

    try:
        with exe_path.open(mode='rb') as f:
            exe = f.read()
    except Exception:
        file_list = get_file_list(root)
        LOGGER.exception(f"Could not read exe %s, file list: %s iso: %s", exe_filename, file_list, iso.file.file)
        return

    md5 = hashlib.md5(exe).hexdigest()
    LOGGER.info("md5 %s", md5)

    datetime = exe_path.stat().create_time

    return {
        "exe_filename": exe_filename,
        "exe_date": datetime,
        "md5": md5,
    }

