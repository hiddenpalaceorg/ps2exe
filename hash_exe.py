import re
import hashlib
import pycdlib
from dates import datetime_from_iso_date


def get_file_list(iso):
    return [child.file_identifier() for child in iso.list_children(iso_path="/")]



def hash_exe(iso):
    file_list = get_file_list(iso)
    if b"SYSTEM.CNF;1" not in file_list:
        print(f"SYSTEM.CNF not found, might not be a PS1/PS2 iso. Files: {file_list}")
        return

    with iso.open_file_from_iso(iso_path="/SYSTEM.CNF;1") as f:
        system_cnf = f.read()

    exe_filename = None
    for line in system_cnf.splitlines():
        if b"BOOT" in line:
            match = re.match(rb"BOOT.?\s*=\s*cdrom0?:\\(.*)", line)
            if match:
                exe_filename = match.group(1)

            break

    if exe_filename is None:
        raise Exception(f"exe not found, SYSTEM.CNF: {system_cnf}")

    print(f"Found exe: {exe_filename.decode()}")
    exe_filename = exe_filename.upper().strip()

    try:
        with iso.open_file_from_iso(iso_path="/" + exe_filename.decode()) as f:
            exe = f.read()
    except pycdlib.pycdlibexception.PyCdlibInvalidInput as e:
        print(f"Could not read exe: {e}")
        print(get_file_list(iso))
        return

    md5 = hashlib.md5(exe).hexdigest()
    print(f"md5: {md5}")

    record = iso.get_record(iso_path="/" + exe_filename.decode())
    if record:
        datetime = datetime_from_iso_date(record.date)
    else:
        datetime = None

    return {
        "exe_filename": exe_filename.decode().replace(";1", ""),
        "exe_date": datetime,
        "md5": md5,
    }

