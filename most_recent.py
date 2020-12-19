import hashlib
import datetime

import cdi
from dates import datetime_from_iso_date


def get_most_recent_file_dr(iso_dir, most_recent_file=None):
    if most_recent_file:
        most_recent_file_date = datetime_from_iso_date(most_recent_file.date)
    else:
        most_recent_file_date = datetime.datetime.min
        most_recent_file_date = most_recent_file_date.replace(tzinfo=datetime.timezone.utc)

    for file in iso_dir:
        if file.is_dot() or file.is_dotdot():
            continue
        if file.is_dir():
            most_recent_file = get_most_recent_file_dr(file.children, most_recent_file)
            if most_recent_file:
                most_recent_file_date = datetime_from_iso_date(most_recent_file.date)
            continue
        file_date = datetime_from_iso_date(file.date)

        if file_date > most_recent_file_date:
            most_recent_file = file
            most_recent_file_date = file_date
    return most_recent_file



def get_most_recent_file(root_dir):
    most_recent_file_date = datetime.datetime.min
    most_recent_file_date = most_recent_file_date.replace(tzinfo=datetime.timezone.utc)
    most_recent_file = None
    for file in root_dir.rglob("*"):
        if file.is_dir():
            continue
        file_date = file.stat().create_time

        if file_date > most_recent_file_date:
            most_recent_file = file
            most_recent_file_date = file_date
    return most_recent_file


def get_most_recent_cdi_file(path_tbl):
    most_recent_file_date = datetime.datetime.min
    most_recent_file = None

    for directory in path_tbl.directories:
        for file in directory.contents:
            if file.name == b"\x00" or file.name == b"\x01" or file.attributes.directory:
                continue

            file_date = file.creation_date

            if file_date > most_recent_file_date:
                most_recent_file = (directory, file)
                most_recent_file_date = file_date
    return most_recent_file


def get_most_recent_file_info(iso, exe_date):
    # Using pathlab iso library
    if hasattr(iso, 'IsoPath'):
        root = iso.IsoPath("/")
        most_recent_file = get_most_recent_file(root)
        most_recent_path = most_recent_file.path
        most_recent_file_date = most_recent_file.stat().create_time
    # Using CD-I
    elif hasattr(iso, "path_tbl"):
        most_recent_file_dir, most_recent_file = get_most_recent_cdi_file(iso.path_tbl)
        if most_recent_file_dir.name == b"\x00":
            most_recent_file_dir.name = b""
        else:
            most_recent_file_dir.name += b"/"
        most_recent_path = (most_recent_file_dir.name + most_recent_file.name).decode()
        most_recent_file_date = most_recent_file.creation_date
    # Using pycdlib
    else:
        most_recent_file_dr = get_most_recent_file_dr(iso.list_dir(iso_path="/"))
        most_recent_path = iso.full_path_from_dirrecord(most_recent_file_dr)
        most_recent_file_date = datetime_from_iso_date(most_recent_file_dr.date)


    if exe_date and most_recent_file_date <= exe_date:
        return {}

    most_recent_file_hash = hashlib.md5()
    if hasattr(iso, 'IsoPath'):
        with most_recent_file.open(mode='rb') as f:
            while chunk := f.read(8192):
                most_recent_file_hash.update(chunk)
        most_recent_file_hash = most_recent_file_hash.hexdigest()
    elif hasattr(iso, "path_tbl"):
        most_recent_file_hash = cdi.get_file_hash(iso, most_recent_file).hexdigest()
    else:
        with iso.open_file_from_iso(iso_path=most_recent_path) as f:
            while chunk := f.read(8192):
                most_recent_file_hash.update(chunk)
        most_recent_file_hash = most_recent_file_hash.hexdigest()

    return {
        "most_recent_file": most_recent_path.replace(";1", ""),
        "most_recent_file_date": most_recent_file_date,
        "most_recent_file_hash": most_recent_file_hash
    }