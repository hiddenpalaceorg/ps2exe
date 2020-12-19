import hashlib

import cdi


def get_file_hashes_pycdlib(iso, iso_dir, file_hashes=None):
    if not file_hashes:
        file_hashes = {}

    for file in iso_dir:
        if file.is_dot() or file.is_dotdot():
            continue
        if file.is_dir():
            file_hashes = get_file_hashes_pycdlib(iso, file.children, file_hashes)
            continue

        file_hash = hashlib.md5()
        file_path = iso.full_path_from_dirrecord(file)
        with iso.open_file_from_iso(iso_path=file_path) as f:
            for chunk in iter(lambda: f.read(65535), b""):
                file_hash.update(chunk)
        file_hashes[file_path] = file_hash.digest()

    return file_hashes



def get_file_hashes_pathlab(root_dir):
    file_hashes = {}
    for file in root_dir.rglob("*"):
        if file.is_dir():
            continue
        file_hash = hashlib.md5()
        with file.open(mode='rb') as f:
            while chunk := f.read(8192):
                file_hash.update(chunk)
        file_hashes[file.path] = file_hash.digest()
    return file_hashes


def get_file_hashes_cdi(iso, path_tbl):
    file_hashes = {}

    for directory in path_tbl.directories:
        for file in directory.contents:
            if file.name == b"\x00" or file.name == b"\x01" or file.attributes.directory:
                continue

            file_hashes[file.name] = cdi.get_file_hash(iso, file).digest()
    return file_hashes


def get_all_files_hash(iso):
    # Using pathlab iso library
    if hasattr(iso, 'IsoPath'):
        root = iso.IsoPath("/")
        file_hashes = get_file_hashes_pathlab(root)
    # Using CD-I
    elif hasattr(iso, "path_tbl"):
        file_hashes = get_file_hashes_cdi(iso, iso.path_tbl)
    # Using pycdlib
    else:
        file_hashes = get_file_hashes_pycdlib(iso, iso.list_dir(iso_path="/"))


    all_hashes = hashlib.md5()
    for file, file_hash in sorted(file_hashes.items()):
        all_hashes.update(file_hash)

    return {
        "all_files_hash": all_hashes.hexdigest(),
    }