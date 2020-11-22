import sys
import os
import re
import csv
from io import BytesIO

try:
    import pycdlib
except ImportError:
    pass

from bin_wrapper import BinWrapper
from hash_exe import hash_exe
from pvd import get_pvd_info


def get_iso_info(iso_filename):
    basename = os.path.basename(iso_filename).encode("cp1252", errors="replace")
    print(f"\nReading {basename.decode()}")

    iso = pycdlib.PyCdlib()
    fp = open(iso_filename, "rb")
    try:
        wrapper = BinWrapper(fp)
        iso.open_fp(wrapper)
    except Exception as e:
        print(f"Could not read ISO, this might be an unsupported format: {e}")
        return

    info = {"name": basename.decode()}

    result = hash_exe(iso)
    if result is not None:
        info.update(result)

    info.update(get_pvd_info(iso))

    iso.close()
    fp.close()

    return info


results = []

dirname = sys.argv[1]

i = 0
max_n = 2000000

for root, dirnames, filenames in os.walk(dirname):
    for filename in filenames:
        path = os.path.join(root, filename)

        if re.search("\.(html|jpeg|jpg|cue|ccd|sub)", path):
            continue

        size = os.path.getsize(path)

        if size < 1024 * 1024 * 2:
            continue

        try:
            result = get_iso_info(path)
            if result:
                results.append(result)
        except Exception as e:
            print(f"Error reading {path}: ", e)

        i += 1

        if i > max_n:
            break

    if i > max_n:
        break

csv_headers = (
    "md5",
    "exe_filename",
    "exe_date",
    "name",
    "system_identifier",
    "volume_identifier",
    "volume_set_identifier",
    "volume_creation_date",
    "volume_modification_date",
    "volume_expiration_date",
    "volume_effective_date",
)

with open("results.csv", "w", newline='') as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
    writer.writeheader()
    for result in results:
        print(result)
        writer.writerow(result)
