import argparse
import csv
import logging
import os
import re
import struct
import sys

from iso_accessor import IsoAccessor
from pycdlib.pycdlibexception import PyCdlibInvalidISO

from bin_wrapper import BinWrapper
from hash_exe import hash_exe
from most_recent import get_most_recent_file_info
from patches import apply_patches
from pvd import get_pvd_info

try:
    import pycdlib
except ImportError:
    pass

LOGGER = logging.getLogger(__name__)


def get_iso_info(iso_filename):
    basename = os.path.basename(iso_filename).encode("cp1252", errors="replace")
    LOGGER.info("Reading %s", basename.decode())

    iso = pycdlib.PyCdlib()
    fp = open(iso_filename, "rb")
    info = {"name": basename.decode(), "path": iso_filename}

    wrapper = BinWrapper(fp)
    try:
        iso.open_fp(wrapper)
        info.update(get_pvd_info(iso))
    except Exception:
        # pycdlib may fail on reading the directory contents of an iso, but it should still correctly parse the PVD
        if not hasattr(iso, "pvd"):
            LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
            return
        info.update(get_pvd_info(iso))

    try:
        iso_accessor = IsoAccessor(wrapper, ignore_susp=True)
    except Exception:
        LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
        return

    result = hash_exe(iso_accessor)
    if result is not None:
        info.update(result)

    info.update(get_pvd_info(iso))

    if iso._initialized:
        info.update(get_most_recent_file_info(iso, info.get("exe_date")))
    else:
        info.update(get_most_recent_file_info(iso_accessor, info.get("exe_date")))

    if iso._initialized:
        iso.close()
    fp.close()

    return info


def process_path(path):
    if re.search("\(Track (?:[2-9]|\d\d\d*)\)\.bin|\.(html|jpeg|jpg|cue|ccd|sub|zip|part)", path):
        return

    size = os.path.getsize(path)

    if size < 1024 * 1024 * 2:
        return

    try:
        return get_iso_info(path)
    except Exception:
        LOGGER.exception("Error reading %s", path)


csv_headers = (
    "system",
    "md5",
    "exe_filename",
    "exe_date",
    "name",
    "path",
    "most_recent_file",
    "most_recent_file_date",
    "most_recent_file_hash",
    "system_identifier",
    "volume_identifier",
    "volume_set_identifier",
    "volume_creation_date",
    "volume_modification_date",
    "volume_expiration_date",
    "volume_effective_date",
)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-o',
                        '--output',
                        help="Output file",
                        type=str,
                        default='results.csv')

    parser.add_argument("-l", "--log", dest="logLevel", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level", default="INFO")

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("input_dir", nargs="?")

    group.add_argument('-f',
                       '--file',
                       help="Speicific file to parse",
                       type=str,
                       required=False)

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.logLevel))

    results = []
    apply_patches()

    if args.file:
        result = process_path(args.file)
        if result:
            results.append(result)
    elif args.input_dir:
        i = 0
        max_n = 2000000

        for root, dirnames, filenames in os.walk(args.input_dir):
            for filename in filenames:
                path = os.path.join(root, filename)
                result = process_path(path)
                if result:
                    results.append(result)
                i += 1

                if i > max_n:
                    break

            if i > max_n:
                break

    if args.output == '-':
        csv_file = sys.stdout
    else:
        csv_file = open(args.output, "w", newline='')

    writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
    writer.writeheader()
    for result in results:
        writer.writerow(result)