import argparse
import csv
import io
import logging
import os
import re
import sys

import cdi
from hash_contents import get_all_files_hash
from iso_accessor import IsoAccessor

from bin_wrapper import BinWrapper
from hash_exe import hash_exe
from most_recent import get_most_recent_file_info
from patches import apply_patches
from pvd import get_pvd_info
from scrambled_wrapper import ScrambleWrapper

try:
    import pycdlib
except ImportError:
    pass

LOGGER = logging.getLogger(__name__)


def get_saturn_header_info(fp):
    fp.seek(0x10)
    header_info = {
        "header_maker_id": fp.read(16),
        "header_product_number": fp.read(10),
        "header_product_version": fp.read(6),
        "header_release_date": fp.read(8),
        "header_device_info": fp.read(8),
        "header_regions": fp.read(10),
    }
    fp.seek(22, os.SEEK_CUR)
    header_info["header_title"] = fp.read(112)

    header_info = {
        header_key: header_item.decode(errors="replace").strip()
        for header_key, header_item in header_info.items()
    }

    return header_info


def get_system_type(fp):
    fp.seek(0)
    if fp.read(15) == b"SEGA SEGASATURN":
        return "saturn"

    fp.seek(0x8001)
    if fp.read(5) == b"CD-I ":
        return "cdi"

    try:
        iso_accessor = IsoAccessor(fp, ignore_susp=True)
    except Exception:
        return

    try:
        with iso_accessor.IsoPath("/SYSTEM.CNF").open() as f:
            system_cnf = f.read()
            if "BOOT2" in system_cnf:
                return "ps2"
            elif "BOOT" in system_cnf:
                return "ps1"
    except FileNotFoundError:
        try:
            with iso_accessor.IsoPath("/PSX.EXE").open():
                return "ps1"
        except FileNotFoundError:
            pass


def get_iso_info(iso_filename, disable_contents_checksum):
    basename = os.path.basename(iso_filename).encode("cp1252", errors="replace")
    LOGGER.info("Reading %s", basename.decode())

    iso = pycdlib.PyCdlib()
    fp = open(iso_filename, "rb")
    info = {"name": basename.decode(), "path": iso_filename}

    wrapper = BinWrapper(fp)
    system = get_system_type(wrapper)
    info.update({"system": system})
    try:
        if system != 'cdi':
            iso.open_fp(wrapper)
            info.update(get_pvd_info(iso))
    except Exception:
        # pycdlib may fail on reading the directory contents of an iso, but it should still correctly parse the PVD
        if not hasattr(iso, "pvd"):
            LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
            return
        info.update(get_pvd_info(iso))

    try:
        if system != 'cdi':
            iso_accessor = IsoAccessor(wrapper, ignore_susp=True)
        else:
            iso_accessor = cdi.Disc(fp, headers=True, scrambled=isinstance(wrapper.fp, ScrambleWrapper))
            iso_accessor.read()
    except Exception:
        LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
        return

    if system:
        result = hash_exe(iso_accessor, system)
        if result is not None:
            info.update(result)

    if system == "saturn":
        info.update(get_saturn_header_info(wrapper))

    if system != 'cdi':
        info.update(get_pvd_info(iso))
    else:
        info.update(cdi.get_disklabel_info(iso_accessor.disclabels[0]))

    if iso._initialized:
        info.update(get_most_recent_file_info(iso, info.get("exe_date")))
        if not disable_contents_checksum:
            info.update(get_all_files_hash(iso))
    else:
        info.update(get_most_recent_file_info(iso_accessor, info.get("exe_date")))
        if not disable_contents_checksum:
            info.update(get_all_files_hash(iso_accessor))

    if iso._initialized:
        iso.close()
    fp.close()

    return info


def process_path(path, disable_contents_checksum):
    if re.search("\(Track (?:\d?[2-9]|[1-9]\d+)\)\.bin|\.(html|jpeg|jpg|cue|ccd|sub|zip|part)", path):
        return

    size = os.path.getsize(path)

    if size < 1024 * 1024 * 2:
        return

    try:
        return get_iso_info(path, disable_contents_checksum)
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
    "header_maker_id",
    "header_product_number",
    "header_product_version",
    "header_release_date",
    "header_device_info",
    "header_regions",
    "header_title",
    "all_files_hash",
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
                       help="Specific file to parse",
                       type=str,
                       required=False)

    parser.add_argument('--no-contents-checksum',
                       help="Disable calculating the hash of the image contents",
                       action='store_true',
                       default=False)

    parser.add_argument('--append-output',
                       help="Append to file instead of overwriting",
                       action='store_true',
                       default=False)

    parser.add_argument('--ignore-existing',
                       help="Don't process discs already in the output csv",
                       action='store_true',
                       default=False)

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.logLevel))

    results = []
    apply_patches()

    if args.output == '-':
        csv_file = sys.stdout
    else:
        if args.append_output:
            csv_file = open(args.output, "a+", newline='')
        else:
            csv_file = open(args.output, "w", newline='')

    writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
    if csv_file == sys.stdout or csv_file.tell() == 0:
        writer.writeheader()
        csv_file.flush()

    existing_files = []
    if args.ignore_existing:
        class NotNullTextWrapper(io.TextIOWrapper):

            def read(self, *args, **kwargs):
                data = super().read(*args, **kwargs)
                return data.replace('\x00', '')

            def readline(self, *args, **kwargs):
                data = super().readline(*args, **kwargs)
                return data.replace('\x00', '')
        with open(args.output, "ba+") as f, \
                NotNullTextWrapper(f) as text_file:
            reader = csv.DictReader(text_file)
            if f.tell() != 0:
                f.seek(0)
                existing_files = [line["path"] for line in reader]
                csv_file.seek(0, os.SEEK_END)

    if args.file:
        if args.file not in existing_files:
            result = process_path(args.file, args.no_contents_checksum)
            if result:
                writer.writerow(result)
    elif args.input_dir:
        i = 0
        max_n = 2000000

        for root, dirnames, filenames in os.walk(args.input_dir):
            for filename in filenames:
                path = os.path.join(root, filename)
                if path in existing_files:
                    continue
                result = process_path(path, args.no_contents_checksum)
                if result:
                    writer.writerow(result)
                    csv_file.flush()
                i += 1

                if i > max_n:
                    break

            if i > max_n:
                break

