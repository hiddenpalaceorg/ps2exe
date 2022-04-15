import argparse
import hashlib
import logging
import os
from datetime import timezone

from common.factory import IsoProcessorFactory
from common.processor import BaseIsoProcessor
from utils.common import is_path_allowed

LOGGER = logging.getLogger(__name__)

def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            sz = f"{num:3.2f}".rstrip('0').rstrip('.')
            return f"{sz}{unit}{suffix}"
        num /= 1024.0
    sz = f"{num:.2f}".rstrip('0').rstrip('.')
    return f"{sz}Yi{suffix}"


def get_iso_dir(iso_filename):
    iso_path = iso_filename.encode("cp1252", errors="replace")
    basename = os.path.basename(iso_filename).encode("cp1252", errors="replace")
    LOGGER.info("Reading %s", iso_path.decode("cp1252"))

    fp = open(iso_filename, "rb")

    if not (iso_path_reader := IsoProcessorFactory.get_iso_path_reader(fp, basename)):
        LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
        return

    system = BaseIsoProcessor.get_system_type(iso_path_reader)
    LOGGER.info("System: %s", system)

    if not (iso_processor_class := IsoProcessorFactory.get_iso_processor_class(system)):
        LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
        return

    iso_processor = iso_processor_class(iso_path_reader, iso_filename, system)
    path_reader = iso_processor.iso_path_reader

    lines = []
    root = path_reader.get_root_dir()
    for file in path_reader.iso_iterator(root, recursive=True, include_dirs=True):
        file_date = path_reader.get_file_date(file)
        if file_date:
            file_date = file_date.astimezone(timezone.utc).strftime("%m/%d/%Y, %H:%M:%S")

        md5_hash = ''
        sha1_hash = ''
        if not path_reader.is_directory(file):
            md5_hash = path_reader.get_file_hash(file, hashlib.md5).hexdigest()
            sha1_hash = path_reader.get_file_hash(file, hashlib.sha1).hexdigest()

        lines.append(", ".join(list(filter(None, [
            str(path_reader.get_file_sector(file)),
            file_date,
            str(path_reader.get_file_size(file)),
            sizeof_fmt(path_reader.get_file_size(file)),
            md5_hash,
            sha1_hash,
            f">:/{path_reader.get_file_path(file).lstrip('/')}"
        ]))))
    return lines

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--log", dest="logLevel", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level", default="INFO")

    group = parser.add_mutually_exclusive_group(required=False)

    group.add_argument("input_dir", nargs="?", default=os.getcwd())

    group.add_argument('-f',
                       '--file',
                       help="Specific file to parse",
                       type=str,
                       required=False)

    parser.add_argument('--allow-extensions',
                       help="Allow these normally ignored extensions to be processed",
                       nargs='+',
                       default=[])

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.logLevel))

    if args.file and is_path_allowed(args.file):
        try:
            lines = get_iso_dir(args.file)
            if lines:
                out_file = f"{os.path.splitext(args.file)[0]}.txt"
                with open(out_file, "w") as f:
                    f.write("\n".join(lines))
        except:
            LOGGER.exception("Error reading %s", args.file)
    elif args.input_dir:
        for root, dirnames, filenames in os.walk(args.input_dir):
            dirnames.sort()
            for filename in sorted(filenames):
                path = os.path.join(root, filename)
                if not is_path_allowed(path):
                    continue
                try:
                    lines = get_iso_dir(path)
                    if lines:
                        out_file = f"{os.path.splitext(path)[0]}.txt"
                        with open(out_file, "w") as f:
                            f.write("\n".join(lines))
                except Exception:
                    LOGGER.exception("Error reading %s", path)
