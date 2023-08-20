import argparse
import csv
import io
import logging
import os
import re
import sys

import enlighten

from common.factory import IsoProcessorFactory
from common.processor import BaseIsoProcessor
from patches import apply_patches
from utils.common import is_path_allowed
from utils.archives import ArchiveWarapper

try:
    import pycdlib
except ImportError:
    pass

LOGGER = logging.getLogger(__name__)
PROGRESS_MANAGER = enlighten.get_manager()


def get_iso_info(iso_filename, disable_contents_checksum, archive_entry=None):
    iso_path = iso_filename.encode("cp1252", errors="replace")
    basename = os.path.basename(iso_filename).encode("cp1252", errors="replace")
    LOGGER.info("Reading %s", iso_path.decode("cp1252"))

    info = {"name": basename.decode("cp1252"), "path": iso_filename}

    if not archive_entry:
        fp = open(iso_filename, "rb")
    else:
        fp = archive_entry.open()
        fp.size = archive_entry.file_size
        info["path"] = os.path.join(archive_entry.archive.path, info["path"])

    if not (iso_path_reader := IsoProcessorFactory.get_iso_path_reader(fp, basename)):
        LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
        return

    system = BaseIsoProcessor.get_system_type(iso_path_reader)
    info.update({"system": system})

    if not (iso_processor_class := IsoProcessorFactory.get_iso_processor_class(system)):
        LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
        return

    iso_processor = iso_processor_class(iso_path_reader, iso_filename, system, PROGRESS_MANAGER)

    info.update(iso_processor.get_disc_type())

    info.update(iso_processor.get_pvd_info())

    info.update(iso_processor.hash_exe())
    info.update(iso_processor.get_most_recent_file_info(info.get("exe_date")))

    if not disable_contents_checksum:
        info.update(iso_processor.get_all_files_hash())

    info.update(iso_processor.get_extra_fields())

    iso_processor.close()
    fp.close()

    return info


csv_headers = (
    "system",
    "disc_type",
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
    "alt_exe_filename",
    "alt_exe_date",
    "alt_md5",
    "alt_all_files_hash",
    "sfo_category",
    "sfo_disc_id",
    "sfo_disc_version",
    "sfo_parental_level",
    "sfo_psp_system_version",
    "sfo_title",
    "exe_signing_type",
    "exe_num_symbols",
    "new_all_files_hash",
    "new_alt_all_files_hash",
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

    parser.add_argument('--allow-extensions',
                       help="Allow these normally ignored extensions to be processed",
                       nargs='+',
                       default=[])

    parser.add_argument('--archives-as-folder',
                       help="Tread compressed archives as if they were folders, processing each file individually",
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
            csv_file = open(args.output, "a+", newline='', encoding='utf-8')
        else:
            csv_file = open(args.output, "w", newline='', encoding='utf-8')

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

    format = PROGRESS_MANAGER.term.bold_underline_bright_white_on_lightslategray(
        "PS2EXE {version} {fill}Gathering Files (found: {count}){fill}{elapsed}"
    )
    status_bar = PROGRESS_MANAGER.counter(counter_format=format,
                                          justify=enlighten.Justify.CENTER,
                                          autorefresh=True,
                                          min_delta=0.5,
                                          version='0.0.1')

    file_count = 0
    files = []
    if args.file:
        if args.file not in existing_files:
            if args.archives_as_folder and re.search(r"\.(zip|7z|rar)$", args.file, re.IGNORECASE):
                with ArchiveWarapper(args.file) as archive:
                    for entry in archive:
                        if os.path.join(args.file, entry.path) in existing_files:
                            continue
                        if not is_path_allowed(entry.path, args.allow_extensions, entry):
                            continue
                        file_count += 1
                    files.append(args.file)
                    status_bar.update()
            elif is_path_allowed(args.file, args.allow_extensions):
                file_count += 1
                files.append(args.file)
                status_bar.update()
    elif args.input_dir:
        max_n = 2000000

        LOGGER.info("Gathering files")
        for root, dirnames, filenames in os.walk(args.input_dir):
            dirnames.sort()
            for filename in sorted(filenames):
                path = os.path.join(root, filename)
                if args.archives_as_folder and re.search(r"\.(zip|7z|rar)$", path, re.IGNORECASE):
                    with ArchiveWarapper(path) as archive:
                        for entry in archive:
                            if os.path.join(path, entry.path) in existing_files:
                                continue
                            if not is_path_allowed(entry.path, args.allow_extensions, entry):
                                continue
                            status_bar.update()
                            file_count += 1
                        files.append(path)
                if path in existing_files:
                    continue
                if not is_path_allowed(path, args.allow_extensions):
                    continue

                file_count += 1
                files.append(path)
                status_bar.update()

                if file_count > max_n:
                    break

            if file_count > max_n:
                break

    status_bar.counter_format = PROGRESS_MANAGER.term.bold_underline_bright_white_on_lightslategray(
        "PS2EXE {version} {fill}Current Game: {game_name} ({count}/{games}){fill}{elapsed}"
    )
    status_bar.count = 0
    status_bar.update(incr=0, games=file_count, game_name='')
    status_bar.refresh()

    for path in files:
        status_bar.update(game_name=os.path.basename(path))

        if len(PROGRESS_MANAGER.counters) > 10:
            oldest_bar = list(PROGRESS_MANAGER.counters.keys())[1:2]
            oldest_bar[0].leave = False
            oldest_bar[0].close()

        if args.archives_as_folder and re.search(r"\.(zip|7z|rar)$", path, re.IGNORECASE):
            LOGGER.info("Reading %s", path)
            with ArchiveWarapper(path, pbar=PROGRESS_MANAGER) as archive:
                for entry in archive:
                    if os.path.join(path, entry.path) in existing_files:
                        continue
                    if not is_path_allowed(entry.path, args.allow_extensions, entry):
                        continue
                    if entry.is_dir:
                        continue
                    status_bar.update(game_name=os.path.basename(entry.path))

                    if len(PROGRESS_MANAGER.counters) > 10:
                        oldest_bar = list(PROGRESS_MANAGER.counters.keys())[1:2]
                        oldest_bar[0].leave = False
                        oldest_bar[0].close()

                    try:
                        result = get_iso_info(entry.path, args.no_contents_checksum, entry)
                        if result:
                            writer.writerow(result)
                            csv_file.flush()

                            bar = list(PROGRESS_MANAGER.counters.keys())[-1]
                            bar.desc = os.path.basename(entry.path)
                            bar.refresh()
                    except Exception:
                        LOGGER.exception("Error reading %s", args.file)
                        entry.close()
                    continue
        if path in existing_files:
            continue
        if not is_path_allowed(path, args.allow_extensions):
            continue
        try:
            result = get_iso_info(path, args.no_contents_checksum)
            if result:
                writer.writerow(result)
                csv_file.flush()

                bar = list(PROGRESS_MANAGER.counters.keys())[-1]
                bar.desc = os.path.basename(path)
                bar.refresh()

        except Exception:
            LOGGER.exception("Error reading %s", args.file)