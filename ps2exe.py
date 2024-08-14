import argparse
import csv
import io
import logging
import os
import pathlib
import sys
from collections import defaultdict

import enlighten

import utils.files
from common.factory import IsoProcessorFactory
from common.processor import BaseIsoProcessor
from common.iso_path_reader.methods.directory import DirectoryPathReader
from patches import apply_patches
from utils.common import is_path_allowed

try:
    import pycdlib
except ImportError:
    pass

LOGGER = logging.getLogger(__name__)
PROGRESS_MANAGER = enlighten.get_manager()


def extract_info(path_reader, basename, iso_path, disable_contents_checksum):
    info = {"name": basename.decode("cp1252"), "path": iso_path}
    system = BaseIsoProcessor.get_system_type(path_reader)
    info.update({"system": system})

    iso_processor_class = IsoProcessorFactory.get_iso_processor_class(system)
    if not iso_processor_class:
        LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_path)
        return None

    iso_processor = iso_processor_class(path_reader, basename.decode("cp1252"), system, PROGRESS_MANAGER)
    info.update(iso_processor.get_disc_type())
    info.update(iso_processor.get_pvd_info())
    info.update(iso_processor.hash_exe())
    info.update(iso_processor.get_most_recent_file_info(info.get("exe_date")))

    if not disable_contents_checksum:
        info.update(iso_processor.get_all_files_hash())

    info.update(iso_processor.get_extra_fields())

    return info, iso_processor


def process_nested_containers(initial_path_reader, base_iso_path, disable_contents_checksum, rows):
    container_stack = defaultdict(list)
    container_stack[None].append(initial_path_reader)
    container_paths = defaultdict(str)
    container_paths[initial_path_reader] = base_iso_path
    file_stack = defaultdict(list)
    processed_containers = defaultdict(list)
    nested_path_reader = None

    LOGGER.info("Checking for nested containers")

    for file in initial_path_reader.iso_iterator(initial_path_reader.get_root_dir(), recursive=True):
        file_stack[initial_path_reader].append(file)

    while container_stack:
        parent_container = next(reversed(container_stack.keys()))
        try:
            current_path_reader = container_stack[parent_container].pop()
        except IndexError:
            current_path_reader = parent_container

        current_base_path = container_paths[current_path_reader]

        while file_stack[current_path_reader]:
            nested_path_reader = None
            file = file_stack[current_path_reader].pop()
            f = current_path_reader.open_file(file)
            try:
                f.__enter__()
            except AttributeError:
                pass
            file_path = current_path_reader.get_file_path(file)
            if not is_path_allowed(file_path, args.allow_extensions):
                f.__exit__()
                continue

            basename = os.path.basename(file_path).encode("cp1252", errors="replace")
            try:
                nested_path_reader = IsoProcessorFactory.get_iso_path_reader(
                    f, basename.decode("cp1252"), current_path_reader
                )
                if not nested_path_reader:
                    f.__exit__()
                    continue
            except utils.files.BinWrapperException:
                f.__exit__()
                continue

            nested_path = str(pathlib.Path(current_base_path) / file_path.lstrip("/"))

            LOGGER.info("Found nested container %s", nested_path)

            nested_info, nested_iso_processor = extract_info(nested_path_reader, basename, file_path,
                                                             disable_contents_checksum)

            nested_info["name"] = basename.decode("cp1252")
            nested_info["path"] = nested_path
            if nested_info:
                rows.append(nested_info)
                container_stack[current_path_reader].append(nested_path_reader)
                processed_containers[current_path_reader].append((nested_iso_processor, f))
                container_paths[nested_path_reader] = nested_path

            else:
                try:
                    f.__exit__()
                except AttributeError:
                    pass

            bar = list(PROGRESS_MANAGER.counters.keys())[-1]
            bar.desc = os.path.basename(basename.decode("cp1252"))
            bar.refresh()
            cleanup_bars()

            if nested_info:
                break

        if nested_path_reader:
            for file in nested_path_reader.iso_iterator(nested_path_reader.get_root_dir(), recursive=True):
                file_stack[nested_path_reader].append(file)

        if len(file_stack[current_path_reader]) == 0 and len(container_stack[current_path_reader]) == 0:
            if current_path_reader:
                current_path_reader.close()
            try:
                f.__exit__()
            except AttributeError:
                pass
            container_stack.pop(current_path_reader)
            file_stack.pop(current_path_reader)

    return rows


def get_iso_info(iso_filename, disable_contents_checksum):
    iso_path = iso_filename.encode("cp1252", errors="replace")
    fp = open(iso_filename, "rb")
    parent_container = DirectoryPathReader(pathlib.Path(fp.name).parent)

    rows = []

    basename = os.path.basename(iso_filename).encode("cp1252", errors="replace").decode("cp1252")
    LOGGER.info("Reading %s", iso_path.decode("cp1252"))

    iso_path_reader = IsoProcessorFactory.get_iso_path_reader(fp, basename, parent_container)
    if not iso_path_reader:
        LOGGER.exception(f"Could not read ISO, this might be an unsupported format, iso: %s", iso_filename)
        return rows

    info, iso_processor = extract_info(iso_path_reader, basename.encode("cp1252", errors="replace"), iso_filename,
                                       disable_contents_checksum)
    if info:
        rows.append(info)

    bar = list(PROGRESS_MANAGER.counters.keys())[-1]
    bar.desc = os.path.basename(path)
    bar.refresh()

    process_nested_containers(iso_path_reader, iso_filename, disable_contents_checksum, rows)

    iso_processor.close()
    fp.close()
    return rows


def cleanup_bars():
    while len(PROGRESS_MANAGER.counters) > 10:
        oldest_bar = list(PROGRESS_MANAGER.counters.keys())[1:2]
        oldest_bar[0].leave = False
        if getattr(oldest_bar[0], "_closed", False):
            oldest_bar[0]._closed = False
        oldest_bar[0].close()


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

    parser.add_argument('--exclude',
                        help="Exclude file/dir. Can specify multiple",
                        nargs='+',
                        default=[])

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
        if args.file not in existing_files and is_path_allowed(args.file):
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
                skip = False
                for exclude in args.exclude:
                    if path.startswith(exclude):
                        skip = True
                        break
                if skip:
                    continue
                if path in existing_files:
                    continue
                if not is_path_allowed(path):
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

        if path in existing_files:
            continue
        if not is_path_allowed(path, args.allow_extensions):
            continue
        try:
            rows = get_iso_info(path, args.no_contents_checksum)
            if len(rows):
                writer.writerows(rows)
                csv_file.flush()

                bar = list(PROGRESS_MANAGER.counters.keys())[-1]
                bar.desc = os.path.basename(path)
                bar.refresh()

        except Exception:
            LOGGER.exception("Error reading %s", args.file)
