import argparse
import csv
import datetime
import fnmatch
import hashlib
import logging
import os
import pathlib
import re
import subprocess
import sys
import zlib

import progressbar

LOGGER = logging.getLogger(__name__)

sevenzip_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "7z")
if os.name == "nt":
    if sys.maxsize > 2 ** 32:
        sevenzip_path = os.path.join(sevenzip_path, "win", "x64", "7za.exe")
    else:
        sevenzip_path = os.path.join(sevenzip_path, "win", "ia32", "7za.exe")
elif sys.platform == "linux":
    if sys.maxsize > 2 ** 32:
        sevenzip_path = os.path.join(sevenzip_path, "linux", "x64", "7za")
    else:
        sevenzip_path = os.path.join(sevenzip_path, "linux", "ia32", "7za")
elif sys.platform == "darwin":
    sevenzip_path = os.path.join(sevenzip_path, "mac", "x64", "7za")

allowed_extensions = [
    ".xdelta",
    ".bin",
    ".c2",
    ".dat",
    ".iso",
    ".img",
    ".cue",
    ".ccd",
    ".dvd",
    ".sub",
    ".jpeg",
    ".jpg",
    ".png",
    ".bmp",
    ".gif",
    ".gdi",
    ".raw",
    ".txt",
    ".log",
    ".bca",
    ".zip",
]

def file_info(input_dirs, skip_hash, include_dir):
    LOGGER.info("Computing file information")
    sys.stdout.flush()
    file_info = {}
    rules = [re.compile(fnmatch.translate(f"*{ext}"), re.IGNORECASE) for ext in allowed_extensions]
    total_size = 0
    files = []
    for input_dir in input_dirs:
        files.extend(file for rule in rules for file in input_dir.iterdir() if rule.match(file.name))
    for file in files:
        if file.name == "links.txt":
            continue
        file_info[file] = {
            "filename": file.name if not include_dir else "/".join([file.parent.name, file.name]),
            "size": file.stat().st_size,
            "date": datetime.datetime.fromtimestamp(file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        }
        total_size += file_info[file]["size"]

    if skip_hash:
        return

    widgets = [
        progressbar.widgets.Bar(),
        progressbar.widgets.Percentage(),
    ]
    bar = progressbar.ProgressBar(max_value=total_size, widgets=widgets)
    procesed_size = 0
    for file in files:
        if file.name == "links.txt":
            continue
        with file.open(mode="rb") as f:
            crc = 0
            sha = hashlib.sha1()
            md5 = hashlib.md5()
            while chunk := f.read(65536):
                crc = zlib.crc32(chunk, crc)
                sha.update(chunk)
                md5.update(chunk)
                procesed_size += len(chunk)
                bar.update(procesed_size)
        file_info[file]["crc32"] = "%08X" % (crc & 0xFFFFFFFF)
        file_info[file]["sha1"] = sha.hexdigest()
        file_info[file]["md5"] = md5.hexdigest()
    bar.finish()
    return file_info


def compress(input_dirs, output_file, use_parent_dir):
    LOGGER.info("Compressing")
    sys.stdout.flush()

    compress_command = [
        sevenzip_path,
        "a",
        "-t7z",
        "-m0=lzma2",
        "-mx=9",
        "-mfb=273",
        "-md=26",
        "-ms=8g",
        "-mqs=on",
        "-bt",
        "-bb3",
        "-ssc-",
        "-mmt=2",
        "-mmtf=on",
        "-bso0",
        "-bsp1",
        "-xr!links.txt",
    ]
    for input_dir in input_dirs:
        # If we're including the parent dir, use a relative path, otherwise, use absolute
        if use_parent_dir:
            compress_command.extend(f"-ir!" + os.path.join(input_dir.name, f"*{ext}") for ext in allowed_extensions)
        else:
            compress_command.extend(f"-ir!" + os.path.join(input_dir, f"*{ext}") for ext in allowed_extensions)
    compress_command.append(output_file)

    if use_parent_dir:
        process = subprocess.Popen(compress_command, stderr=subprocess.PIPE, stdout=subprocess.PIPE, cwd=input_dirs[0].parent)
    else:
        process = subprocess.Popen(compress_command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    widgets = [
        progressbar.widgets.Bar(),
        progressbar.widgets.Percentage(),
    ]
    bar = progressbar.ProgressBar(max_value=100, widgets=widgets)
    s = b""
    while True:
        c = process.stdout.read(1)
        if not c:
            break
        if c == b'%' and s:
            bar.update(int(s))
            s = b""
        elif not c.isdigit():
            s = b""
        else:
            s += c
    process.wait()
    bar.finish()


def process(input_dirs, out_path, no_hash):
    use_parent_dir = len(input_dirs) > 1
    LOGGER.info(f"Processing {input_dirs[0]}")

    wikifile_info = file_info(input_dirs, no_hash, use_parent_dir)

    compress(input_dirs, out_path, use_parent_dir)

    LOGGER.info("Getting 7z hash")

    widgets = [
        progressbar.widgets.Bar(),
        progressbar.widgets.Percentage(),
    ]
    bar = progressbar.ProgressBar(max_value=out_path.stat().st_size, widgets=widgets)
    procesed_size = 0

    compressed_info = {
        "out_file": str(out_path.name)
    }
    with out_path.open(mode="rb") as cf:
        crc = 0
        sha = hashlib.sha1()
        md5 = hashlib.md5()
        while chunk := cf.read(65536):
            crc = zlib.crc32(chunk, crc)
            sha.update(chunk)
            md5.update(chunk)
            procesed_size += len(chunk)
            bar.update(procesed_size)
    compressed_info["crc32"] = "%08X" % (crc & 0xFFFFFFFF)
    compressed_info["sha1"] = sha.hexdigest()
    compressed_info["md5"] = md5.hexdigest()
    bar.finish()

    with out_path.with_suffix(".txt").open("w") as f:
        f.write("== Files ==\n")
        f.write("{{filelist|\n")
        for i, item in enumerate(wikifile_info.values()):
            f.write(
                f"{{{{filelistentry |i={i+1}|icon=file|indent=0|filename={item['filename']}|type=File|date={item['date']}|size={item['size']}|crc32={item['crc32']}|md5={item['md5']}|sha1={item['sha1']}|comment=}}}}\n")
        f.write("|date=yes}}\n")
    return compressed_info

out_columns = [
    "out_file",
    "md5",
    "sha1",
    "crc32",
]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--log", dest="logLevel", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level", default="INFO")

    parser.add_argument("input_csv")

    parser.add_argument("input_column",
                        help="Column number or label of input files",
                        type=str)

    parser.add_argument("output_column",
                        help="Column number or label containing output filename",
                        type=str)

    parser.add_argument("output",
                        help="Output folder",
                        type=str)

    parser.add_argument("--input-dir",
                        help="Directory containing input files, defaults to current directory",
                        type=str,
                        default=os.path.dirname(os.path.abspath(__file__)))

    parser.add_argument('--no-hash',
                       help="Disable generating hash file",
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

    output_dir = pathlib.Path(args.output)

    if args.append_output:
        csv_open_args = "a+"
    else:
        csv_open_args = "w"

    existing_files = []
    if args.ignore_existing:
        try:
            with (output_dir / "repack.csv").open("r") as o:
                r = csv.DictReader(o)
                existing_files = [line["out_file"] for line in r]
        except FileNotFoundError:
            pass

    with open(args.input_csv, "r", encoding="utf-8-sig") as f, \
            (output_dir / "repack.csv").open(csv_open_args, newline="") as out:
        reader = csv.DictReader(f)
        writer = csv.DictWriter(out, out_columns)
        if out.tell() == 0:
            writer.writeheader()

        for line in reader:
            if args.input_column.isnumeric():
                col_num = int(args.input_column) - 1
                input_file = list(line.items())[col_num][1]
            else:
                input_file = line[args.input_column]

            input_file_list = input_file.splitlines()

            if args.output_column.isnumeric():
                col_num = int(args.output_column) - 1
                output_file = list(line.items())[col_num][1]
            else:
                output_file = line[args.output_column]

            if output_file in existing_files:
                continue

            out_path = output_dir / output_file

            input_dirs = {}
            for input_file in input_file_list:
                input_dirs[(pathlib.Path(args.input_dir) / input_file).parent] = None
            input_dirs = list(input_dirs.keys())

            try:
                compressed_info = process(input_dirs, out_path, args.no_hash)
            except:
                LOGGER.exception("Error processing row")
                continue

            writer.writerow(compressed_info)
