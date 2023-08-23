import os
import re


def is_path_allowed(path, allowed_extensions=None, archive_entry=None):
    if allowed_extensions is None:
        allowed_extensions = []

    disallowed_extensions = {
        "html",
        "htm",
        "jpeg",
        "jpg",
        "png",
        "bmp",
        "gif",
        "txt",
        "cue",
        "ccd",
        "sub",
        "dat",
        "json",
        "c2",
        "7z",
        "rar",
        "zip",
        "part",
        "wav",
        "mp3",
        "gdi",
        "raw",
        "cdi",
        "exe",
        "nfo",
        "sfv",
        "sha1",
        "md5",
        "par2",
        "pdf",
        "tif",
        "avi",
        "r\d\d",
        "dctmp",
    }
    disallowed_extensions = "|".join(disallowed_extensions - set(allowed_extensions))
    ignored_filenames = {
        "ip.bin",
        "ss.bin",
        "pfi.bin",
        "dmi.bin",
        r"Data\d{4}",
    }
    ignored_filenames = "|".join(ignored_filenames)
    if re.search(
            rf"[Tt]rack ?(?:\d?[2-9]|[1-9]\d+)\)?\.(?:bin|iso)$|({ignored_filenames})$|\.({disallowed_extensions})$",
            path,
            re.IGNORECASE):
        return False

    if archive_entry:
        size = archive_entry.file_size
    else:
        size = os.path.getsize(path)

    # Allow bin/iso files to be any size (to detect Dreamcast games via track 1 which can be very small)
    if not re.search(r"\.(iso|bin)$", path, re.IGNORECASE) and size < 1024 * 1024 * 2:
        return False

    return True