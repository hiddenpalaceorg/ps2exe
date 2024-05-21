import os
import re


class MSF:
    def __init__(self, data):
        self.m, self.s, self.f = list(data)

    def __str__(self):
        return f"{self.m:02x}:{self.s:02x}:{self.f:02x}"

    def __cmp__(self, other):
        if self.m != other.m:
            return self.m.__cmp__(other.m)

        if self.s != other.s:
            return self.s.__cmp__(other.s)

        return self.f.__cmp__(other.f)

    def __eq__(self, other):
        return (self.m, self.s, self.f) == (other.m, other.s, other.f)

    def to_bcd(self, x):
        return (x >> 4) * 10 + (x & 0xF)

    def to_sector(self):
        return (
            ((self.to_bcd(self.m) * 60) + self.to_bcd(self.s)) * 75
            + self.to_bcd(self.f)
        ) - 150

    @classmethod
    def from_sector(cls, sector_index):
        s, f = divmod(sector_index + 150, 75)
        m, s = divmod(s, 60)
        m = m // 10 * 16 + m % 10
        ret = cls(bytes.fromhex(f"{m:02x}{s:02}{f:02}"))
        return ret


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
            rf"[Tt]rack ?(?:(0+)?A|0+|\d?[2-9]|[1-9]\d+)\)?\.(?:bin|iso)$|({ignored_filenames})$|\.({disallowed_extensions})$",
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
