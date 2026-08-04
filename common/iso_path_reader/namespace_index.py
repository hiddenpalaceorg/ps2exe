import hashlib
import logging

LOGGER = logging.getLogger(__name__)

# Outcome sentinel for a lookup that resolved to nothing
MISS = "\x00miss"

# A log longer than this is not worth replaying; such containers always rescan
MAX_LOG_ENTRIES = 20000


def normalize_path(path):
    if not isinstance(path, str):
        path = str(path)
    path = path.replace("\\", "/")
    while "//" in path:
        path = path.replace("//", "/")
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1:
        path = path.rstrip("/")
    # only the ISO9660 version suffix; ';1' elsewhere is part of the name
    if path.endswith(";1"):
        path = path[:-2]
    return path.casefold()


class NamespaceLog:
    # Every lookup a nested container made through its parent's namespace while
    # it was scanned. Two volume views of one image name the same files
    # differently, so the scan may only be reused for another view if replaying
    # this log there gives the same answers
    def __init__(self):
        self.entries = []
        self.iter_scopes = []
        self.replayable = True

    def give_up(self):
        self.replayable = False
        self.entries.clear()
        self.iter_scopes.clear()

    def record(self, entry):
        if not self.replayable:
            return
        if len(self.entries) >= MAX_LOG_ENTRIES:
            LOGGER.debug("Namespace log grew too large to replay")
            self.give_up()
            return
        self.entries.append(entry)

    def covered_by_iteration(self, path):
        for scope, recursive in self.iter_scopes:
            prefix = "/" if scope == "/" else scope + "/"
            if not path.startswith(prefix):
                continue
            if recursive or "/" not in path[len(prefix):]:
                return True
        return False


class NamespaceIndex:
    # Case folded path -> extents map of a whole volume view, so a lookup another
    # view performed can be answered here without walking the image again
    def __init__(self, reader):
        self.by_path = {}
        self.by_extents = {}
        self.entries = []
        self.complete = True
        self._digests = {}
        try:
            for file in reader.iso_iterator(reader.get_root_dir(), recursive=True, include_dirs=True):
                try:
                    raw_path = reader.get_file_path(file)
                    is_dir = reader.is_directory(file)
                    extents = reader.get_file_extents(file)
                except Exception:
                    self.complete = False
                    continue
                if extents is None:
                    self.complete = False
                    continue
                path = normalize_path(raw_path)
                self.by_path[path] = extents
                self.entries.append((path, extents, is_dir))
                if extents not in self.by_extents:
                    try:
                        date = reader.get_file_date(file)
                    except Exception:
                        date = None
                    self.by_extents[extents] = (raw_path, date)
        except Exception as e:
            LOGGER.debug("Could not index the namespace of %s: %s", reader.volume_type, e)
            self.complete = False
        self.entries.sort()

    def resolve(self, path):
        return self.by_path.get(path, MISS)

    def explains(self, entries):
        # Would this view answer these recorded lookups the way they were answered?
        for entry in entries:
            kind = entry[0]
            if kind == "get":
                if self.resolve(entry[1]) != entry[2]:
                    return False
            elif kind in ("path", "date"):
                found = self.by_extents.get(entry[1])
                if found is None or found[0 if kind == "path" else 1] != entry[2]:
                    return False
        return True

    def digest(self, scope, recursive, include_dirs):
        key = (scope, recursive, include_dirs)
        if key in self._digests:
            return self._digests[key]
        prefix = "/" if scope == "/" else scope + "/"
        hash = hashlib.md5()
        for path, extents, is_dir in self.entries:
            if is_dir and not include_dirs:
                continue
            if not path.startswith(prefix):
                continue
            remainder = path[len(prefix):]
            if not remainder or (not recursive and "/" in remainder):
                continue
            hash.update(path.encode("utf-8", errors="replace"))
            hash.update(repr(extents).encode())
        digest = hash.hexdigest()
        self._digests[key] = digest
        return digest
