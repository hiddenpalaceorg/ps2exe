import json
import logging
import pathlib
import re

from common.iso_path_reader.methods.directory import DirectoryPathReader

LOGGER = logging.getLogger(__name__)

# How many disc numbers to probe when searching for siblings by name
MAX_DISC_SEARCH = 12


class DiscSetResolver:
    """Locates sibling disc images of a multi-disc installer set, from a
    JSON manifest (a list of disc-path lists, resolved relative to the
    manifest file) when the current disc is listed in one, otherwise by a
    strict name heuristic. The reader validates every candidate volume
    against the set's descriptor before using it"""

    # Disc designator in redump/TOSEC-style names: "(Disc 1)", "(CD2)",
    # "(Disc 1 of 4)"
    DISC_TOKEN = re.compile(r"\((?:Disc|Disk|CD|DVD)\s*(\d+)(?:\s+of\s+\d+)?\)", re.IGNORECASE)
    # Trailing per-disc labels like " (Play Disc)" or "[!]"
    NAME_TAGS = r"(?:\s*(?:\([^)]*\)|\[[^\]]*\]))*"

    def __init__(self, factory, progress_manager, manifest_path=None, search_siblings=True):
        self.factory = factory
        self.progress_manager = progress_manager
        self.search_siblings = search_siblings
        self.manifest = self._load_manifest(manifest_path) if manifest_path else []
        self._root = None
        self._containers = None
        self._open_files = []

    @staticmethod
    def _load_manifest(manifest_path):
        base = pathlib.Path(manifest_path).resolve().parent
        with open(manifest_path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = list(data.values())
        sets = []
        for disc_set in data:
            paths = [pathlib.Path(disc) for disc in disc_set]
            sets.append([(path if path.is_absolute() else base / path).resolve()
                         for path in paths])
        return sets

    def set_root(self, path):
        """Declare the input file currently being scanned; drops sibling
        containers opened for the previous one"""
        path = pathlib.Path(path).resolve()
        if path == self._root:
            return
        self.close()
        self._root = path

    def close(self):
        for container in self._containers or []:
            self._close_quietly(container)
        for fp in self._open_files:
            self._close_quietly(fp)
        self._containers = None
        self._open_files = []

    @staticmethod
    def _close_quietly(fp):
        try:
            fp.close()
        except Exception:
            pass

    def __call__(self, wrapper):
        """SIBLING_DISC_RESOLVER interface, returns (container, base_dir)
        pairs; a None base_dir means the cabinet's own directory"""
        if self._containers is None:
            self._containers = []
            for candidate in self._candidates():
                self._containers.extend(self._open_disc(candidate))
        return [(container, None) for container in self._containers]

    def _candidates(self):
        if self._root is None:
            return []
        for disc_set in self.manifest:
            if self._root in disc_set:
                LOGGER.debug("Disc %s found in manifest set", self._root)
                return [path for path in disc_set if path != self._root]
        if self.search_siblings:
            return self._sibling_candidates()
        return []

    def _sibling_candidates(self):
        return self._disc_token_candidates() or self._numbered_name_candidates()

    def _disc_token_candidates(self):
        # Redump/TOSEC-style names: the title and tags before the disc
        # token must match exactly, per-disc labels after it may differ
        # ("Game (Disc 1) (Play Disc).iso" pairs with "Game (Disc 2).iso")
        root = self._root
        token_match = self.DISC_TOKEN.search(root.name)
        if not token_match:
            return []
        tail = root.name[token_match.end():]
        tail_match = re.match(self.NAME_TAGS + r"(\..+)?$", tail)
        if not tail_match:
            return []
        own_number = int(token_match.group(1))
        extension = re.escape(tail_match.group(1) or "")
        name_pattern = re.compile(
            re.escape(root.name[:token_match.start()]) + self.DISC_TOKEN.pattern +
            self.NAME_TAGS + extension + "$", re.IGNORECASE)

        candidates = []
        for directory in self._token_sibling_directories(root, own_number):
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for path in entries:
                match = name_pattern.match(path.name)
                if match and int(match.group(1)) != own_number and path != root and path.is_file():
                    candidates.append((int(match.group(1)), path))
        return [path for _, path in sorted(candidates)]

    def _token_sibling_directories(self, root, own_number):
        directories = [root.parent]
        dir_match = self.DISC_TOKEN.search(root.parent.name)
        if dir_match and int(dir_match.group(1)) == own_number:
            # Each disc in its own redump-named directory
            dir_pattern = re.compile(
                re.escape(root.parent.name[:dir_match.start()]) + self.DISC_TOKEN.pattern +
                self.NAME_TAGS + "$", re.IGNORECASE)
            directories += sorted(
                sibling for sibling in root.parent.parent.iterdir()
                if sibling.is_dir() and sibling != root.parent
                and (match := dir_pattern.match(sibling.name)) and int(match.group(1)) != own_number)
        return directories

    def _numbered_name_candidates(self):
        # A sibling must match the disc's path exactly except for the last
        # digit run in the stem (and a matching numbered parent directory).
        # Only digits before the first dot count as a disc number, so
        # digits inside extensions (.7z) are never rewritten
        root = self._root
        stem_end = root.name.find(".")
        stem = root.name[:stem_end] if stem_end > 0 else root.name
        match = re.search(r"(\d+)(?=\D*$)", stem)
        if not match:
            return []
        digits = match.group(1)
        own_number = int(digits)
        name_pre, name_post = root.name[:match.start()], root.name[match.end():]
        parent = root.parent
        dir_match = re.search(r"(\d+)$", parent.name)
        dir_numbered = dir_match is not None and int(dir_match.group(1)) == own_number
        candidates = []
        for number in range(1, MAX_DISC_SEARCH + 1):
            if number == own_number:
                continue
            for num_str in {str(number), str(number).zfill(len(digits))}:
                name = name_pre + num_str + name_post
                directories = [parent]
                if dir_numbered:
                    for dir_num in {str(number), str(number).zfill(len(dir_match.group(1)))}:
                        directories.append(
                            parent.parent / (parent.name[:dir_match.start()] + dir_num))
                for directory in directories:
                    path = directory / name
                    if path != root and path.is_file() and path not in candidates:
                        candidates.append(path)
        return candidates

    def _open_disc(self, path):
        try:
            dir_reader = DirectoryPathReader(path.parent)
            file = dir_reader.get_file(str(path))
            fp = dir_reader.open_file(file)
        except Exception as e:
            LOGGER.warning("Could not open sibling disc %s: %s", path, e)
            return []
        try:
            fp.__enter__()
        except AttributeError:
            pass
        readers = []
        try:
            readers, _ = self.factory.get_iso_path_readers(
                fp, path.name, dir_reader, self.progress_manager)
        except Exception as e:
            LOGGER.warning("Could not read sibling disc %s: %s", path, e)
        if not readers:
            self._close_quietly(fp)
            return []
        self._open_files.append(fp)
        LOGGER.info("Opened sibling disc %s (%s)", path,
                    ", ".join(reader.volume_type for reader in readers))
        return readers
