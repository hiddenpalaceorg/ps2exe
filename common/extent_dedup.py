import logging
import os

LOGGER = logging.getLogger(__name__)


class ScannedContainer:
    # One completed scan of a byte range, and the rows it produced
    def __init__(self, dedup, key, src_reader, src_path, namespace_log, start_idx):
        self.dedup = dedup
        self.key = key
        self.src_reader = src_reader
        self.src_path = src_path
        self.src_chain = src_reader.volume_type_chain
        self.namespace_log = namespace_log
        self.start_idx = start_idx
        self.end_idx = None

    def finish(self, remember=True):
        self.src_reader.end_namespace_recording()
        self.end_idx = len(self.dedup.rows)
        if remember:
            self.dedup.scans.setdefault(self.key, []).append(self)


class ExtentDedup:
    # Which byte ranges inside one container have already been scanned, so other
    # references to the same ranges can reuse that scan instead of repeating it.
    # Volume views of one image list the same files under different names, so
    # each view still gets its own rows, they just aren't scanned again
    def __init__(self, rows, enabled=True):
        self.rows = rows
        self.enabled = enabled
        self.scans = {}

    def child(self):
        # Scans are only reusable within the container they were found in
        return ExtentDedup(self.rows, self.enabled)

    def key_for(self, path_reader, file):
        if not self.enabled:
            return None
        extents = path_reader.get_file_extents(file)
        if extents is None:
            # this filesystem can't say which bytes the file occupies
            return None
        return (id(path_reader.fp), extents)

    def reusable_scan(self, key, path_reader):
        if key is None:
            return None
        for scan in self.scans.get(key, ()):
            # same bytes, but only the same content if every name the scan looked
            # up in its own view resolves the same way in this one
            if path_reader.namespace_replays(scan.namespace_log, scan.src_reader):
                return scan
        return None

    def begin_scan(self, key, path_reader, nested_path):
        if key is None:
            return None
        return ScannedContainer(self, key, path_reader, nested_path,
                                path_reader.begin_namespace_recording(), len(self.rows))

    def reuse(self, scan, path_reader, file_path, nested_path):
        if scan.end_idx > scan.start_idx:
            LOGGER.info("Container %s has the same extents as %s, reusing its scan",
                        nested_path, scan.src_path)
        new_chain = path_reader.volume_type_chain
        new_name = os.path.basename(file_path).encode("cp1252", errors="replace").decode("cp1252")
        for row in self.rows[scan.start_idx:scan.end_idx]:
            new_row = dict(row)
            # rows of the whole subtree, renamed to how this view reaches them
            if new_row["path"] == scan.src_path:
                new_row["name"] = new_name
            new_row["path"] = nested_path + new_row["path"][len(scan.src_path):]
            new_row["parent_volume_type"] = new_chain + new_row["parent_volume_type"][len(scan.src_chain):]
            self.rows.append(new_row)
