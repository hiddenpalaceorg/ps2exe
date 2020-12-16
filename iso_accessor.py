import datetime

from pathlab import IsoAccessor as _IsoAccessor
from pathlab.iso import SECTOR

class _ScandirIter:
    """
    For compatibility with different python versions.
    Pathlib:
    - prior 3.8 - Use it as an iterator
    - 3.8 - Use it as an context manager
    """

    def __init__(self, iterator):
        self.iterator = iterator

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __iter__(self):
        return self.iterator


class IsoAccessor(_IsoAccessor):
    def _load_children(self, record):
        assert record['type'] == 'dir'
        start = SECTOR * record['sector']
        end = start + record['size']
        self.fileobj.seek(start)
        while self.fileobj.tell() < end:
            if not self.fileobj.peek(1)[0]:
                self._unpack_to_boundary()
                continue
            try:
                yield self._unpack_record()
            except AssertionError:
                self._unpack_to_boundary()
                continue

    def _unpack_time(self, long=False):
        if long:
            s = self.fileobj.read(16).decode('ascii')
            t = datetime.datetime.strptime(s, '%Y%m%d%H%M%S%f')
        else:
            y, m, d, H, M, S = self.fileobj.read(6)

            # For whatever reason, despite the ISO spec, many discs use 0-68 to to
            # represent years between 2000 and 2068, and 69-99 to represent 1969-1999
            if y < 70:
                y += 100

            try:
                t = datetime.datetime(1900 + y, m, d, H, M, S)
            except ValueError:
                t = datetime.datetime.min

        offset = int.from_bytes(self.fileobj.read(1), byteorder="little", signed=True)
        t = t.replace(tzinfo=datetime.timezone(datetime.timedelta(minutes=15 * offset)))
        return t

    def scandir(self, path):
        return _ScandirIter((self.factory(path, name) for name in self.listdir(path)))