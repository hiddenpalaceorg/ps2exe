import io
import threading


class FakeMemoryMap(object):
    def __init__(self, f):
        self._lock = threading.Lock()
        self._file = f
        with self._lock:
            f.seek(0, io.SEEK_END)
            self._size = f.tell()
            f.seek(0)

    def __len__(self):
        return self._size

    def __getitem__(self, key):
        with self._lock:
            save_pos = self._file.tell()
            try:
                if not isinstance(key, slice):
                    if key < 0:
                        key += self._size
                    if not (0 <= key < self._size):
                        raise IndexError('fake mmap index out of range')
                    self._file.seek(key)
                    return ord(self._file.read(1))
                step = 1 if key.step is None else key.step
                if step > 0:
                    start = min(self._size, max(0, (
                        0 if key.start is None else
                        key.start + self._size if key.start < 0 else
                        key.start
                        )))
                    stop = min(self._size, max(0, (
                        self._size if key.stop is None else
                        key.stop + self._size if key.stop < 0 else
                        key.stop
                        )))
                    self._file.seek(start)
                    if start >= stop:
                        return b''
                    return self._file.read(stop - start)[::step]
                elif step < 0:
                    start = min(self._size, max(0, (
                        -1 if key.stop is None else
                        key.stop + self._size if key.stop < 0 else
                        key.stop
                        ) + 1))
                    stop = min(self._size, max(0, (
                        self._size - 1 if key.start is None else
                        key.start + self._size if key.start < 0 else
                        key.start
                        ) + 1))
                    self._file.seek(start)
                    if start >= stop:
                        return b''
                    return self._file.read(stop - start)[::-1][::-step]
                else:
                    raise ValueError('slice step cannot be zero')
            finally:
                self._file.seek(save_pos)

    def __setitem__(self, index, value):
        self._read_only()

    def read(self, num):
        with self._lock:
            return self._file.read(num)

    def readline(self):
        with self._lock:
            return self._file.readline()

    def seek(self, pos, whence=io.SEEK_SET):
        with self._lock:
            self._file.seek(pos, whence)
            return self._file.tell()

    def size(self):
        return self._size

    def tell(self):
        with self._lock:
            return self._file.tell()

    def close(self):
        self._file.close()