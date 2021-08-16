import pyisotools.iso


def apply_patches():
    import pycdlib.dates
    orig_parse = pycdlib.dates.VolumeDescriptorDate.parse
    def parse(self, datestr):
        datestr = datestr.replace(b"\x00\x00", b"00")
        if datestr[15:16] == b"\x00":
            datestr = datestr[0:15] + b"0" + datestr[16:]
        return orig_parse(self, datestr)
    pycdlib.dates.VolumeDescriptorDate.parse = parse

    def read_string(io, offset: int = 0, maxlen: int = 0, encoding: str = "ascii") -> str:
        """ Reads a null terminated string from the specified address """

        length = 0

        io.seek(offset)
        while io.read(1) != b"\x00" and (length < maxlen or maxlen <= 0):
            length += 1

        io.seek(offset)
        return io.read(length).decode(encoding, errors="ignore")
    pyisotools.iso.read_string = read_string