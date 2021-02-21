def apply_patches():
    import pycdlib.dates
    orig_parse = pycdlib.dates.VolumeDescriptorDate.parse
    def parse(self, datestr):
        datestr = datestr.replace(b"\x00\x00", b"00")
        if datestr[15:16] == b"\x00":
            datestr = datestr[0:15] + b"0" + datestr[16:]
        return orig_parse(self, datestr)
    pycdlib.dates.VolumeDescriptorDate.parse = parse