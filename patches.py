def apply_patches():
    import pycdlib.dates
    orig_parse = pycdlib.dates.VolumeDescriptorDate.parse
    def parse(self, datestr):
        datestr = datestr.replace(b"\x00\x00", b"00")
        return orig_parse(self, datestr)
    pycdlib.dates.VolumeDescriptorDate.parse = parse