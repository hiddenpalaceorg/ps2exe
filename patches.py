import pyisotools.iso

import utils.archives


def apply_patches():
    import pycdlib.dates
    orig_parse = pycdlib.dates.VolumeDescriptorDate.parse
    def parse(self, datestr):
        datestr = datestr.replace(b"\x00\x00", b"00")
        if datestr[15:16] == b"\x00":
            datestr = datestr[0:15] + b"0" + datestr[16:]
        return orig_parse(self, datestr)
    pycdlib.dates.VolumeDescriptorDate.parse = parse

    # Hack to bypass any endian tests in pycdlib
    class mockint(int):
        def __ne__(self, other):
            return False

        def __eq__(self, value):
            return True
    import pycdlib.utils
    orig_swab32bit = pycdlib.utils.swab_32bit
    def swab_32bit(x):
        return mockint(orig_swab32bit(x))

    orig_swab16bit = pycdlib.utils.swab_16bit
    def swab_16bit(x):
        return mockint(orig_swab16bit(x))
    pycdlib.utils.swab_32bit = swab_32bit
    pycdlib.utils.swab_16bit = swab_16bit

    # Hack to keep iso entries in the correct order in pycdlib
    import pycdlib.dr
    import pycdlib.pycdlibexception
    orig_add_child = pycdlib.dr.DirectoryRecord._add_child
    def _add_child(self, child, *args, **kwargs):
        try:
            ret = orig_add_child(self, child, *args, **kwargs)
        except pycdlib.pycdlibexception.PyCdlibInvalidInput:
            # Ignore this duplicate if its exactly the same as what's already in the ISO FS
            # Also allow . and .. to be duplicated as they will be ignored anyway
            if child in self.children or child.is_dot() or child.is_dotdot():
                return
            raise
        try:
            idx = self.children.index(child)
            if idx != len(self.children) - 1:
                self.children.pop(idx)
                self.children.append(child)
        except ValueError:
            pass
        return ret
    pycdlib.dr.DirectoryRecord._add_child = _add_child

    # Hack to track file position on pycdlibio objects when calling readinto
    import pycdlib.pycdlibio
    orig_readinto = pycdlib.pycdlibio.PyCdlibIO.readinto
    def readinto(self, b):
        readsize = orig_readinto(self, b)
        self._offset += readsize
        return readsize
    pycdlib.pycdlibio.PyCdlibIO.readinto = readinto

    def read_string(io, offset: int = 0, maxlen: int = 0, encoding: str = "ascii") -> str:
        """ Reads a null terminated string from the specified address """

        length = 0

        io.seek(offset)
        while io.read(1) != b"\x00" and (length < maxlen or maxlen <= 0):
            length += 1

        io.seek(offset)
        return io.read(length).decode(encoding, errors="ignore")
    pyisotools.iso.read_string = read_string

    def init_from_iso(self, _rawISO):
        from pyisotools.boot import Boot
        from pyisotools.bi2 import BI2
        from pyisotools.apploader import Apploader
        from dolreader.dol import DolFile
        from pyisotools.bnrparser import BNR
        from pyisotools.fst import FSTNode
        from io import BytesIO
        from fnmatch import fnmatch

        _rawISO.seek(0)
        self.bootheader = Boot(_rawISO)
        self.bootinfo = BI2(_rawISO)
        self.apploader = Apploader(_rawISO)
        self.dol = DolFile(_rawISO, startpos=self.bootheader.dolOffset)
        _rawISO.seek(self.bootheader.fstOffset)
        self._rawFST = BytesIO(_rawISO.read(self.bootheader.fstSize))

        self.load_file_systemv(self._rawFST)

        if self.bootinfo.countryCode == BI2.Country.JAPAN:
            region = BNR.Regions.JAPAN
        else:
            region = self.bootinfo.countryCode - 1

        bnrNode = None
        for child in self.children:
            if child.is_file() and fnmatch(child.path, "*opening.bnr"):
                bnrNode = child
                break

        if bnrNode:
            _rawISO.seek(bnrNode._fileoffset)
            self.bnr = BNR.from_data(
                _rawISO, region=region, size=bnrNode.size)
        else:
            self.bnr = None

        prev = FSTNode.file("", None, self.bootheader.fstSize,
                            self.bootheader.fstOffset)
        for node in self.nodes_by_offset():
            alignment = self._detect_alignment(node, prev)
            if alignment != 4:
                self._alignmentTable[node.path] = alignment
            prev = node
    pyisotools.iso.GamecubeISO.init_from_iso = init_from_iso

    import machfs.main
    import struct

    from machfs import File, Folder, bitmanip, btree
    from machfs.main import _link_aliases, _get_every_extent
    # Patches the read function to allow more lazy data loading and add additional attributes
    def read(self, from_volume):
        offset = 0
        from_volume.seek(0x400)
        while part_data := from_volume.read(512):
            partition_magic, partition_start = struct.unpack(">2s6xL500x", part_data)
            if partition_magic != b'PM':
                break
            partition_start *= 512
            if partition_start:
                if from_volume[partition_start + 1024:partition_start + 1024 + 2] == b'H+':
                    raise ValueError('HFS+ not supported')
                if from_volume[partition_start+1024:partition_start+1024+2] == b'BD':
                    offset = partition_start
                    break
        if not offset:
            for i in range(0, len(from_volume), 512):
                if from_volume[i + 1024:i + 1024 + 2] == b'H+':
                    raise ValueError('HFS+ not supported')
                if from_volume[i+1024:i+1024+2] == b'BD':
                    if i:
                        # Test offset
                        offset = i
                        drSigWord, drCrDate, drLsMod, drAtrb, drNmFls, \
                        drVBMSt, drAllocPtr, drNmAlBlks, drAlBlkSiz, drClpSiz, drAlBlSt, \
                        drNxtCNID, drFreeBks, drVN, drVolBkUp, drVSeqNum, \
                        drWrCnt, drXTClpSiz, drCTClpSiz, drNmRtDirs, drFilCnt, drDirCnt, \
                        drFndrInfo, drVCSize, drVBMCSize, drCtlCSize, \
                        drXTFlSize, drXTExtRec, \
                        drCTFlSize, drCTExtRec, \
                            = struct.unpack('>2sLLHHHHHLLHLH28pLHLLLHLL32sHHHL12sL12s',
                                            from_volume[1024 + offset:1024 + offset + 162])
                        try:
                            drVN.decode("mac_roman")
                        except UnicodeDecodeError:
                            continue
                    break
            else:
                raise ValueError('Magic number not found in image')

        drSigWord, drCrDate, drLsMod, drAtrb, drNmFls, \
        drVBMSt, drAllocPtr, drNmAlBlks, drAlBlkSiz, drClpSiz, drAlBlSt, \
        drNxtCNID, drFreeBks, drVN, drVolBkUp, drVSeqNum, \
        drWrCnt, drXTClpSiz, drCTClpSiz, drNmRtDirs, drFilCnt, drDirCnt, \
        drFndrInfo, drVCSize, drVBMCSize, drCtlCSize, \
        drXTFlSize, drXTExtRec, \
        drCTFlSize, drCTExtRec, \
        = struct.unpack('>2sLLHHHHHLLHLH28pLHLLLHLL32sHHHL12sL12s', from_volume[1024 + offset:1024 + offset + 162])

        self.crdate, self.mddate, self.bkdate = drCrDate, drLsMod, drVolBkUp
        self.name = drVN.decode('mac_roman')

        block2offset = lambda block: 512*drAlBlSt + drAlBlkSiz*block
        getextentscontents = lambda extents: b''.join(from_volume[offset + block2offset(firstblk):offset + block2offset(firstblk+blkcnt)] for (firstblk, blkcnt) in extents)
        getextents = lambda size, extrec1, cnid, fork: _get_every_extent((size+drAlBlkSiz-1)//drAlBlkSiz, extrec1, cnid, extoflow, fork)
        getfork = lambda size, extrec1, cnid, fork: getextentscontents(_get_every_extent((size+drAlBlkSiz-1)//drAlBlkSiz, extrec1, cnid, extoflow, fork))[:size]

        extoflow = {}
        for rec in btree.dump_btree(getfork(drXTFlSize, drXTExtRec, 3, 'data')):
            if rec[0] != 7: continue
            xkrFkType, xkrFNum, xkrFABN, extrec = struct.unpack_from('>xBLH12s', rec)
            if xkrFkType == 0xFF:
                fork = 'rsrc'
            elif xkrFkType == 0:
                fork = 'data'
            extoflow[xkrFNum, fork, xkrFABN] = extrec

        cnids = {}
        childlist = [] # list of (parent_cnid, child_name, child_object) tuples

        prev_key = None
        for rec in btree.dump_btree(getfork(drCTFlSize, drCTExtRec, 4, 'data')):
            # create a directory tree from the catalog file
            rec_len = rec[0]
            if rec_len == 0: continue

            key = rec[2:1+rec_len]
            val = rec[bitmanip.pad_up(1+rec_len, 2):]

            ckrParID, namelen = struct.unpack_from('>LB', key)
            ckrCName = key[5:5+namelen]

            datatype = (None, 'dir', 'file', 'dthread', 'fthread')[val[0]]
            datarec = val[2:]

            if datatype == 'dir':
                dirFlags, dirVal, dirDirID, dirCrDat, dirMdDat, dirBkDat, dirUsrInfo, dirFndrInfo \
                = struct.unpack_from('>HHLLLL16s16s', datarec)

                f = Folder()
                cnids[dirDirID] = f
                childlist.append((ckrParID, ckrCName, f))

                f.crdate, f.mddate, f.bkdate = dirCrDat, dirMdDat, dirBkDat

            elif datatype == 'file':
                filFlags, filTyp, filUsrWds, filFlNum, \
                filStBlk, filLgLen, filPyLen, \
                filRStBlk, filRLgLen, filRPyLen, \
                filCrDat, filMdDat, filBkDat, \
                filFndrInfo, filClpSize, \
                filExtRec, filRExtRec, \
                = struct.unpack_from('>BB16sLHLLHLLLLL16sH12s12sxxxx', datarec)

                f = File()
                cnids[filFlNum] = f
                childlist.append((ckrParID, ckrCName, f))

                f.crdate, f.mddate, f.bkdate = filCrDat, filMdDat, filBkDat
                f.type, f.creator, f.flags, f.x, f.y = struct.unpack_from('>4s4sHHH', filUsrWds)

                extents = getextents(filLgLen, filExtRec, filFlNum, 'data')
                if extents:
                    f.start_lba = block2offset(extents[0][0]) // 2048
                else:
                    f.start_lba = 0
                f.size = filLgLen

                f.data = getfork(filLgLen, filExtRec, filFlNum, 'data')
                f.rsrc = getfork(filRLgLen, filRExtRec, filFlNum, 'rsrc')

        for parent_cnid, child_name, child_obj in childlist:
            if parent_cnid != 1:
                parent_obj = cnids[parent_cnid]
                parent_obj[child_name] = child_obj

        self.update(cnids[2])

        self.pop('Desktop', None)
        self.pop('Desktop DB', None)
        self.pop('Desktop DF', None)

        _link_aliases(drCrDate, cnids)
    machfs.main.Volume.read = read

    import rarfile
    import os
    orig_open_unrar = rarfile.CommonParser._open_unrar
    def _open_unrar(self, rarfile, inf, pwd=None, tmpfile=None, force_file=False):
        if not tmpfile or force_file:
            inf.filename = inf.filename.replace("\\", os.path.sep)
        return orig_open_unrar(self, rarfile, inf, pwd=pwd, tmpfile=tmpfile, force_file=force_file)
    rarfile.CommonParser._open_unrar = _open_unrar

    orig_check = rarfile.RarExtFile._check
    def _check(self):
        try:
            orig_check(self)
        except rarfile.BadRarFile as e:
            if self._remain != 0:
                raise
            from utils.archives import LOGGER
            LOGGER.exception(e)
    rarfile.RarExtFile._check = _check

    from libarchive.exception import ArchiveError
    import libarchive.ffi
    orig_check_int = libarchive.ffi.check_int
    def check_int(retcode, func, args):
        try:
            return orig_check_int(retcode, func, args)
        except ArchiveError as e:
            if e.errno == 0:
                return libarchive.ffi.ARCHIVE_EOF
            if getattr(libarchive, "current_file_path", None):
                e.msg += f" file: {libarchive.current_file_path}"
            errors_to_allow = [
                "ZIP compressed data is wrong size",
                "ZIP decompression failed",
                "Decompression failed",
                "ZIP bad CRC",
                "Truncated input file",
            ]
            for error in errors_to_allow:
                if e.msg.startswith(error):
                    libarchive.ffi.logger.warning(e.msg)
                    return libarchive.ffi.ARCHIVE_WARN
            raise
    libarchive.ffi.read_data.errcheck = check_int

    def check_int_header(retcode, func, args):
        try:
            return check_int(retcode, func, args)
        except ArchiveError as e:
            if e.msg.startswith("Damaged 7-Zip archive"):
                libarchive.ffi.logger.warning(e.msg)
                return libarchive.ffi.ARCHIVE_WARN
            raise

    libarchive.ffi.read_next_header2.errcheck = check_int_header

    import zipfile
    orig_decodeExtra = zipfile.ZipInfo._decodeExtra
    def _decodeExtra(self):
        try:
            orig_decodeExtra(self)
        except zipfile.BadZipfile:
            pass
    zipfile.ZipInfo._decodeExtra = _decodeExtra

    import gzip
    def _read_eof(self):
        # Same as parent but checking for FF padding as well as 00
        crc32, isize = struct.unpack("<II", self._read_exact(8))
        if crc32 != self._crc:
            raise gzip.BadGzipFile("CRC check failed %s != %s" % (hex(crc32),
                                                             hex(self._crc)))
        elif isize != (self._stream_size & 0xffffffff):
            raise gzip.BadGzipFile("Incorrect length of data produced")

        c = b"\x00"
        while c in [b"\x00", b"\xff"]:
            c = self._fp.read(1)
        if c:
            self._fp.prepend(c)

    gzip._GzipReader._read_eof = _read_eof
