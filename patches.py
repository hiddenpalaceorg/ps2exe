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

    import machfs.main
    import struct

    from machfs import File, Folder, bitmanip, btree
    from machfs.main import _link_aliases, _get_every_extent
    # Patches the read function to allow more lazy data loading and add additional attributes
    def read(self, from_volume):
        offset = 0
        from_volume.seek(0x400)
        partition_start, = struct.unpack(">8xL", from_volume.read(12))
        partition_start *= 512
        if partition_start:
            if from_volume[partition_start + 1024:partition_start + 1024 + 2] == b'H+':
                raise ValueError('HFS+ not supported')
            if from_volume[partition_start+1024:partition_start+1024+2] == b'BD':
                offset = partition_start
        if not offset:
            for i in range(0, len(from_volume), 512):
                if from_volume[i + 1024:i + 1024 + 2] == b'H+':
                    raise ValueError('HFS+ not supported')
                if from_volume[i+1024:i+1024+2] == b'BD':
                    if i:
                        offset = i
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
