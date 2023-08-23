import io
import logging
import os
from pathlib import Path

import pycdlib
from pycdlib.pycdlibexception import PyCdlibInvalidInput
from pyisotools.iso import GamecubeISO

from cdi.path_reader import CdiPathReader
from common.iso_path_reader.methods.compressed import CompressedPathReader
from common.iso_path_reader.methods.hfs import HfsPathReader
from common.iso_path_reader.methods.pathlab import PathlabPathReader
from common.iso_path_reader.methods.pycdlib import PyCdLibPathReader
from common.processor import GenericIsoProcessor
from common.udf.pycdlib_udf import PyCdlibUdf
from dreamcast.processor import DreamcastIsoProcessor
from gamecube.path_reader import GamecubePathReader
from gamecube.processor import GamecubeIsoProcessor
from iso_accessor import IsoAccessor
from machfs import Volume, Folder, File

from cdi.processor import CdiIsoProcessor
from cdi.utils import Disc
from p3do.path_reader import P3doPathReader
from p3do.processor import P3doIsoProcessor
from cd32.processor import CD32IsoProcessor
from ps3.path_reader import Ps3PathReader
from psx.processor import PsxIsoProcessor
from psp.processor import PspIsoProcessor
from ps3.processor import Ps3IsoProcessor
from saturn.processor import SaturnIsoProcessor
from megacd.processor import MegaCDIsoProcessor
from p3do.operafs import OperaFs
from utils.archives import ArchiveWarapper
from utils.files import BinWrapper, ConcatenatedFile
from wii.path_reader import WiiPathReader
from wii.processor import WiiIsoProcessor
from wii.utils.wii_iso import WiiISO
from wii.utils.disc import Disc as WiiDisc
from xbox.path_reader import XboxPathReader, XboxStfsPathReader
from xbox.processor import XboxIsoProcessor, Xbox360IsoProcessor, XboxLiveProcessor
from xbox.stfs.stfs import STFS
from xbox.xdvdfs.xdvdfs import XDvdFs

LOGGER = logging.getLogger(__name__)


class IsoProcessorFactory:
    @staticmethod
    def get_iso_path_reader(fp, file_name):
        file_ext = os.path.splitext(file_name)[1].decode()
        if file_ext.lower() in [".7z", ".rar", ".zip"]:
            with ArchiveWarapper(fp.name) as archive:
                return CompressedPathReader(archive, fp)

        fp.seek(0)
        if fp.read(4) == b"LIVE":
            stfs = STFS(filename=None, fd=fp)
            if stfs.content_type == 0x7000:
                # Not an XBLA archive, actually a GOD game. Process like a concatenated ISO
                offsets = []
                files = []
                current_size = 0
                data_files = Path(f"{fp.name}.data").rglob("Data*")
                for file in data_files:
                    offsets.append(current_size)
                    file = BinWrapper(file.open("rb"), sector_size=0xCD000, sector_offset=0x1000, start_offset=0x1000)
                    files.append(file)
                    current_size += file.length()
                fp = ConcatenatedFile(files, offsets)
            else:
                stfs.parse_filetable()
                return XboxStfsPathReader(stfs, fp)

        if isinstance(fp, io.IOBase):
            wrapper = BinWrapper(fp)
        else:
            wrapper = fp

        wrapper.seek(0)
        if wrapper.peek(7) == b"\x01\x5A\x5A\x5A\x5A\x5A\x01":
            reader = OperaFs(wrapper)
            reader.initialize()
            return P3doPathReader(reader, wrapper)

        wrapper.seek(0x1C)
        if wrapper.read(4) == b"\xC2\x33\x9F\x3D":
            iso_path = Path(fp.name).resolve()
            iso = GamecubeISO.from_iso(iso_path)
            return GamecubePathReader(iso, fp)

        wrapper.seek(0)
        if wrapper.read(64) == b"\x30\x30\x00\x45\x30\x31" + b"\x00" * 26 + \
                b"\x4E\x44\x44\x45\x4D\x4F" + b"\x00" * 26:
            iso_path = Path(fp.name).resolve()
            iso = GamecubeISO.from_iso(iso_path)
            return GamecubePathReader(iso, fp)

        wrapper.seek(0x18)
        if wrapper.read(4) == b"\x5D\x1C\x9E\xA3":
            disc = WiiDisc(wrapper)
            iso = WiiISO.from_disc(fp.name, disc)
            return WiiPathReader(iso, fp)

        # Apple formatted disc
        wrapper.seek(0x430)
        if wrapper.read(9) == b"Apple_HFS":
            try:
                volume = Volume()
                volume.read(wrapper)
                return HfsPathReader(volume, fp)
            except ValueError:
                pass

        wrapper.seek(0x800)
        if wrapper.peek(12) == b"PlayStation3":
            iso = PyCdlibUdf()
            try:
                iso.open_fp(wrapper)
                return Ps3PathReader(iso, wrapper)
            except:
                if iso.udf_teas:
                    raise

        wrapper.seek(0x7068)
        if wrapper.peek(25) == b"PlayStation Master Disc 3":
            iso = PyCdlibUdf()
            try:
                iso.open_fp(wrapper)
                return Ps3PathReader(iso, wrapper)
            except:
                if iso.udf_teas:
                    raise

        wrapper.seek(0x8001)
        if wrapper.read(5) == b"CD-I ":
            cdi = Disc(fp, headers=True, scrambled=wrapper.is_scrambled)
            cdi.read()
            return CdiPathReader(cdi, fp)

        # Xbox and 360 ISO
        if wrapper.length() > 65556:
            wrapper.seek(0x10000)
            if wrapper.peek(20) == b"MICROSOFT*XBOX*MEDIA":
                reader = XDvdFs(wrapper, 0x10000)
                return XboxPathReader(reader, wrapper)
        if wrapper.length() > 34144276:
            wrapper.seek(0x2090000)
            if wrapper.peek(20) == b"MICROSOFT*XBOX*MEDIA":
                reader = XDvdFs(wrapper, 0x2090000)
                return XboxPathReader(reader, wrapper)
        if wrapper.length() > 265945108:
            wrapper.seek(0xFDA0000)
            if wrapper.peek(20) == b"MICROSOFT*XBOX*MEDIA":
                reader = XDvdFs(wrapper, 0xFDA0000)
                return XboxPathReader(reader, wrapper)
        # Redump-style dual layer DVD
        if wrapper.length() > 405864468:
            wrapper.seek(0x18310000)
            if wrapper.peek(20) == b"MICROSOFT*XBOX*MEDIA":
                reader = XDvdFs(wrapper, 0x18310000)
                return XboxPathReader(reader, wrapper)

        wrapper.seek(0)

        iso = pycdlib.PyCdlib()
        try:
            iso.open_fp(wrapper)
            return PyCdLibPathReader(iso, wrapper)
        except Exception:
            # pycdlib may fail on reading the directory contents of an iso, but it should still correctly parse the PVD
            if not hasattr(iso, "pvd") and not hasattr(iso, "pvds"):
                return
            if hasattr(iso, "pvd") and iso.pvd.root_dir_record.children:
                iso._initialized = True
                try:
                    iso.get_record(iso_path="/test_path_that_does_not_exist")
                except PyCdlibInvalidInput:
                    return PyCdLibPathReader(iso, wrapper)
                except:
                    pass
            if not iso.pvds and not iso._has_udf:
                return
            if not hasattr(iso, "pvd") and hasattr(iso, "pvds") and iso.pvds:
                iso.pvd = iso.pvds[0]

        if iso._has_udf:
            iso = PyCdlibUdf()
            iso.open_fp(wrapper)
            return PyCdLibPathReader(iso, wrapper, udf=True)
        else:
            iso_accessor = IsoAccessor(wrapper, ignore_susp=True)
            return PathlabPathReader(iso_accessor, wrapper, pvd=iso.pvd)


    @staticmethod
    def get_iso_processor_class(system_type):
        if system_type == "cdi":
            return CdiIsoProcessor
        elif system_type in ["ps1", "ps2"]:
            return PsxIsoProcessor
        elif system_type == "saturn":
            return SaturnIsoProcessor
        elif system_type == "megacd":
            return MegaCDIsoProcessor
        elif system_type == "psp":
            return PspIsoProcessor
        elif system_type == "ps3":
            return Ps3IsoProcessor
        elif system_type == "3do":
            return P3doIsoProcessor
        elif system_type == "cd32":
            return CD32IsoProcessor
        elif system_type == "xbox":
            return XboxIsoProcessor
        elif system_type == "xbox360":
            return Xbox360IsoProcessor
        elif system_type == "dreamcast":
            return DreamcastIsoProcessor
        elif system_type == "gamecube":
            return GamecubeIsoProcessor
        elif system_type == "wii":
            return WiiIsoProcessor
        elif system_type == "xbla":
            return XboxLiveProcessor

        return GenericIsoProcessor

