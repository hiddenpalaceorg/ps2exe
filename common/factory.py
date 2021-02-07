import io
import logging
import os
import sys

import pycdlib

from cdi.path_reader import CdiPathReader
from common.iso_path_reader.methods.compressed import CompressedPathReader
from common.iso_path_reader.methods.pathlab import PathlabPathReader
from common.iso_path_reader.methods.pycdlib import PyCdLibPathReader
from common.processor import GenericIsoProcessor
from dreamcast.processor import DreamcastIsoProcessor
from iso_accessor import IsoAccessor

from cdi.processor import CdiIsoProcessor
from cdi.utils import Disc
from p3do.path_reader import P3doPathReader
from p3do.processor import P3doIsoProcessor
from cd32.processor import CD32IsoProcessor
from psx.processor import PsxIsoProcessor
from psp.processor import PspIsoProcessor
from ps3.processor import Ps3IsoProcessor
from saturn.processor import SaturnIsoProcessor
from megacd.processor import MegaCDIsoProcessor
from p3do.operafs import OperaFs
from utils.files import BinWrapper
from xbox.path_reader import XboxPathReader
from xbox.processor import XboxIsoProcessor, Xbox360IsoProcessor
from xbox.xdvdfs.xdvdfs import XDvdFs

try:
    import libarchive
except TypeError:
    libarchive_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "libarchive")
    if os.name == "nt":
        if sys.maxsize > 2**32:
            libarchive_path = os.path.join(libarchive_path, "win64", "libarchive.dll")
        else:
            libarchive_path = os.path.join(libarchive_path, "win32", "libarchive.dll")
    elif sys.platform == "linux":
        libarchive_path = os.path.join(libarchive_path, "linux", "libarchive.so")
    elif sys.platform == "darwin":
        libarchive_path = os.path.join(libarchive_path, "macosx", "libarchive.dylib")

    os.environ["LIBARCHIVE"] = libarchive_path
    import libarchive

LOGGER = logging.getLogger(__name__)


class IsoProcessorFactory:
    @staticmethod
    def get_iso_path_reader(fp, file_name):
        file_ext = os.path.splitext(file_name)[1]
        if file_ext in [b".7z", b".rar", b".zip"]:
            with libarchive.file_reader(fp.name) as archive:
                return CompressedPathReader(archive, fp)

        if isinstance(fp, io.IOBase):
            wrapper = BinWrapper(fp)
        else:
            wrapper = fp

        wrapper.seek(0)
        if wrapper.peek(7) == b"\x01\x5A\x5A\x5A\x5A\x5A\x01":
            reader = OperaFs(wrapper)
            reader.initialize()
            return P3doPathReader(reader, wrapper)

        wrapper.seek(0x8001)
        if wrapper.read(5) == b"CD-I ":
            cdi = Disc(fp, headers=True, scrambled=wrapper.is_scrambled)
            cdi.read()
            return CdiPathReader(cdi, fp)

        # Redump-style dual layer DVD
        if wrapper.length() == 7825162240:
            wrapper.seek(0x18310000)
            if wrapper.peek(20) == b"MICROSOFT*XBOX*MEDIA":
                reader = XDvdFs(wrapper, 0x18310000)
                return XboxPathReader(reader, wrapper)
        # 360 ISO
        # Scene releases are the following sizes:
        # 7,572,881,408 bytes: Xtreme 3.0 rip
        # 7,835,492,352 or 7,834,892,288 bytes: SplitVid rip
        elif wrapper.length() in [7572881408, 7835492352, 7834892288]:
            wrapper.seek(0xFDA0000)
            if wrapper.peek(20) == b"MICROSOFT*XBOX*MEDIA":
                reader = XDvdFs(wrapper, 0xFDA0000)
                return XboxPathReader(reader, wrapper)
        wrapper.seek(0x10000)
        if wrapper.peek(20) == b"MICROSOFT*XBOX*MEDIA":
            reader = XDvdFs(wrapper, 0x10000)
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
            if not hasattr(iso, "pvd") and hasattr(iso, "pvds") and iso.pvds:
                iso.pvd = iso.pvds[0]

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

        return GenericIsoProcessor

