import io
import logging

import pycdlib

from bin_wrapper import BinWrapper
from cdi.path_reader import CdiPathReader
from common.iso_path_reader.methods.pathlab import PathlabPathReader
from common.iso_path_reader.methods.pycdlib import PyCdLibPathReader
from common.processor import GenericIsoProcessor
from iso_accessor import IsoAccessor

from cdi.processor import CdiIsoProcessor
from cdi.utils import Disc
from p3do.path_reader import P3doPathReader
from p3do.processor import P3doIsoProcessor
from psx.processor import PsxIsoProcessor
from psp.processor import PspIsoProcessor
from saturn.processor import SaturnIsoProcessor
from megacd.processor import MegaCDIsoProcessor
from scrambled_wrapper import ScrambleWrapper
from p3do.operafs import OperaFs

LOGGER = logging.getLogger(__name__)


class IsoProcessorFactory:
    @staticmethod
    def get_iso_path_reader(fp):
        if isinstance(fp, io.IOBase):
            wrapper = BinWrapper(fp)
        else:
            wrapper = fp

        wrapper.seek(0x28)
        if wrapper.peek(6) == b"CD-ROM":
            reader = OperaFs(wrapper)
            reader.initialize()
            return P3doPathReader(reader, wrapper)

        wrapper.seek(0x8001)
        if wrapper.read(5) == b"CD-I ":
            cdi = Disc(fp, headers=True, scrambled=isinstance(wrapper.fp, ScrambleWrapper))
            cdi.read()
            return CdiPathReader(cdi, fp)

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
        elif system_type == "3do":
            return P3doIsoProcessor

        return GenericIsoProcessor

