import fnmatch
import io
import logging
import re

import rarfile

from post_psx.npdrm.path_reader import NPDRMPathReader
from post_psx.npdrm.pkg import Pkg
from utils import pycdlib
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
from pc.processor import PcIsoProcessor
from ps3.path_reader import Ps3PathReader
from psx.processor import PsxIsoProcessor
from psp.processor import PspIsoProcessor
from ps3.processor import Ps3IsoProcessor
from saturn.processor import SaturnIsoProcessor
from megacd.processor import MegaCDIsoProcessor
from p3do.operafs import OperaFs
from utils.archives import ArchiveWrapper
from utils.files import BinWrapper, ConcatenatedFile, OffsetFile, MmappedFile, BinWrapperException
from wii.path_reader import WiiPathReader
from wii.processor import WiiIsoProcessor
from wii.utils.partition import Partition
from wii.utils.wii_iso import WiiISO
from wii.utils.disc import Disc as WiiDisc
from xbox.path_reader import XboxPathReader, XboxStfsPathReader
from xbox.processor import XboxIsoProcessor, Xbox360IsoProcessor, XboxLiveProcessor
from xbox.stfs.stfs import STFS
from xbox.xdvdfs.xdvdfs import XDvdFs

LOGGER = logging.getLogger(__name__)


class IsoProcessorFactory:
    @staticmethod
    def get_iso_path_readers(fp, file_name, parent_container, pbar):
        path_readers = []
        exceptions = {}
        is_ps3 = False

        fp.seek(0)
        magic = fp.read(16)
        compressed_magic_values = [
            b"PK\x03\x04",
            b"7z\xBC\xAF\x27\x1C",
            b"\x1F\x8B",
            b"ustar",
            b"BZh",
            b"\xFD7zXZ\x00",
            b"Rar\x21\x1A\x07",
            b"\x2E/PaxHeaders/\x2E"
        ]
        for magic_to_try in compressed_magic_values:
            if magic.startswith(magic_to_try):
                try:
                    return [CompressedPathReader(ArchiveWrapper(fp, parent_container, pbar), fp, parent_container)], []
                except rarfile.NeedFirstVolume:
                    return [], []
                except Exception as e:
                    if getattr(e, "msg", "").startswith("Passphrase required for this entry"):
                        LOGGER.warning("Error processing %s: %s", file_name, e.msg)
                    elif (getattr(e, "msg", "").startswith("Unrecognized archive format") or
                          getattr(e, "msg", "").startswith('Lzma library error')):
                        if magic_to_try not in [b"\x1F\x8B", b"BZh", b"\xFD7zXZ\x00"]:
                            LOGGER.warning("Error processing %s: %s", file_name, e.msg)
                        elif magic_to_try == b"\x1F\x8B":
                            # gzipped non-archive file. decompress the
                            # file and check for other types of containers
                            fp.seek(0)
                            try:
                                import gzip
                                gzfp = gzip.GzipFile(fileobj=fp, mode="rb")
                                # Test if the file can be ungzipped
                                gzfp.seek(0, io.SEEK_END)
                                fp = gzfp
                                break
                            except ImportError:
                                LOGGER.warning("gzip support not available, not able to decompress %s", file_name)
                            except EOFError:
                                break
                            except Exception as e:
                                if e.__class__.__name__ == "BadGzipFile":
                                    LOGGER.warning("Gzipped file %s could not be decompressed", file_name)
                                    gzfp = None
                                else:
                                    raise
                        elif magic_to_try == b"BZh":
                            # gzipped non-archive file. decompress the
                            # file and check for other types of containers
                            fp.seek(0)
                            try:
                                import bz2
                                fp = bz2.BZ2File(filename=fp, mode="rb")
                                break
                            except ImportError:
                                LOGGER.warning("bz2 support not available, not able to decompress %s", file_name)
                        elif magic_to_try == b"\xFD7zXZ\x00":
                            # gzipped non-archive file. decompress the
                            # file and check for other types of containers
                            fp.seek(0)
                            try:
                                import lzma
                                fp = lzma.LZMAFile(filename=fp, mode="rb")
                                break
                            except ImportError:
                                LOGGER.warning("lzma support not available, not able to decompress %s", file_name)
                    else:
                        exceptions[CompressedPathReader.volume_type] = e

        fp.seek(0)
        if fp.read(4) == b"LIVE" and parent_container.get_file_size(parent_container.get_file(fp.name)) >= 0x971A:
            stfs = STFS(filename=None, fd=fp)
            if stfs.content_type == 0x7000:
                # Not an XBLA archive, actually a GOD game. Process like a concatenated ISO
                offsets = []
                files = []
                current_size = 0
                rule = re.compile(fnmatch.translate(r"*Data[0-9]*"), re.IGNORECASE)
                data_dir = None
                for dir in parent_container.iso_iterator(parent_container.get_root_dir(), recursive=True,
                                                         include_dirs=True):
                    if parent_container.get_file_path(dir).lower().endswith(file_name.lower() + ".data"):
                        data_dir = dir
                        break
                if data_dir:
                    for data_file in parent_container.iso_iterator(data_dir):
                        if not rule.match(parent_container.get_file_path(data_file)):
                            continue
                        offsets.append(current_size)
                        f = parent_container.open_file(data_file)
                        try:
                            f.__enter__()
                        except AttributeError:
                            pass
                        file = BinWrapper(
                            OffsetFile(
                               MmappedFile(f),
                               offset=0x1000,
                               end_pos=parent_container.get_file_size(data_file)
                            ),
                            sector_size=0xCD000,
                            sector_offset=0x1000,
                        )
                        files.append(file)
                        current_size += file.length()
                    if len(files) == 1:
                        fp = files[0]
                    else:
                        fp = ConcatenatedFile(files, offsets)

                    fp.seek(0)
                    if fp.peek(20) == b"MICROSOFT*XBOX*MEDIA":
                        reader = XDvdFs(fp, 0, -stfs.god_offset)
                        try:
                            path_readers.append(XboxPathReader(reader, fp, parent_container))
                        except Exception as e:
                            exceptions[XboxPathReader.volume_type] = e
            else:
                try:
                    stfs.parse_filetable()
                    path_readers.append(XboxStfsPathReader(stfs, fp, parent_container))
                except Exception as e:
                    exceptions[XboxStfsPathReader.volume_type] = e

        if isinstance(fp, io.IOBase):
            try:
                wrapper = BinWrapper(fp)
            except BinWrapperException:
                if not isinstance(fp, MmappedFile):
                    wrapper = MmappedFile(fp)
                else:
                    wrapper = fp
        else:
            wrapper = fp

        wrapper.seek(0)
        if wrapper.peek(4) == b"\x7FPKG":
            try:
                reader = Pkg(wrapper)
                reader.parse_header()
                reader.parse_metadata()
                path_reader = NPDRMPathReader(reader, wrapper, parent_container)
                path_reader.edat_key, path_reader.self_key = path_reader.get_edat_key(pbar)
                path_readers.append(path_reader)
            except Exception as e:
                exceptions[NPDRMPathReader.volume_type] = e

        wrapper.seek(0)
        if wrapper.peek(7) == b"\x01\x5A\x5A\x5A\x5A\x5A\x01" and file_name != "Disc label":
            try:
                reader = OperaFs(wrapper)
                reader.initialize()
                path_readers.append(P3doPathReader(reader, wrapper, parent_container))
            except Exception as e:
                exceptions[P3doPathReader.volume_type] = e

        wrapper.seek(0x1C)
        if wrapper.read(4) == b"\xC2\x33\x9F\x3D":
            try:
                iso = GamecubeISO.from_iso(wrapper)
                path_readers.append(GamecubePathReader(iso, fp, parent_container))
            except Exception as e:
                exceptions[GamecubePathReader.volume_type] = e

        wrapper.seek(0)
        if wrapper.read(64) == b"\x30\x30\x00\x45\x30\x31" + b"\x00" * 26 + \
                b"\x4E\x44\x44\x45\x4D\x4F" + b"\x00" * 26:
            try:
                iso = GamecubeISO.from_iso(wrapper)
                path_readers.append(GamecubePathReader(iso, fp, parent_container))
            except Exception as e:
                exceptions[GamecubePathReader.volume_type] = e

        wrapper.seek(0x18)
        if wrapper.read(4) == b"\x5D\x1C\x9E\xA3":
            try:
                disc = WiiDisc(wrapper)
                for partition_info in disc.partitions:
                    try:
                        if partition_info.type == 0:
                            LOGGER.info("Found data partition index %d on disc %s", partition_info.index, file_name)
                        iso = WiiISO.from_partition(file_name, Partition(disc, partition_info))
                        path_readers.append(WiiPathReader(iso, wrapper, parent_container))
                    except Exception as e:
                        exceptions[f"wii partition {partition_info.volume_group}:{partition_info.index}"] = e
            except Exception as e:
                exceptions["wii"] = e

        # Apple formatted disc
        for offset in [0x430, 0x630]:
            wrapper.seek(offset)
            if wrapper.read(9) == b"Apple_HFS":
                try:
                    volume = Volume()
                    volume.read(wrapper)
                    path_readers.append(HfsPathReader(volume, fp, parent_container))
                except Exception as e:
                    exceptions[HfsPathReader.volume_type] = e

        wrapper.seek(0x800)
        if wrapper.peek(12) == b"PlayStation3":
            is_ps3 = True

        wrapper.seek(0x7068)
        if wrapper.peek(25) == b"PlayStation Master Disc 3":
            is_ps3 = True

        wrapper.seek(0x8001)
        if wrapper.read(5) == b"CD-I ":
            try:
                cdi = Disc(wrapper.mmap, headers=True)
                cdi.read()
                path_readers.append(CdiPathReader(cdi, wrapper.mmap, parent_container))
            except Exception as e:
                exceptions[CdiPathReader.volume_type] = e

        # Xbox and 360 ISO
        possible_locations = [
            0x10000,
            0x2090000,
            0xFDA0000,
            0x18310000,
        ]
        for location_to_check in possible_locations:
            if wrapper.length() > location_to_check + 20:
                wrapper.seek(location_to_check)
                if wrapper.read(20) == b"MICROSOFT*XBOX*MEDIA":
                    try:
                        reader = XDvdFs(wrapper, location_to_check)
                        path_readers.append(XboxPathReader(reader, wrapper, parent_container))
                        break
                    except Exception as e:
                        exceptions[XboxPathReader.volume_type] = e

        found_iso_magic = False
        for magic_offset, magics in [(0, [b"CD001", b"BEA01"]), (8, [b'CDROM'])]:
            wrapper.seek(0x8001 + magic_offset)
            ident = wrapper.read(5)
            if ident in magics:
                found_iso_magic = True
                break

        if not found_iso_magic:
            return path_readers, exceptions

        wrapper.seek(0)

        path_reader_class = PyCdLibPathReader
        if is_ps3:
            path_reader_class = Ps3PathReader

        iso = pycdlib.PyCdlib()
        try:
            iso.open_fp(wrapper)
        except Exception as e:
            # pycdlib may fail on reading the directory contents of an iso, but it should still correctly parse the PVD
            if not hasattr(iso, "pvd") and hasattr(iso, "pvds") and iso.pvds:
                iso.pvd = iso.pvds[0]

            if hasattr(iso, "pvd"):
                iso._initialized = True

            if not iso._initialized:
                wrapper.seek(0x8001)
                if wrapper.read(5) != b"BEA01":
                    exceptions["iso9660"] = e

        if iso._initialized:
            if iso.pvd.root_dir_record.children:
                path_readers.append(path_reader_class(iso, wrapper, parent_container, volume_type="iso9660"))

            if iso.rock_ridge:
                if next((child for child in
                         iso.pvd.root_dir_record.children
                         if not child.is_dot() and child.is_dotdot() and child.rock_ridge), None):
                    path_readers.append(path_reader_class(iso, wrapper, parent_container, volume_type="rock_ridge"))

            if iso.joliet_vd:
                path_readers.append(path_reader_class(iso, wrapper, parent_container, volume_type="joliet"))

            if wrapper.starting_sector == 0 and wrapper.length() > 45000 * iso.logical_block_size:
                hd_addr = 45000 * iso.logical_block_size
                wrapper.seek(hd_addr)
                if wrapper.read(15) == b"SEGA SEGAKATANA":
                    iso_hd = pycdlib.PyCdlib()
                    wrapper_hd = OffsetFile(
                        wrapper,
                        offset=hd_addr,
                        end_pos=wrapper.length()
                    )
                    hd_fp = BinWrapper(ConcatenatedFile(
                        [wrapper_hd, wrapper_hd], [0, hd_addr]
                    ))
                    try:
                        iso_hd.open_fp(hd_fp)
                        path_readers[-1].volume_type = "iso9660 (LD)"
                        path_readers.append(path_reader_class(iso_hd, hd_fp, parent_container, volume_type="iso9660 (HD)"))
                    except Exception as e:
                        exceptions["iso9660 (HD)"] = e

        if iso._has_udf:
            iso = PyCdlibUdf()
            iso.open_fp(wrapper)
            path_readers.append(path_reader_class(iso, wrapper, parent_container, volume_type="udf"))

        if not iso._initialized and not iso._has_udf:
            try:
                iso_accessor = IsoAccessor(wrapper, ignore_susp=True)
                path_readers.append(PathlabPathReader(iso_accessor, wrapper, parent_container, pvd=iso.pvd))
            except Exception as e:
                exceptions[PathlabPathReader.volume_type] = e

        return path_readers, exceptions


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
        elif system_type == "pc":
            return PcIsoProcessor

        return GenericIsoProcessor
