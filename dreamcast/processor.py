import fnmatch
import logging
import os
import pathlib
import re
from os.path import basename

from common.processor import BaseIsoProcessor
from utils.files import ConcatenatedFile, MmappedFile, BinWrapper

LOGGER = logging.getLogger(__name__)


class DreamcastIsoProcessor(BaseIsoProcessor):
    def __init__(self, iso_path_reader, iso_filename, *args):
        from common.factory import IsoProcessorFactory
        if iso_path_reader.fp.starting_sector == 0:
            super().__init__(iso_path_reader, iso_filename, *args)
            return
        file_dir = pathlib.Path(iso_filename).parent.absolute()
        found = False
        # Try to find a gdi file in this directory
        rule = re.compile(fnmatch.translate("*.gdi"), re.IGNORECASE)
        for i in [os.path.join(file_dir, name) for name in os.listdir(file_dir) if rule.match(name)]:
            i = pathlib.Path(i)
            tracks = self.parse_gdi(i)
            if basename(iso_filename) not in [track["file_name"] for track in tracks]:
                continue
            fp = self.get_fp_from_gdi(i, tracks)
            gdi_name = i.name.encode("cp1252", errors="replace")
            iso_path_reader = IsoProcessorFactory.get_iso_path_reader(fp, gdi_name)
            found = True

        if found:
            super().__init__(iso_path_reader, iso_filename, *args)
            return

        # No gdi file found, try a cue file
        rule = re.compile(fnmatch.translate("*.cue"), re.IGNORECASE)
        for i in [os.path.join(file_dir, name) for name in os.listdir(file_dir) if rule.match(name)]:
            i = pathlib.Path(i)
            tracks = self.parse_cue(i)
            if not any(track["file_name"] != basename(iso_filename) for track in tracks):
                continue
            fp = self.get_fp_from_gdi(i, tracks)
            gdi_name = i.name.encode("cp1252", errors="replace")
            iso_path_reader = IsoProcessorFactory.get_iso_path_reader(fp, gdi_name)

        super().__init__(iso_path_reader, iso_filename, *args)


    def parse_gdi(self, gdi_file):
        with gdi_file.open() as f:
            text = f.read()
            lines = text.splitlines()

            _n_tracks = int(lines.pop(0))

            tracks = []
            for track_i, line in enumerate(lines):
                match = re.match(r" *?(?P<index>\d+) +(?P<sector>\d+) +(?P<type>\d+) +(?P<sector_size>\d+)"
                                 r" +\"?(?P<file_name>[^\"\n]+)\"? +(\d+)", line)


                track = match.groupdict()

                for key in ("index", "sector", "type", "sector_size"):
                    track[key] = int(track[key])


                tracks.append(track)
        return tracks

    def get_fp_from_gdi(self, gdi_file, tracks):
        data_tracks = [tracks[2]]
        if len(tracks) > 3:
            data_tracks.append(tracks.pop())

        # Duplicate track 3 as offset 0 to fool the iso parser to see it as a normal iso with the PVD at 0x8000
        offsets = [0]
        files = [BinWrapper(
            MmappedFile(open(gdi_file.parent / data_tracks[0]["file_name"], "rb")),
            sector_size=data_tracks[0]["sector_size"],
            sector_offset=16 if data_tracks[0]["sector_size"] == 2352 else 0,
        )]
        for track in data_tracks:
            offsets.append(int(track["sector"]) * 2048)
            files.append(
                BinWrapper(
                    open(gdi_file.parent / track["file_name"], "rb"),
                    sector_size=track["sector_size"],
                    sector_offset=16 if track["sector_size"] == 2352 else 0,
                )
            )

        return ConcatenatedFile(files, offsets)

    def parse_cue(self, cue_file):
        with cue_file.open() as f:
            text = f.read()
            lines = text.splitlines()

            tracks = []
            sector = 0
            track = {}
            for line in lines:
                if line == "REM SINGLE-DENSITY AREA":
                    continue
                if line == "REM HIGH-DENSITY AREA":
                    sector = 45000
                if match := re.match(r"FILE \"?(?P<file_name>[^\"\n]+)\"?", line):
                    if track:
                        if track["index"] != 2:
                            sector += int((cue_file.parent / track["file_name"]).stat().st_size / track["sector_size"])
                        tracks.append(track)
                    track = match.groupdict()
                    track["sector"] = sector
                if match := re.match(r" *?TRACK (?P<index>\d+) (?P<type>.*)", line):
                    track.update(match.groupdict())
                    track["index"] = int(track["index"])
                    if track["type"] == "MODE1/2352":
                        track["type"] = 0
                    elif track["type"] == "AUDIO":
                        track["type"] = 4
                    track["sector_size"] = 2352
            tracks.append(track)
        return tracks

    def get_disc_type(self):
        return {"disc_type": "gdr"}

    def get_exe_filename(self):
        self.iso_path_reader.fp.seek(0x60)
        exe_name = self.iso_path_reader.fp.read(16)
        return "/" + exe_name.decode("ascii").strip()

    def get_extra_fields(self):
        fp = self.iso_path_reader.fp
        fp.seek(0x20)
        header_info = {
            "header_device_info": fp.read(16),
            "header_regions": fp.read(8),
        }
        fp.seek(0x40)
        header_info.update({
            "header_product_number": fp.read(10),
            "header_product_version": fp.read(6),
            "header_release_date": fp.read(8),
        })
        fp.seek(0x70)
        header_info.update({
            "header_maker_id": fp.read(16),
            "header_title": fp.read(128),
        })

        header_info = {
            header_key: header_item.decode(errors="replace").strip()
            for header_key, header_item in header_info.items()
        }

        return header_info
