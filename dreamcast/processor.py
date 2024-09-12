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
        self.iso_path_reader = iso_path_reader
        file_dir = self.iso_path_reader.parent_container.get_file(str(pathlib.Path(iso_filename).parent))
        found = False
        iso_filename = basename(iso_filename)
        # Try to find a gdi file in this directory
        rule = re.compile(fnmatch.translate("*.gdi"), re.IGNORECASE)
        for i in [entry for entry in iso_path_reader.parent_container.iso_iterator(file_dir)
                  if rule.match(iso_path_reader.parent_container.get_file_path(entry))]:
            if not (tracks := self.parse_gdi(self.iso_path_reader.parent_container.get_file_path(i), iso_filename)):
                continue
            if basename(iso_filename) not in [track["file_name"] for track in tracks]:
                continue
            fp = self.get_fp_from_gdi(i, tracks)
            if not fp:
                continue
            gdi_name = basename(iso_path_reader.parent_container.get_file_path(i)).encode("cp1252", errors="replace")
            iso_path_readers, exceptions = IsoProcessorFactory.get_iso_path_readers(fp, gdi_name, *args)
            if not iso_path_readers:
                break
            iso_path_reader = iso_path_readers[0]
            found = True
            break

        if found:
            super().__init__(iso_path_reader, iso_filename, *args)
            return

        # No gdi file found, try a cue file
        rule = re.compile(fnmatch.translate("*.cue"), re.IGNORECASE)
        for i in [entry for entry in iso_path_reader.parent_container.iso_iterator(file_dir)
                  if rule.match(iso_path_reader.parent_container.get_file_path(entry))]:
            if not (tracks := self.parse_cue(self.iso_path_reader.parent_container.get_file_path(i), iso_filename)):
                continue
            if not any(track["file_name"] != basename(iso_filename) for track in tracks):
                continue
            fp = self.get_fp_from_gdi(i, tracks)
            if not fp:
                continue
            cue_name = basename(iso_path_reader.parent_container.get_file_path(i)).encode("cp1252", errors="replace")
            iso_path_readers, exceptions = IsoProcessorFactory.get_iso_path_readers(fp, cue_name, *args)
            if not iso_path_readers:
                break
            iso_path_reader = iso_path_readers[0]
            break

        super().__init__(iso_path_reader, iso_filename, *args)

    def parse_gdi(self, gdi_path, iso_filename):
        gdi_file = self.iso_path_reader.parent_container.get_file(gdi_path)
        with self.iso_path_reader.parent_container.open_file(gdi_file) as f:
            try:
                text = f.read().decode()
            except UnicodeDecodeError:
                return
            lines = text.splitlines()

            _n_tracks = int(lines.pop(0))

            tracks = []
            found_iso = False
            for track_i, line in enumerate(lines):
                match = re.match(r" *?(?P<index>\d+) +(?P<sector>(?:\d+|\[fix\])) +(?P<type>\d+) +(?P<sector_size>\d+)"
                                 r" +\"?(?P<file_name>[^\"\n]+)\"? +(\d+)", line)


                track = match.groupdict()

                for key in ("index", "sector", "type", "sector_size"):
                    # Fix for DIC's placeholder track 2
                    if key == "sector" and track[key] == "[fix]":
                        track[key] = 0
                    else:
                        track[key] = int(track[key])

                if track["file_name"] == iso_filename:
                    found_iso = True

                tracks.append(track)
        if found_iso:
            return tracks

    def get_fp_from_gdi(self, gdi_file, tracks):
        if len(tracks) < 3:
            data_tracks = [tracks[0]]
        else:
            data_tracks = [tracks[2]]

        if len(tracks) > 3:
            data_tracks.append(tracks.pop())

        gdi_path = self.iso_path_reader.parent_container.get_file_path(gdi_file)
        gdi_dir = pathlib.Path(gdi_path).parent
        try:
            track_file = self.iso_path_reader.parent_container.get_file(str(gdi_dir / data_tracks[0]["file_name"]))
        except FileNotFoundError:
            return

        # Duplicate track 3 as offset 0 to fool the iso parser to see it as a normal iso with the PVD at 0x8000
        track = BinWrapper(
            MmappedFile(self.iso_path_reader.parent_container.open_file(track_file)),
            sector_size=data_tracks[0]["sector_size"],
            sector_offset=16 if data_tracks[0]["sector_size"] == 2352 else 0,
            virtual_sector_size=2048
        )
        track.starting_sector = 0
        offsets = [0]
        files = [track]
        try:
            for track in data_tracks:
                track_file = self.iso_path_reader.parent_container.get_file(str(gdi_dir / track["file_name"]))
                offsets.append(int(track["sector"]) * 2048)
                track = BinWrapper(
                        MmappedFile(self.iso_path_reader.parent_container.open_file(track_file)),
                        sector_size=track["sector_size"],
                        sector_offset=16 if track["sector_size"] == 2352 else 0,
                        virtual_sector_size=2048
                    )
                track.starting_sector = 0
                files.append(track)
        except FileNotFoundError:
            return

        return ConcatenatedFile(files, offsets)

    def parse_cue(self, cue_path, iso_filename):
        cue_file = self.iso_path_reader.parent_container.get_file(cue_path)
        with self.iso_path_reader.parent_container.open_file(cue_file) as f:
            cue_dir = str(pathlib.Path(cue_path).parent)
            text = f.read().decode()
            lines = text.splitlines()

            tracks = []
            sector = 0
            track = {}
            found_iso = False
            for line in lines:
                if line == "REM SINGLE-DENSITY AREA":
                    continue
                if line == "REM HIGH-DENSITY AREA":
                    sector = 45000
                if match := re.match(r"FILE \"?(?P<file_name>[^\"\n]+)\"?", line):
                    if track:
                        if track["index"] != 2:
                            file = self.iso_path_reader.parent_container.get_file(str(pathlib.Path(cue_dir) / track["file_name"]))
                            sector += int(self.iso_path_reader.parent_container.get_file_size(file) / track["sector_size"])
                        tracks.append(track)
                    track = match.groupdict()
                    if track["file_name"] == iso_filename:
                        if self.iso_path_reader.fp.starting_sector:
                            sector = self.iso_path_reader.fp.starting_sector
                        found_iso = True
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

        # Check if this is a dic-style scm/img file
        if len(tracks) == 1:
            if (self.iso_path_reader.get_file_sector(self.iso_path_reader.get_root_dir())) == 45020:
                tracks[0]["sector"] = 45000

        if found_iso:
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

