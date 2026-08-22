import argparse
import csv
import pathlib
import sqlite3
import struct
import xml.etree.ElementTree as ET
import zlib

from Crypto.Cipher import AES

# IRD format: https://www.psdevwiki.com/ps3/IRD
IRD_MAGIC = b"3IRD"
GZIP_MAGIC = b"\x1f\x8b"

D1_AES_KEY = bytes.fromhex("380bcf0b53455b3c7817ab4fa3ba90ed")
D1_AES_IV = bytes.fromhex("69474772af6fdab342743aefaa186287")

SECTOR_SIZE = 2048
PVD_VOLUME_SPACE_SIZE_OFFSET = 16 * SECTOR_SIZE + 80

PIC_SIZE = 115


class IrdError(ValueError):
    pass


class Ird:
    def __init__(self, version, title_id, title, header, data1):
        self.version = version
        self.title_id = title_id
        self.title = title
        self.header = header
        self.data1 = data1

    @property
    def disc_key(self):
        return AES.new(D1_AES_KEY, AES.MODE_CBC, D1_AES_IV).encrypt(self.data1)

    @property
    def disc_size(self):
        if len(self.header) < PVD_VOLUME_SPACE_SIZE_OFFSET + 4:
            return None
        sectors, = struct.unpack_from("<I", self.header, PVD_VOLUME_SPACE_SIZE_OFFSET)
        return sectors * SECTOR_SIZE


def gunzip(data):
    return zlib.decompressobj(zlib.MAX_WBITS | 32).decompress(data)


class IrdReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, size):
        if self.pos + size > len(self.data):
            raise IrdError("IRD file ended after {} of {} bytes".format(
                len(self.data) - self.pos, size))
        chunk = self.data[self.pos:self.pos + size]
        self.pos += size
        return chunk

    def read_byte(self):
        return self.read(1)[0]

    def unpack(self, fmt):
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))[0]

    def read_string(self, size):
        return self.read(size).decode("ascii", errors="replace").rstrip("\x00 ")

    def read_prefixed_string(self):
        # BinaryWriter length prefix: 7 bits of length per byte, low byte first
        length = 0
        for shift in range(0, 35, 7):
            byte = self.read_byte()
            length |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
        else:
            raise IrdError("Invalid string length prefix")
        return self.read(length).decode("utf-8", errors="replace")

    def read_compressed(self):
        return gunzip(self.read(self.unpack("<i")))


def parse_ird(data, verify_crc=True):
    if data[:4] != IRD_MAGIC and data[:2] == GZIP_MAGIC:
        try:
            data = gunzip(data)
        except zlib.error as e:
            raise IrdError("Could not decompress IRD file: {}".format(e))
    if data[:4] != IRD_MAGIC:
        raise IrdError("Not an IRD file")

    reader = IrdReader(data)
    reader.read(4)
    version = reader.read_byte()
    if not 6 <= version <= 9:
        raise IrdError("Unsupported IRD version {}".format(version))

    title_id = reader.read_string(9)
    title = reader.read_prefixed_string()
    reader.read(4 + 5 + 5)  # PS3 system version, game version, app version
    if version == 7:
        reader.read(4)  # id
    header = reader.read_compressed()
    reader.read_compressed()  # footer

    reader.read(reader.read_byte() * 16)  # one MD5 per region
    reader.read(reader.unpack("<i") * 24)  # sector and MD5 of every file
    reader.read(4)

    # The PIC moved in front of the keys in v9
    if version == 9:
        reader.read(PIC_SIZE)
    data1 = reader.read(16)
    reader.read(16)  # data2
    if version < 9:
        reader.read(PIC_SIZE)
    reader.read(4)  # uid

    crc32_offset = reader.pos
    stored_crc32 = reader.unpack("<I")
    if verify_crc:
        crc32 = zlib.crc32(data[:crc32_offset]) & 0xFFFFFFFF
        if crc32 != stored_crc32:
            raise IrdError("Corrupt IRD file, expected CRC32 {:08x}, got {:08x}".format(
                stored_crc32, crc32))

    return Ird(version, title_id, title, header, data1)


def parse_ird_file(path, verify_crc=True):
    return parse_ird(pathlib.Path(path).read_bytes(), verify_crc=verify_crc)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-d',
                        '--datfile',
                        help="Redump dat file",
                        type=str,
                        default=None)

    parser.add_argument('-k',
                        '--keyfolder',
                        help="Folder containing Redump key files",
                        type=str,
                        default=None)

    parser.add_argument('-i',
                        '--ird-dir',
                        help="Directory containing .ird files, searched recursively",
                        type=str,
                        default=None)

    parser.add_argument('-l',
                        '--dev-klics',
                        help="dev_klics.txt file",
                        type=str,
                        default=None)

    parser.add_argument('-r',
                        '--rap-dir',
                        help="Directory containing rap files",
                        type=str,
                        default=None)

    parser.add_argument('-o',
                        '--output',
                        help="Output directory",
                        type=str,
                        default=str(((pathlib.Path(__file__).parent / 'post_psx').absolute())))

    parser.add_argument('-t',
                        '--tsv',
                        help="PS3/PSP_GAMES.TSV file path",
                        nargs='+',
                        action='append',
                        type=str)

    parser.add_argument('-a',
                        '--append',
                        help="Append to db instead of overwriting it",
                        action='store_true',
                        default=False)

    args = parser.parse_args()

    if bool(args.datfile) != bool(args.keyfolder):
        parser.error("--datfile and --keyfolder have to be given together")
    if not any((args.datfile, args.ird_dir, args.dev_klics, args.rap_dir, args.tsv)):
        parser.error("no key source given")

    db_file = pathlib.Path(args.output) / 'keys.db'
    if not args.append:
        db_file.unlink(missing_ok=True)
    db = sqlite3.connect(db_file)
    c = db.cursor()
    try:
        c.execute("BEGIN")
        c.execute("""
        CREATE TABLE IF NOT EXISTS keys (name TEXT, size TEXT, crc32 TEXT, md5 TEXT, sha1 TEXT, key BLOB, UNIQUE (size, md5, sha1, key));
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS dev_klics (key BLOB, title_id TEXT, name TEXT, UNIQUE(key, title_id));
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS raps (key BLOB, title_id TEXT, UNIQUE(key));
        """)

        if args.datfile:
            key_dir = pathlib.Path(args.keyfolder)
            key_list = []
            datfile = ET.parse(args.datfile)
            root = datfile.getroot()
            games = root.findall('.//game')
            for game in games:
                game_name = game.attrib['name']
                rom = game.find('.//rom')
                key_file = (key_dir / (game_name + ".key"))
                if not key_file.exists():
                    print("Could not find key for game " + game_name)
                    continue
                with key_file.open("rb") as kf:
                    key = kf.read()
                    if len(key) == 32:
                        key = bytes.fromhex(key.decode("ascii"))
                key_list.append((
                    game_name,
                    rom.attrib['size'],
                    rom.attrib['crc'],
                    rom.attrib['md5'],
                    rom.attrib['sha1'],
                    key)
                )
            c.executemany("""
                INSERT OR IGNORE INTO keys VALUES (?, ?, ?, ?, ?, ?)""", key_list)

        if args.ird_dir:
            ird_keys = {}
            ird_files = sorted(pathlib.Path(args.ird_dir).rglob("*.ird"))
            for ird_file in ird_files:
                try:
                    ird = parse_ird_file(ird_file)
                except (IrdError, OSError) as e:
                    print("Could not read IRD file {}: {}".format(ird_file, e))
                    continue
                if ird.disc_size is None:
                    print("IRD file {} has no volume descriptor, skipping".format(ird_file))
                    continue
                ird_keys[(str(ird.disc_size), ird.disc_key)] = ird_file.stem
            new_keys = [
                (name, size, '', '', '', key)
                for (size, key), name in ird_keys.items()
                if not c.execute(
                    "SELECT 1 FROM keys WHERE size = ? AND key = ?", [size, key]
                ).fetchone()
            ]
            print("Found {} new keys in {} IRD files".format(len(new_keys), len(ird_files)))
            c.executemany("""
                INSERT OR IGNORE INTO keys VALUES (?, ?, ?, ?, ?, ?)""", new_keys)

        if args.dev_klics:
            klics = []
            dev_klics = pathlib.Path(args.dev_klics)
            if dev_klics.exists():
                with dev_klics.open("r") as f:
                    for line in f:
                        if line.startswith("-"):
                            continue
                        entry = line.strip().split(' ', maxsplit=2)
                        if len(entry) != 3 or len(entry[0]) != 32 or len(entry[1]) != 36:
                            continue

                        klics.append((
                            bytes.fromhex(entry[0]),
                            entry[1],
                            entry[2]
                        ))
            if klics:
                c.executemany("""
                    INSERT OR IGNORE INTO dev_klics VALUES (?, ?, ?)""", klics)

        raps = set()
        if args.rap_dir:
            rap_dir = pathlib.Path(args.rap_dir)
            if rap_dir.exists():
                for rap_file in rap_dir.glob("*.rap"):
                    with rap_file.open("rb") as f:
                        rap_data = f.read()
                        if len(rap_data) == 256:
                            rap_data = rap_data[:16]
                        title_id = rap_file.stem
                        raps.add((
                            rap_data,
                            title_id
                        ))
            if raps:
                c.executemany("""
                    INSERT OR IGNORE INTO raps VALUES (?, ?)""", raps)

        if args.tsv:
            for tsv in args.tsv:
                tsv_path = pathlib.Path(tsv[0])
                if tsv_path.exists():
                    with tsv_path.open("r", encoding="utf-8") as infile:
                        reader = csv.DictReader(infile, delimiter="\t")
                        for row in reader:
                            if row["RAP"] and row["Content ID"] and len(row["RAP"]) == 32 and len(row["Content ID"]) == 36:
                                raps.add((
                                    bytes.fromhex(row["RAP"]),
                                    row["Content ID"]
                                ))
        if raps:
            c.executemany("""
                INSERT OR IGNORE INTO raps VALUES (?, ?)""", list(raps))

        c.execute("COMMIT")
    except:
        c.execute("ROLLBACK")
        raise


