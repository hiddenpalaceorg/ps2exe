import argparse
import csv
import pathlib
import sqlite3
import xml.etree.ElementTree as ET

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-d',
                        '--datfile',
                        help="Redump dat file",
                        type=str,
                        required=True,
                        default=argparse.SUPPRESS)

    parser.add_argument('-k',
                        '--keyfolder',
                        help="Folder containing Redump key files",
                        type=str,
                        required=True,
                        default=argparse.SUPPRESS)

    parser.add_argument('-l',
                        '--dev-klics',
                        help="dev_klics.txt file",
                        type=str,
                        required=False,
                        default=argparse.SUPPRESS)

    parser.add_argument('-r',
                        '--rap-dir',
                        help="Directory containing rap files",
                        type=str,
                        required=False,
                        default=argparse.SUPPRESS)

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

    key_dir = pathlib.Path(args.keyfolder)

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


