import argparse
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

    parser.add_argument('-o',
                        '--output',
                        help="Output directory",
                        type=str,
                        default=str(((pathlib.Path(__file__).parent / 'ps3').absolute())))

    args = parser.parse_args()

    key_dir = pathlib.Path(args.keyfolder)

    db_file = pathlib.Path(args.output) / 'keys.db'
    db_file.unlink(missing_ok=True)
    db = sqlite3.connect(db_file)
    c = db.cursor()
    try:
        c.execute("BEGIN")
        c.execute("""
        CREATE TABLE keys (name TEXT, size TEXT, crc32 TEXT, md5 TEXT, sha1 TEXT, key BLOB);
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
            INSERT INTO keys VALUES (?, ?, ?, ?, ?, ?)""", key_list)
        c.execute("COMMIT")
    except:
        c.execute("ROLLBACK")
        raise


