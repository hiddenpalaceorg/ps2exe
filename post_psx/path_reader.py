import pathlib
import sqlite3


class PostPsxPathReader:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = None
        db_file = pathlib.Path(__file__).parent / "keys.db"
        if not db_file.exists():
            return
        self.db = sqlite3.connect(db_file)
