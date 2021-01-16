"""
These classes handles XDBF files (Xbox 360 Database Files) such as the Gamer Profile Data (GPD) files.
"""

import struct


class Language:
    def __init__(self, data, byte_order='>'):
        self.magic = struct.unpack(byte_order + '4s', data[0:4])[0]
        self.version = struct.unpack(byte_order + 'I', data[4:8])[0]
        self.size = struct.unpack(byte_order + 'I', data[8:12])[0]
        self.default_language = struct.unpack(byte_order + 'I', data[12:16])[0]


class StringTable:
    def __init__(self, data, byte_order='>'):
        self.magic = struct.unpack(byte_order + '4s', data[0:4])[0]
        self.version = struct.unpack(byte_order + 'I', data[4:8])[0]
        self.size = struct.unpack(byte_order + 'I', data[8:12])[0]
        self.string_count = struct.unpack(byte_order + 'H', data[12:14])[0]
        self.strings = {}
        pos = 14
        for string in range(self.string_count):
            string_id = struct.unpack(byte_order + 'H', data[pos:pos+2])[0]
            string_length = struct.unpack(byte_order + 'H', data[pos+2:pos+4])[0]
            string_data = data[pos+4:pos+4+string_length]
            self.strings[string_id] = string_data
            pos = pos + 4 + string_length
        return



class Setting:
    """ Represents a Setting entry
        Some values can be resolved by matching them against constant objects
        See contents.GPDID, contents.GamerTagConstants
    """

    def __init__(self, data, byte_order='>'):
        self.content_id = ord(data[8])
        self.setting_id = struct.unpack(byte_order + 'I', data[0:4])[0]

        if self.content_id == 0:  # Context
            self.data = struct.unpack(byte_order + "I", data[16:20])[0]

        elif self.content_id == 1:  # Unsigned Integer
            self.data = struct.unpack(byte_order + "I", data[16:20])[0]

        elif self.content_id == 2:  # Long long
            self.data = struct.unpack(byte_order + "Q", data[16:24])[0]

        elif self.content_id == 3:  # Double
            self.data = struct.unpack(byte_order + "d", data[16:24])[0]

        elif self.content_id == 4:  # UTF16-BE
            length = struct.unpack(byte_order + "I", data[16:20])[0]
            self.data = str(data[24:24 + length], 'utf-16-be')

        elif self.content_id == 5:  # Float
            self.data = struct.unpack(byte_order + "f", data[16:20])[0]

        elif self.content_id == 6:  # Binary
            length = struct.unpack(byte_order + "I", data[16:20])[0]
            self.data = data[24:24 + length]

        elif self.content_id == 7:  # Timestamp
            self.data = struct.unpack(byte_order + "Q", data[16:24])[0]

        else:  # Null
            self.data = data[9:17]


class Title:
    """ Represents a title entry
        Includes the name, last played time and achievement stats
    """

    def __str__(self):
        result = ["GPD Title"]
        result.append(self.get_name())
        result.append(hex(self.title_id))
        return " ".join(result)

    def __init__(self, data, byte_order='>'):
        self.title_id = struct.unpack(byte_order + 'I', data[0:4])[0]
        self.achievement_count = struct.unpack(byte_order + 'i', data[4:8])[0]
        self.achievement_unlocked = struct.unpack(byte_order + 'i', data[8:12])[0]
        self.gamerscore_total = struct.unpack(byte_order + 'i', data[12:16])[0]
        self.gamerscore_unlocked = struct.unpack(byte_order + 'i', data[16:20])[0]
        self.unknown1 = struct.unpack(byte_order + 'q', data[20:28])[0]
        self.unknown2 = struct.unpack(byte_order + 'i', data[28:32])[0]
        self.last_played = struct.unpack(byte_order + 'q', data[32:40])[0]
        end_name = 40 + data[40:].find(b'\x00\x00')
        self.name = data[40:end_name]

    # Due to intermittent unicode problems I decided to store the data raw and convert it only when needed
    def get_name(self):
        """ Convert the name from utf-16-be data in a raw string to a unicode object """
        if self.name:
            return str(self.name, 'utf-16-be')
        else:
            return ''


class Achievement:
    """ Achievement entry object
        Includes name, descriptions and unlock time
    """
    def __str__(self):
        result = ["GPD Achievement"]
        if self.achievement_id:
            result.append(hex(self.achievement_id))
        result.append(self.get_name())
        return " ".join(result)

    def __init__(self, data, byte_order = '>'):
        self.achievement_id = None
        self.image_id = None
        self.gamer_score = None
        self.flags = None
        self.unlock_time = None
        self.name = None
        self.locked_desc = None
        self.unlocked_desc = None
        self.magic = struct.unpack(byte_order + 'I', data[0:4])[0]
        if self.magic != 28 or len(data) < 28:
            return
        self.achievement_id = struct.unpack(byte_order + 'I', data[4:8])[0]
        self.image_id = struct.unpack(byte_order + 'I', data[8:12])[0]
        self.gamer_score = struct.unpack(byte_order + 'I', data[12:16])[0]
        self.flags = struct.unpack(byte_order + 'I', data[16:20])[0]
        # self.unlock_time = xboxtime.filetime2unixtime(struct.unpack(byte_order + 'q', data[20:28])[0])

        end_name = 28 + data[28:].find('\x00\x00')
        self.name = data[28:end_name]
        end_locked_desc = end_name + 2 + data[end_name+2:].find('\x00\x00') #+2 to skip previous null
        self.locked_desc = data[end_name+2:end_locked_desc]
        end_unlocked_desc = end_locked_desc + 2 + data[end_locked_desc+2:].find('\x00\x00')
        self.unlocked_desc = data[end_locked_desc+2:end_unlocked_desc]

    def get_name(self):
        """ Convert the name from utf-16-be data in a raw string to a unicode object """
        if self.name:
            return str(self.name, 'utf-16-be')
        else:
            return ''

    def get_locked_desc(self):
        """ Convert the locked description from utf-16-be data in a raw string to a unicode object """
        if self.locked_desc:
            return str(self.locked_desc, 'utf-16-be')
        else:
            return ''

    def get_unlocked_desc(self):
        """ Convert the unlocked description from utf-16-be data in a raw string to a unicode object """
        if self.unlocked_desc:
            return str(self.unlocked_desc, 'utf-16-be')
        else:
            return ''

class Entry:
    """ Entry object which describes where to find the data inside the file and its payload type
        The namespace class member maps namespace numbers to data type
    """

    def __str__(self):
        return "GPD Entry: %s %s" % (hex(self.idnum), Entry.namespaces[self.namespace])

    def __init__(self, xdbf, data, global_offset, fd, byte_order='>'):
        self.namespace = struct.unpack(byte_order + 'H', data[0:2])[0]
        self.idnum = struct.unpack(byte_order + 'Q', data[2:10])[0]
        self.offset = struct.unpack(byte_order + 'I', data[10:14])[0]
        self.length = struct.unpack(byte_order + 'I', data[14:18])[0]
        self.payload = None

        if self.length <= 0:
            return

        fd.seek(self.offset + global_offset)
        paydata = fd.read(self.length)
        if self.namespace == 1:
            if paydata[:4] == b"XSTC" or paydata[:4] == b"XSRC":
                xdbf.spa = True
                if paydata[:4] == b"XSTC":
                    self.payload = Language(paydata, byte_order)
                return
            elif paydata[:4] == b"XACH" and len(paydata) > 28:
                self.payload = Achievement(paydata, byte_order)
        elif self.namespace == 4:
            if len(paydata) > 40:
                self.payload = Title(paydata, byte_order)
            else:
                return
        elif self.namespace == 3:
            if xdbf.spa:
                self.payload = StringTable(paydata, byte_order)
            elif len(paydata) > 20:
                self.payload = Setting(paydata, byte_order)
        else:
            self.payload = paydata


class XDBF:
    """
        Main object representing a GPD/XDBF archive
        Contains dictionaries that map id numbers to entries
        achievements, images, strings, titles, settings
        These can also be accessed via the list of Entry objects and their payload member
    """

    def __init__(self, fd):
        self.fd = fd
        self.spa = False
        data = self.fd.read(0x18)

        if data[:4] == b"\x58\x44\x42\x46":  # XDBF
            self.byte_order = '>'
        elif data[:4] == b"\x46\x42\x44\x58":  # FBDX
            self.byte_order = '<'
        else:
            raise AssertionError("XDBF Magic Not Found")

        self.version = struct.unpack(self.byte_order + 'I', data[4:8])[0]
        self.table_len = struct.unpack(self.byte_order + 'I', data[8:12])[0]
        self.entry_count = struct.unpack(self.byte_order + 'I', data[12:16])[0]
        self.free_len = struct.unpack(self.byte_order + 'I', data[16:20])[0]
        self.free_count = struct.unpack(self.byte_order + 'I', data[20:24])[0]
        self.global_offset = self.table_len * 0x12 + self.free_len * 0x8 + 0x18

        self.default_language = 0
        self.entries = []
        self.achievements = {}
        self.images = {}
        self.settings = {}
        self.titles = {}
        self.strings = {}
        self.string_table = {}
        self.process_entries()
        self.fd.close()

    def process_entries(self):
        """ Populates the entries list and the various payload dictionaries """
        for c in range(0, self.entry_count):
            self.fd.seek(0x18 + 0x12 * c, 0)
            data = self.fd.read(0x12)
            e = Entry(self, data, self.global_offset, self.fd, self.byte_order)
            self.entries.append(e)

            if e.payload:
                if isinstance(e.payload, Achievement):
                    self.achievements[e.idnum] = e.payload
                if isinstance(e.payload, Language):
                    self.default_language = e.payload.default_language
                elif e.namespace == 2:
                    self.images[e.idnum] = e.payload
                elif e.namespace == 3:
                    if self.spa:
                        self.string_table[e.idnum] = e.payload
                    else:
                        self.settings[e.idnum] = e.payload
                elif e.namespace == 4:
                    self.titles[e.idnum] = e.payload
                elif e.namespace == 5:
                    self.strings[e.idnum] = e.payload
