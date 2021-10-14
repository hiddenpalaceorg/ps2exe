"""
# The data in these tables were mostly sourced from Free60 and various forums and tools.
# In particular the tool Le Fluffie was helpful
# Some data has been verified, some changed and some has yet to be used.
"""

class STFSHashInfo(object):
    """ Whether the block represented by the BlockHashRecord is used, free, old or current """
    types = {
            0x00: "Unused",
            0x40: "Freed",
            0x80: "Old",
            0xC0: "Current"
            }
    types_list = ["Unused", "Allocated Free", "Allocated In Use Old", "Allocated In Use Current"]

class ContentTypes:
    """ STFS Content Types mapping """
    types = {
        0xD0000:  "Arcade Title",
        0x9000:   "Avatar Item",
        0x40000:  "Cache File",
        0x2000000:    "Community Game",
        0x80000:  "Game Demo",
        0x20000:  "Gamer Picture",
        0xA0000:  "Game Title",
        0xC0000:  "Game Trailer",
        0x400000:     "Game Video",
        0x4000:   "Installed Game",
        0xB0000:  "Installer",
        0x2000:   "IPTV Pause Buffer",
        0xF0000:  "License Store",
        0x2:  "Marketplace Content",
        0x100000:     "Movie",
        0x300000:     "Music Video",
        0x500000:     "Podcast Video",
        0x10000:  "Profile",
        0x3:  "Publisher",
        0x1:  "Saved Game",
        0x50000:  "Storage Download",
        0x30000:  "Theme",
        0x200000:     "TV",
        0x90000:  "Video",
        0x600000:     "Viral Video",
        0x70000:  "Xbox Download",
        0x5000:   "Xbox Original Game",
        0x60000:  "Xbox Saved Game",
        0x1000:   "Xbox 360 Title",
        0x5000:   "Xbox Title",
        0xE0000:  "XNA"
    }
