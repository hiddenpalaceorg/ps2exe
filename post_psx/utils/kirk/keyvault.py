"""KIRK command 4/7 key vault.

The 128 AES-128 keys a command 4 or 7 header selects through its `keyseed` byte, indexed
by that byte. Command 4 may only use the first 64; command 7 may use all of them.

AMCTRL asks for four: 0x38 and 0x3A for BBMac, 0x39 for the BBCipher data hash and 0x63
for the BBCipher keystream. The rest are unused here but the table is indexed by seed, so
it has to be complete.
"""

KIRK_4_7_KEYS = tuple(bytes.fromhex(key) for key in (
    "2c92e5902b86c106b72eea6cd4ec7248",  # 0x00
    "058dc80b33a5bf9d5698fae0d3715e1f",
    "b813c35ec64441e3dc3c16f5b45e6484",
    "9802c4e6ec9e9e2ffc634ce42fbb4668",
    "99244cd258f51bcbb0619ca73830075f",
    "0225d7ba63ecb94a9d237601b3f6ac17",
    "6099f28170560e5f747cb520c0cdc23c",
    "76368b438f77d87efe5fb6115939885c",
    "14a115eb434a1ba4905e03b617a15c04",  # 0x08
    "e65803d9a71aa87f059d229daf5453d0",
    "ba3480b428a7ca5f216412f70fbb7323",
    "72ad35ac9ac3130a778cb19d88550b0c",
    "8485c848750843bc9b9aeca79c7f6018",
    "b5b16ede23a97b0ea17cdba2dcdec46e",
    "c871fdb3bcc5d2f2e2d7729ddf826882",
    "0abb336c96d4cdd8cb5f4be0badb9e03",
    "32295bd5eaf7a34216c88e48ff50d371",  # 0x10
    "46f25e8e4d2aa540730bc46e47ee6f0a",
    "5dc71139d01938bc027fdddcb0837d9d",
    "51dd65f071a4e5ea6aaf12194129b8f4",
    "03763c6865c69b0ffe8fd8eea43616a0",
    "7d50b85caf6769f0e54aa8098b0ebe1c",
    "72684b32ac3b332f2a7afc9e14d56f6b",
    "201d31964ad99fbf32d5d61c491bd9fc",
    "f8d84463d610d12a448e9690a6bb0bad",  # 0x18
    "5cd4057fa13060440ad9b6745f244f4e",
    "f48ad678599c22c1d411933df845b893",
    "cae7d287a2ecc1cd94542b5e1d9488b2",
    "de26d37a39956c2ad8c3a6af21ebb301",
    "7cb68b4da38d1dd932679ca99ffb2852",
    "a0b556b469ab368f36dec9092ecb41b1",
    "939de19b725feee2452abc1706d14769",
    "a4a4e621382ef1af7b177ae842ad0031",  # 0x20
    "c37f13e8cf84db34747bc3a0f19d3a73",
    "2bf7838ad898e95fa5f901da61fe35bb",
    "c704621e714a66ea62e04b203db8c2e5",
    "c933859aab00cdce4d8b8e9f3de6c00f",
    "1842561f2b5f34e3513eb78977431a65",
    "dcb0a0065a50a14e59ac973f1758a3a3",
    "c4dbae83e29cf254a3dd374e807bf425",
    "bfaeeb498265c57c64b8c17e19064409",  # 0x28
    "797cecc3b3ee0ac03bd8e6c1e0a8b1a4",
    "7534fe0bd6d0c28d68d4e02ae7d5d155",
    "fab35326974f4edfe4c3a814c32f0f88",
    "ec97b386b433c6bf4e539d95ebb979e4",
    "b320a204cf480629b5dd8efc98d4177b",
    "5dfc0d4f2c39da684a3374ed4958a73a",
    "d75a5422ced9a3d62b557d8de8bec7ec",
    "6b4aee4345ae7007cf8dcf4e4ae93cfa",  # 0x30
    "2b522f664c2d114cfe61318c56784ea6",
    "3aa34e44c66faf7bfae55327efcfcc24",
    "2b5c78bfc38e499d41c33c5c7b2796ce",
    "f37eead2c0c8231da99bfa495db7081b",
    "708d4e6fd1f66f1d1e1fcb02f9b39926",
    "0f6716e180699c51fcc7ad6e4fb846c9",
    "560a494a844c8ed982ee0b6dc57d208d",
    "12468d7e1c42209bba5426835eb03303",  # 0x38
    "c43bb6d653ee67493ea95fbc0ced6f8a",
    "2cc3cf8c2878a5a663e2af2d715e86ba",
    "833da70ced6a2012d196e6fe5c4d37c5",
    "c743d06742ee90b8ca75503520adbcce",
    "8ae3663f8d9e82a1ede68c9ce8256daa",
    "7fc96f0bb1485ca55dd364b77af5e4ea",
    "91b765788bcb8bd402ed553a6662d0ad",
    "2824f9101b8d0f7b6eb263b5b55b2ebb",  # 0x40
    "30e2575de0a249cee8cf2b5e4d9f52c7",
    "5ee50439623202fa85393f72bb77fd1a",
    "f88174b1bde9bfdd45e2f55589cf46ab",
    "7df49265e3fad678d6fe78adbb3dfb63",
    "747fd62dc7a1ca96e27aceffaa723ff7",
    "1e58ebd065bbf168c5bdf746ba7be100",
    "24347daf5e4b35727a52276ba05474db",
    "09b1c705c35f536677c0eb3677df8307",  # 0x48
    "ccbe615c05a20033378e5964a7dd703d",
    "0d4750bbfcb0028130e184dea8d48413",
    "0cfd679af9b4724fd78dd6e99642288b",
    "7ad31a8b4befc2c2b39901a9fe76b987",
    "be787817c7f16f1ae0ef3bde4cc2d786",
    "7cd8b891910a4314d0533dd84c45be16",
    "32722c8807cf357d4a2f511944ae68da",
    "7e6bbff6f687b898eeb51b3216e46e5d",  # 0x50
    "08ea5a8349b59db53e0779b19a59a354",
    "f31281bfe69f51d164082521ffbb2261",
    "affe8eb13dd17ed80a61241c959256b6",
    "92cdb4c25bf2355a2309e819c9144235",
    "e1c65b226be1da02ba18fa21349ef96d",
    "14ec76ce97f38a0a34506c539a5c9ab4",
    "1c9bc490e3066481fa59fdb600bb2870",
    "43a5cacc0d6c2d3f2bd989676b3f7f57",  # 0x58
    "00effd1808a405893c38fb2572706106",
    "eeaf49e009879befaad6326a3213c429",
    "8d26b90f431dbb08db1ddac5b52c92ed",
    "577c3060ae6ebeae3aab1819c571680b",
    "115a5d20d53a8dd39cc5af410f0f186f",
    "0d4d51ab2379bf803abfb90e75fc14bf",
    "9993da3e7d2e5b15f252a4e66bb85a98",
    "f42830a5fb0d8d760ea671c22bde669d",  # 0x60
    "fb5feb7fc7dcdd693701979b29035c47",
    "02326ae7d396ce7f1c419dd65207ed09",
    "9c9b1372f8c640cf1c62f5d592ddb582",
    "03b302e85ff381b13b8daa2a90ff5e61",
    "bcd7f9d32facf847c0fb4d2f309abda6",
    "f55596e97faf867facb33ae69c8b6f93",
    "ee297093f94e445944171f8e86e170fc",
    "e434520cf088cfc8cd781b6ccf8c48c4",  # 0x68
    "c1bf66818ef953f2e1266b6f550cc9cd",
    "560fff8f3c9649144516f1bcbfcea30c",
    "2408dc753760a29f0554b5f243857399",
    "ddd5b56a59c55ae83b9667c75c2ae2dc",
    "aa686772e02d44d5cdbb6504bcd5bf4e",
    "1f17f014e777a2fe4b136b56cd7ef7e9",
    "c93548cf558d7503896b2eeb618ca902",
    "de34c541e7ca86e8bea7c31cece4360f",  # 0x70
    "dde5ff551b74f6f4e016d7ab22311b6a",
    "b0e93521333fd7bab4762ccb4d8008d8",
    "381469c4c3f91b9633638e4d5f3df029",
    "fa486ad98e6716ef6ab087f589457f2a",
    "321a091250148a3e963dea025932e18f",
    "4b00be29bcb02864cefd43a96fd95ced",
    "577dc4ff0244e28091f4ca0a7569fda8",
    "835336c61803e43e4eb30f6b6e799b7a",  # 0x78
    "5c9265fd7b596aa37a2f509d85e927f8",
    "9a39fb89df55b2601424cea6d9650a9d",
    "8b75be91a8c75ad2d7a594a01cbb9591",
    "95c21b8d05acf5ec5aee77812395c4d7",
    "b9a461643633fa5d9488e2d3281e01a2",
    "b8b084fb9f4cfaf730fe7325a2ab897d",
    "5f8c179fc1b21df1f6367a9cf7d3d47c",
))
