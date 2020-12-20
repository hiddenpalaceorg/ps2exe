# Usage:
1. --append-output - appends current scan to a pre-existing .csv
2. --ignore-existing - doesn't process files that are already in the output csv
3. --no-contents-checksum - skips the composite checksum calculations (speed up)
4. -o *filename.csv* - output to a specific name (default is results.csv)
5. -f *filename.iso* - pass a single file to the script

# TODO:
1. ~~if there's no system.cnf, find psx.exe at the root and get the timestamp/checksum of it~~
2. ~~fix variants of cdrom: string in system.cnf~~
    - ~~cdrom:\\;~~
	- ~~cdrom:;~~
	- ~~cdrom:\;~~
	- ~~cdrom:\PATH\TO\EXE;~~
3. ~~some games don't report timestamps for the exe even though they've been identified and hash'd~~
	- ~~Armorines - Project S.W.A.R.M. (USA) (Track 1).bin~~
	- ~~Asciiware Training CD (USA).bin~~
	- ~~Best Buy Greatest Hits Demo Disc - Volume One (USA) (Track 1).bin~~
	- ~~Blood Omen - Legacy of Kain (USA) (Beta 1).bin~~
	- ~~Blood Omen - Legacy of Kain (USA) (Beta 2).bin~~
	- ~~Chrono Cross (USA) (Disc 1).bin~~
	- ~~Chrono Cross (USA) (Disc 2).bin~~
	- ~~Clock Tower II - The Struggle Within (USA).bin~~
	- ~~Code Breaker (USA) (Unl).bin~~
	- ~~Code Breaker Version 2 (USA) (Unl).bin~~
	- ~~Code Breaker Version 3 (USA) (Unl).bin~~
	- ~~Codebreaker D.J. (USA) (Unl) (Track 1).bin~~
	- ~~Contender (USA) (Demo) (Track 1).bin~~
	- ~~Cool Boarders 2001 (USA).bin~~
	- ~~Cool Boarders 2001 (USA) (Demo).bin~~
	- ~~Crash Bash & Spyro - Year of the Dragon (USA) (Demo) (Track 1).bin~~
	- ~~Crash Bash (USA).bin~~
	- ~~Crash Bash (USA) (Demo) (Track 1).bin~~
	- ~~D (USA) (Disc 1) (Track 1).bin~~
	- ~~D (USA) (Disc 2) (Track 1).bin~~
	- ~~D (USA) (Disc 3) (Track 1).bin~~
	- ~~Dave Mirra Freestyle BMX - Maximum Remix (USA) (Track 1).bin~~
	- ~~Disney's Tarzan (USA) (Rerelease) (Track 1).bin~~
	- ~~DSP Music Revelation (USA, Europe) (Unl) (Track~~
	- ~~ECW Anarchy Rulz (USA) (Track 1).bin~~
	- ~~ECW Hardcore Revolution (USA) (Track 1).bin~~
	- ~~ECW Hardcore Revolution (USA) (Demo) (Track 1).bin~~
	- ~~Eidos Demo Disc Volume 7 (USA) (Track 1).bin~~
	- ~~ESPN Extreme Games (USA) (Track 1).bin~~
	- ~~Final Fantasy Chronicles - Chrono Trigger (USA) (Rev 1).bin~~
	- ~~Final Fantasy Chronicles - Final Fantasy IV (USA) (Rev 1).bin~~
4. ~~skip any file with a filename that contains (Track #) where # is a number higher than 1~~
5. ~~report filename, checksum, and timestamp of latest modified file~~
6. ~~Discs that report 1900 as a year in the TOC should be 2000.~~
7. ~~add saturn/sega cd supprt for the main exe (note: the exe is always the first file sorted alphanumerically on the root of the disc). naybe we should interpret the ip/header as well https://github.com/GerbilSoft/rom-properties/blob/61999700a70b98acd457d7cf35efb437d597c79b/src/libromdata/Console/saturn_structs.h ?~~
8. ~~add philips cd-i support. the main executable filename differs from game to game, but the it can be determined in LBA 16 at address 0x23E (maybe 0x9556 in each .bin).~~
9. add panasonic 3do support. the main executable will always be named "launchme", and should be found at the root.  3DO uses something called "OperaFS". The first 132 bytes of sector 0 is the volume header. operafs doesn't include timestamps, so we can only really grab the launchme hash.
10. add system detector
    - ~~PS1 games can be detected if "BOOT" is present in system.cnf.~~
    - ~~PS2 games can be detetcted if "BOOT2" is present in system.cnf~~
    - ~~Sega Saturn games can be detected if the string "SEGASATURN" is present at 0x15 in an iso.~~
    - Sega CD games can be detected if the string "SEGADISCSYSTEM" is present at 0x10 in a .bin and 0x0 in an .iso.
    - Sega Dreamcast games can be detected if "1ST_READ.BIN" is present on the track that contains game data. Alternatively, Dreamcast games also have a IP.BIN/Disc header that contains the string "SEGA SEGAKATANA" at 0x10 in every data track (track01.bin should always be a data track).
    - ~~Philips CD-i games can be detected if the file "path_tbl" is located at the root of the disc.~~
    - Panasonic 3DO can be detected if the word "CD-ROM" can be found at 0x38 in the .img.
    - Microsoft Xbox games can be detected if 'default.xbe' is present on the disc. Some prototypes will either be on normal DVD-Rs with a normal PC readable file system, some prototypes will use the xbox file system as its first partition, and some will be on pressed discs that use two partitions (a dvd video partition followed by a xbox file system partition where game data is stored).
    - Commodore Amiga CD32.
    - PlayStation Portable - games can exist on DVD-Rs in a specific format or on raw UMD dumps.
    - Default case - mark disc as Asset if no other match is found (still return latest modified file data just in case).
11. (HIGH PRIORITY) add edccchk support for cd based images (https://github.com/claunia/edccchk). scan images for edc/ecc consistency to check for errors. parse the log output and include just the total warning and total error count into to respective columns. maybe save the total output for the current run session in a separate log file for review. Make this optional with a parameter/flag. (HIGH PRIORITY)
12. detect media type (CD-R or DVD-R). unsure if we can do this.
