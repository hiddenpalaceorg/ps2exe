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
9. ~~add panasonic 3do support. the main executable will always be named "launchme", and should be found at the root.  3DO uses something called "OperaFS". The first 132 bytes of sector 0 is the volume header. operafs doesn't include timestamps, so we can only really grab the launchme hash. sample code for extracting files in Go and more documentation on OperaFS can be found here https://github.com/barbeque/3dodump~~
10. add microsoft xbox support. the main executable for a game mastered on a disc will always be named "default.xbe". however, xbox might be tricky as there are various ways xbox games can be mastered. the three most common ways are as follows:
    - dvd-r using a udf partition, explorable within windows. not very common. this will have a valid volume descriptor.
    - dvd-r using a single xbox file system partition. common in protos. no volume descriptor.
    - pressed disc using a dvd-video parition (partition 1) followed by an xbox file system partition for game files (partition 2). always used in retail games but can be found on protos too, since sometimes microsoft pressed them instead of burning them on recordable media. these are usually always burnt on dual layer dvds. when doing composite checksums, or any kind of file search, we always ignore these partitions. there will be a volume descriptor in the dvd video partition which is usually useless, but nothing for the xbox fs partition.
    
    the xbox file system itself lacks timestamps, so finding the last modified file will be impossible unless the game was mastered on a standard dvd-r with udf. however, each default.xbe contains headers and sections that contain lots of information that we can use. i'm not sure how to determine the location of the header, but the contents of the header is as follows: https://i.imgur.com/NFSVddu.png
    
    for this project, the most important thing to extract is dwTimeDate, dwPeTimeDate, and dwDebugFileNameAddr from the executable's header. within the xbe itself, there's a certificate section that follows the header section that has information that we need, such as dwTitleId (treat this as a string I think), wszTitleName, dwGameRegion, and dwVersion.
    
    for calculating composite checksums of the games, we need to leave out the dvd-video parition if it exists and only focus on the file system that contains default.xbe. when calculating the composite checksum, it might be better to leave default.xbe out of the calculation. there might be instances where "protos" are nothing more than final versions but with different certificates. it might be possible to strip the certification/header out of the xbe, but not sure if its necessary.
11. add microsoft xbox 360 support. this should be similar in procedure to xbox og games, but there'll be some differences. i know that the .xex will be encrypted and has to be decrypted, which should be trivial to do as it seems to be based on a common key (?). research needed.
~~12. add amiga cd/cd32 support. amiga cd/cd32 games use standard iso format, with toc/pvd. games can be detected in S\startup-sequence is found (case insenstive). however, the actual boot executable can only be determined via the startup-sequence, and every game has its own sequence. you'd have to interpret the sequence to locate the actual executable. sequence files look similar to linux bash commands. in theory, the last command run in the file is the executable. if you interpret the last line as a filename and search the iso for that file, thats the executable. of course, there could be instances where the filename of the executable is used elsewhere for another file, but chances are unlikely. the proper way would be to at least mimick the "cd" commands to locate the correct file. low priority.~~
13. add ps3 support. ps3 will either originate from dvd-rs or bd-rs somewhat encrypted, using a udf file system - so volume information, timestamps, latest mod file, etc can be determined. starting from the root of a ps3 you'll find PS3_GAME (where the game files are stored), PS3_UPDATE (contains firmware update files, ignore this completely), and PS3_DISC.SFB. 
    - PS3_DISC.SFB contains metadata for the disc itself, which we can pull version number, game title, and disc id (https://www.psdevwiki.com/ps3/PS3_DISC.SFB for more info).
    - Inside the PS3_GAME folder you'll find PARAM.SFO. Just like the PSP, this file contains a ton of information about the game itself (mostly used by the XMB/firmware). More information here: https://www.psdevwiki.com/ps3/PARAM.SFO
    - However, the contents of the USRDIR are encrypted. I don't know what can be done in the case of the script, as prototypes can be decrypted uses sony's official tools. there might be something out there that can finally universally decrypt these files. more research needed.
14. add system detector
    - ~~PS1 games can be detected if "BOOT" is present in system.cnf.~~
    - ~~PS2 games can be detetcted if "BOOT2" is present in system.cnf~~
    - ~~Sega Saturn games can be detected if the string "SEGASATURN" is present at 0x15 in an iso.~~
    - ~~Sega CD games can be detected if the string "SEGADISCSYSTEM" is present at 0x10 in a .bin and 0x0 in an .iso.~~
    - Sega Dreamcast games can be detected if "1ST_READ.BIN" is present on the track that contains game data. Alternatively, Dreamcast games also have a IP.BIN/Disc header that contains the string "SEGA SEGAKATANA" at 0x10 in every data track (track01.bin should always be a data track).
    - ~~Philips CD-i games can be detected if the file "path_tbl" is located at the root of the disc.~~
    - ~~Panasonic 3DO can be detected if the word "CD-ROM" can be found at 0x38 in the .img.~~
    - Microsoft Xbox games can be detected if 'default.xbe' is present on the disc. Some prototypes will either be on normal DVD-Rs with a normal PC readable file system, some prototypes will use the xbox file system as its first partition, and some will be on pressed discs that use two partitions (a dvd video partition followed by a xbox file system partition where game data is stored).
    - Microsoft Xbox 360 games can be detected if 'default.xex' is present on the disc. Some prototypes will either be on normal DVD-Rs with a normal PC readable file system, some prototypes will use the xbox file system as its first partition, and some will be on pressed discs that use two partitions (a dvd video partition followed by a xbox file system partition where game data is stored). I'm not familiar with XBox 360, but it seems similar to Xbox OG. More research needed. However, each game has its own start up sequence.
    ~~- Commodore Amiga CD/CD32 games can be detected if S\Startup-Sequence can be found (case insensitive).~~ 
    - PlayStation 3 games can be determined if PS3_DISC.SFB or /PS3_GAME is present at the root of the disc.
    - ~~PlayStation Portable - games can exist on DVD-Rs in a specific format or on raw UMD dumps.~~
    - Default case - mark disc as Asset if no other match is found (still return latest modified file data just in case).
15. (HIGH PRIORITY) add edccchk support for cd based images (https://github.com/claunia/edccchk). scan images for edc/ecc consistency to check for errors. parse the log output and include just the total warning and total error count into to respective columns. maybe save the total output for the current run session in a separate log file for review. Make this optional with a parameter/flag. (HIGH PRIORITY)
16. detect media type (CD-R or DVD-R). unsure if we can do this. (partially implemented on a system by system basis)
