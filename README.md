TODO:
1.) if there's no system.cnf, find psx.exe at the root and get the timestamp/checksum of it
2.) fix variants of cdrom: string in system.cnf
	- cdrom:\\;
	- cdrom:;
	- cdrom:\;
	- cdrom:\PATH\TO\EXE;
3.) some games don't report timestamps for the exe even though they've been identified and hash'd
	Armorines - Project S.W.A.R.M. (USA) (Track 1).bin
	Asciiware Training CD (USA).bin
	Best Buy Greatest Hits Demo Disc - Volume One (USA) (Track 1).bin
	Blood Omen - Legacy of Kain (USA) (Beta 1).bin
	Blood Omen - Legacy of Kain (USA) (Beta 2).bin
	Chrono Cross (USA) (Disc 1).bin
	Chrono Cross (USA) (Disc 2).bin
	Clock Tower II - The Struggle Within (USA).bin
	Code Breaker (USA) (Unl).bin
	Code Breaker Version 2 (USA) (Unl).bin
	Code Breaker Version 3 (USA) (Unl).bin
	Codebreaker D.J. (USA) (Unl) (Track 1).bin
	Contender (USA) (Demo) (Track 1).bin
	Cool Boarders 2001 (USA).bin
	Cool Boarders 2001 (USA) (Demo).bin
	Crash Bash & Spyro - Year of the Dragon (USA) (Demo) (Track 1).bin
	Crash Bash (USA).bin
	Crash Bash (USA) (Demo) (Track 1).bin
	D (USA) (Disc 1) (Track 1).bin
	D (USA) (Disc 2) (Track 1).bin
	D (USA) (Disc 3) (Track 1).bin
	Dave Mirra Freestyle BMX - Maximum Remix (USA) (Track 1).bin
	Disney's Tarzan (USA) (Rerelease) (Track 1).bin
	DSP Music Revelation (USA, Europe) (Unl) (Track
	ECW Anarchy Rulz (USA) (Track 1).bin
	ECW Hardcore Revolution (USA) (Track 1).bin
	ECW Hardcore Revolution (USA) (Demo) (Track 1).bin
	Eidos Demo Disc Volume 7 (USA) (Track 1).bin
	ESPN Extreme Games (USA) (Track 1).bin
	Final Fantasy Chronicles - Chrono Trigger (USA) (Rev 1).bin
	Final Fantasy Chronicles - Final Fantasy IV (USA) (Rev 1).bin
4.) skip any file with a filename that contains (Track #) where # is a number higher than 1
5.) report filename, checksum, and timestamp of latest modified file
6.) Discs that report 1900 as a year in the TOC should be 2000.
7.) add saturn/sega cd supprt for the main exe (note: the exe is always the first file sorted alphanumerically on the root of the disc).
8.) add system detector
    - PS1 games can be detected if "BOOT" is present in system.cnf.
    - PS2 games can be detetcted if "BOOT2" is present in system.cnf
    - Sega Saturn games can be detected if the string "SEGASATURN" is present at 0x15 in an iso.
    - Sega CD games can be detected if the string "SEGADISCSYSTEM" is present at 0x10 in a .bin and 0x0 in an .iso.
