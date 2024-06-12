# Usage:
1. --append-output - appends current scan to a pre-existing .csv
2. --ignore-existing - doesn't process files that are already in the output csv
3. --no-contents-checksum - skips the composite checksum calculations (speed up)
4. --allow-extensions *extension without .* - allows scanning of compressed archives. useful for xbox.
5. -o *filename.csv* - output to a specific name (default is results.csv)
6. -f *filename.iso* - pass a single file to the script

# Examples:

1.) Scan compressed archives (rar, 7z, zip) for disc images:

  pipenv run python ps2exe.py /input/dir --append-output --ignore-existing --archives-as-folder -o out.csv

2.) Scan compressed archives (rar, 7z, zip) but treat them as disc images themselves (for example, loose Xbox HDD file dumps):

  pipenv run python ps2exe.py /input/dir --append-output --ignore-existing --allow-extensions zip rar 7z -o out.csv
