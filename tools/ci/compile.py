import subprocess
import pathlib
import sys

tmpfile = pathlib.Path('temp.bin')
cmd = ['yarac'] + sys.argv[1:] + [tmpfile.absolute()]

ERROR = -1
try:
    process = subprocess.run(cmd, check=False)
    ERROR = process.returncode
except Exception as e:
    print(f'[COMPILER] Process Exception happened: {e}')

try:
    tmpfile.unlink()
except FileNotFoundError as e:
    if ERROR == 0:
        ERROR = -2
except Exception as e:
    print(f'[COMPILER] File Exception happened: {e}')

sys.exit(ERROR)
