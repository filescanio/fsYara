import subprocess
import pathlib
import sys

tmpfile = pathlib.Path('temp.bin')
cmd = ['yarac'] + sys.argv[1:] + [tmpfile.absolute()]

ERROR = -1
try:
    process = subprocess.run(cmd, check=False)
    ERROR = process.returncode
    tmpfile.unlink()
except Exception as e:
    pass

sys.exit(ERROR)
