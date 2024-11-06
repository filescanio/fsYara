import os
import re
import sys
import glob


RULE_REX = re.compile(r'^(?:(?<!global\s)\bglobal\b\s|(?<!private\s)\bprivate\b\s){0,2}\brule\b\s((?![0-9])[_a-zA-Z0-9]{1,128})(?:\s:(?:\s(?![0-9])[_a-zA-Z0-9]{1,128}){1,128})?', re.MULTILINE)
RULE_NAMES = {}

yara_files = glob.glob(os.path.join('.', '**', '*.yar'), recursive=True) + \
             glob.glob(os.path.join('.', '**', '*.yara'), recursive=True)

for filepath in yara_files:
    if 'to_vet' in filepath.split(os.sep):
        continue

    try:
        with open(filepath, 'r', encoding='utf8') as file:
            content = file.read()
            for m in re.finditer(RULE_REX, content):
                rule_name = m.group(1)
                if rule_name not in RULE_NAMES:
                    RULE_NAMES[rule_name] = []
                RULE_NAMES[rule_name].append(filepath)
    except Exception as e:
        print(f'Exception happened during parsing {filepath}... Exception: {str(e)}')


ERRORS = 0
for rule_name, rule_files in RULE_NAMES.items():
    if len(rule_files) > 1:
        print(f'[ERROR] The rule "{rule_name}" is duplicated in the following files:')
        for file in rule_files:
            print(f'\t{file}')
        print()
        ERRORS += 1

sys.exit(ERRORS)
