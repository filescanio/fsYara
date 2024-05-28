import os
import re
import sys
import glob


rule_regex = re.compile(r'^\s+(score|weight)\s*=\s*(\d+)', re.MULTILINE)
yara_files = glob.glob(os.path.join('.', '**', '*.yar'), recursive=True) + \
             glob.glob(os.path.join('.', '**', '*.yara'), recursive=True)

ERROR = 0
for filepath in yara_files:
    if 'to_vet' in filepath.split(os.sep):
        continue

    try:
        with open(filepath, 'r', encoding='utf8') as file:
            content = file.read()
            for m in re.finditer(rule_regex, content):
                rule_name = m.group(1)
                rule_score = m.group(2)
                max_score = 10
                if rule_name == 'score':
                    max_score = 100
                if int(rule_score) < 0 or int(rule_score) > max_score:
                    ERROR += 1
                    context_size = 64
                    context = content[max(0, m.span()[0] - context_size): min(len(content), m.span()[1] + context_size)]
                    print(f'[ERROR] In file "{filepath}" severity is an impossible value. Context:')
                    print(f'\t{context}')
    except Exception as e:
        print(f'Exception happened during parsing {filepath}... Exception: {str(e)}')

sys.exit(ERROR)