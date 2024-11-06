import os
import sys
import glob
import plyara
from plyara.utils import generate_hash

"""
If the resultant hashes are identical for two YARA rules, the rules will match on identical content.
The reverse it not true, so two rules that match the same content may not generate the same hash.
For example, if a rule only contains one string, the logic for 'any of' and 'all of' generate different hashes,
but the rules contain the same logic.
"""

rulesets = []
logic_hash_dict = {}

rulesets =  glob.glob(os.path.join('.', '**', '*.yar'), recursive=True) + \
            glob.glob(os.path.join('.', '**', '*.yara'), recursive=True)


print(">>>>> rule1,ruleset1,rule2,ruleset2")
yara_parser = plyara.Plyara()

ERRORS = 0
for rule_path in rulesets:
    try:
        yara_parser.clear()
        yara_rules = yara_parser.parse_string(open(rule_path, 'r').read())
        for yara in yara_rules:
            try:
                logic_hash = generate_hash(yara)
                if logic_hash in logic_hash_dict:
                    ERRORS += 1
                    print(f"[DUP] {yara['rule_name']},{rule_path},{logic_hash_dict[logic_hash]['rule_name']},{logic_hash_dict[logic_hash]['ruleset']}")
                else:
                    data = {}
                    data['rule_name'] = yara['rule_name']
                    data['ruleset'] = rule_path
                    logic_hash_dict[logic_hash] = data
            except:
                ERRORS += 1
                print(f"Something wrong with yara rule:{yara} ({rule_path})")
    except:
        ERRORS += 1
        print(f"Something wrong with ruleset: {rule_path}")

sys.exit(ERRORS)
