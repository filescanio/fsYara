import sys
import os
import glob
import plyara
import json
import yara

rulesets_parent_dir = sys.argv[1]
matches_file = "rules_match.json"

rulesets_orig = glob.glob(os.path.join(rulesets_parent_dir, '**', '*.yar'), recursive=True) + \
             glob.glob(os.path.join(rulesets_parent_dir, '**', '*.yara'), recursive=True)

print(f"Read {len(rulesets_orig)} rulesets.")

yara_parser = plyara.Plyara()


# For some reason buggy. Did not debug to fix, implemented 2nd version
def get_ruleset(rulename, rulesets):
    print(f"Searching {rulename} on {len(rulesets)} rulesets")
    for rset_path in rulesets:
        yara_parser.clear()
        yara_rules = yara_parser.parse_string(open(rset_path, 'r').read())
        for yararule in yara_rules:
            if rulename == yararule['rule_name']:
                return rset_path
        return None


print("Fetching rules.")
rules = {}
limited_rules = {}
for rule_path in rulesets_orig:
    rules[rule_path] = []
    limited_rules[rule_path] = []

    yara_parser.clear()
    yara_rules = yara_parser.parse_string(open(rule_path, 'r').read())

    for yararule in yara_rules:
        rules[rule_path].append(yararule['rule_name'])

        if 'tags' in yararule and 'limited' in yararule['tags']:
            limited_rules[rule_path].append(yararule['rule_name'])

print("Fetched rules.")
print(f"\tThere are a total of {sum(len(value) for value in rules.values())} rules among {len(rulesets_orig)} rulesets")


def get_ruleset2(rulename):
    for ruleset in rules.keys():
        if rulename in rules[ruleset]:
            return ruleset
    return None


loaded_rulesets = {}

# {rule_name: failure_reason}
error_rules = {}

with open(matches_file, 'r') as file:
    rules_match = json.load(file)

for matching_rule in rules_match:
    if rules_match[matching_rule] != None: # Skip rules with no test sample
        print(f"Testing {matching_rule}")
        #ruleset = get_ruleset(matching_rule, rulesets_orig)
        ruleset = get_ruleset2(matching_rule)
        if ruleset != None:
            if ruleset not in loaded_rulesets: #compile only once
                loaded_rulesets[ruleset] = yara.compile(ruleset)
            matching_sample = "./matchingsamples/" + rules_match[matching_rule]
            print(f"\tRuleset {ruleset}")
            print(f"\tSample {rules_match[matching_rule]}")
            if os.path.isfile(matching_sample):
                matches = loaded_rulesets[ruleset].match(filepath=matching_sample)
                if bool(matches):
                    for match in matches:
                        if match.rule == matching_rule:
                            print("\tAll good!")
                else:
                    if ruleset in limited_rules and matching_rule not in limited_rules[ruleset]:
                        print("\tNo match...")
                        error_rules[matching_rule] = "NO_MATCH"
                    else:
                        print("\tRule is limited")
            else:
                print(f"Matching sample {matching_sample} does not exist.")
                error_rules[matching_rule] = "NO_SAMPLE"
        else:
            print(f"\tRuleset not found for {matching_rule}.")
            error_rules[matching_rule] = "NO_RULESET"

if (len(error_rules)) > 0:
    print(error_rules)
    print("\n Some rules did not match the correponding samples, see printed json.")
    sys.exit(1)
else:
    print("All the rules matched.")