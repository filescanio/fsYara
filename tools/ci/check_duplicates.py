from github import Github
from github import Auth
import plyara
from plyara.utils import generate_hash

"""
If the resultant hashes are identical for two YARA rules, the rules will match on identical content.
The reverse it not true, so two rules that match the same content may not generate the same hash.
For example, if a rule only contains one string, the logic for 'any of' and 'all of' generate different hashes,
but the rules contain the same logic.
"""

token = "<your_token>"
auth = Auth.Token(token)
g = Github(auth=auth)

repo = g.get_repo('filescanio/fsYara')
rulesets = []
logic_hash_dict = {}
def get_yara_files(contents):
    for content_file in contents:
        if content_file.type == "dir":
            get_yara_files(repo.get_contents(content_file.path))
        elif content_file.path.endswith(".yar") or content_file.path.endswith(".yara"):
            rulesets.append(content_file)

get_yara_files(repo.get_contents(""))

print("rule1,ruleset1,rule2,ruleset2")
for ruleset in rulesets:
    yara_parser = plyara.Plyara()  # reset
    yara_rules = yara_parser.parse_string(ruleset.decoded_content.decode())
    for yara in yara_rules:
        logic_hash = generate_hash(yara)
        if logic_hash in logic_hash_dict:
            print(f"{yara['rule_name']},{ruleset.path},{logic_hash_dict[logic_hash]['rule_name']},{logic_hash_dict[logic_hash]['ruleset']}")
        else:
            data = {}
            data['rule_name'] = yara['rule_name']
            data['ruleset'] = ruleset.path
            logic_hash_dict[logic_hash] = data