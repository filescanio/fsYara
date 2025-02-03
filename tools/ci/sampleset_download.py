# This is the script Dani wrote to download the samples. 
# You do not need to run this! It was only needed to generate the matchinsamples.zip and rules_match. 

import os
import sys
import traceback
import glob
import plyara
import requests
import base64
import json

fskey = "YOUR_FSIO_API_KEY"

rulesets_dir = sys.argv[1]

rulesets_orig = glob.glob(os.path.join(rulesets_dir, '**', '*.yar'), recursive=True) + \
             glob.glob(os.path.join(rulesets_dir, '**', '*.yara'), recursive=True)


yara_parser = plyara.Plyara()
rules = {}
rule_match = {}


# DOWNLOAD A FILE FROM FSIO MATCHING A GIVEN YARA RULE
def download_file_match(yara_rule, fskey):
    url = f"https://www.filescan.io/api/reports/advanced-search?derived_files=false&age=-1&page=1&page_size=10&unique_files=false&method=and&derived_files=true&no_date_limit=false&yara_rule=" + yara_rule +"&main_task_state=success"
    headers = {'X-Api-Key': fskey}
    #params = {"page": 1}
    #response = requests.get(url, headers=headers, params=params)
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200:
            resp_json = response.json()
            result_items = resp_json["items"]
            if len(result_items) == 0:
                # try again with no limits date
                url = url + "&no_date_limit=true"
                response = requests.get(url, headers=headers)
                resp_json = response.json()

                result_items = resp_json["items"]
                if len(result_items) == 0:
                    print(f"No matches found for yara rule '{yara_rule}'")
                    return None
            item = 0
            resp_json = {}

            # No content means private file
            while "content" not in resp_json and item < len(result_items):
                filehash = result_items[item]["file"]["sha256"]
                #check if it is already downloaded
                if not os.path.isfile("./matchingsamples/" + filehash):
                    url = f"https://www.filescan.io/api/files/{filehash}?type=base64&original_name=false"
                    response = requests.get(url, headers=headers)
                    resp_json = response.json()
                    if "content" in resp_json:
                        decoded_content = base64.b64decode(resp_json["content"])
                        with open("./matchingsamples/" + filehash, "wb") as file:
                            file.write(decoded_content)
                        return filehash
                    else:
                        item += 1
                else:
                    return filehash
            print("No public reports found")
            return None
        else:
            print(f"FSIO Yara search error. \n\tStatus code: {response.status_code}\n\t")
            return None

    except:
        print("%s %s" % (sys.stderr, traceback.format_exc()))
        return None


for rule_path in rulesets_orig:
    rules[rule_path] = []
    try:
        yara_parser.clear()
        yara_rules = yara_parser.parse_string(open(rule_path, 'r').read())
        for yara in yara_rules:
            try:
                print(f"Checking {yara['rule_name']}", end=" ")
                rules[rule_path].append(yara['rule_name'])
                filehash = download_file_match(yara['rule_name'], fskey)
                rule_match[yara['rule_name']] = filehash
                print(f"--> {filehash}")
            except:
                print(f"Something wrong with yara rule: {yara['rule_name']} ({rule_path})")
                print("%s %s" % (sys.stderr, traceback.format_exc()))
    except Exception as ex:
        print(f"Something wrong with ruleset: {rule_path}")



print(f"There are a total of {len(rules)} rules among {len(rulesets_orig)} rulesets")
with open("rules_match.json", "w") as file:
    file.write(json.dumps(rule_match, indent=4))