import os
import argparse
from datetime import datetime

def generate_yara_master_index(input_folder, output_file="master_file.yar", ignore_filenames=None, ignore_folders=None):
    """
    Generates a master YARA index file by including all `.yar` files in the given directory.
    """

    ignore_filenames = ignore_filenames or set()
    ignore_folders = ignore_folders or set()
    
    with open(output_file, "w") as fw:
        fw.write("/*\n")
        fw.write(f"Generated on {datetime.now().strftime('%Y-%m-%d')}\n")
        fw.write("Copyright 2024 OPSWAT Inc., All Rights Reserved, www.filescan.com\n")
        fw.write("*/\n\n")
        
        for root, dirs, files in os.walk(input_folder):
            if root in ignore_folders:
                print(f"root: {root}")
                print(f"dir: {dirs}")
                print(f"path: {os.path.basename(root)}")
                continue
            
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    print(f"path: {os.path.basename(root)}")
                    if file in ignore_filenames or file == output_file:
                        continue
                    yara_file_path = os.path.abspath(os.path.join(root, file))
                    yara_file_path = yara_file_path.replace(
                        "/home/runner/work/fsYara/fsYara/",
                        "/app/transform/yara/rules/0PSWAT_fsYara/"
                    )
                    fw.write(f'include "{yara_file_path}"\n')

        print(f"Generated YARA master file: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Generates a master YARA index file by including all `.yar` files in the given directory")
    parser.add_argument("input_folder", help="Path to the input folder containing YARA rule files.")
    parser.add_argument("--output_file", help="Name of the output file", default="master_file.yar")
    parser.add_argument("--ignore_filenames", help="Files to be ignored", default=None)
    parser.add_argument("--ignore_folders", help="Folders to be ignored", default=None)

    args = parser.parse_args()

    generate_yara_master_index(args.input_folder, output_file=args.output_file, ignore_filenames=args.ignore_filenames, ignore_folders=args.ignore_folders)

# Example usage
if __name__ == "__main__":
    # generate_yara_master_index(".", "master_file.yar")
    main()