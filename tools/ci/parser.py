import os
import yara
from datetime import datetime

def generate_yara_master_index(input_folder, output_file, ignore_filenames=None, ignore_folders=None):
    """
    Generates a master YARA index file by including all `.yar` files in the given directory.
    """
    ignore_filenames = ignore_filenames or set()
    ignore_folders = ignore_folders or set()
    
    with open(output_file, "w") as fw:
        fw.write("/*\n")
        fw.write(f"Generated on {datetime.now().strftime('%Y-%m-%d')}\n")
        fw.write("*/\n\n")
        
        for root, dirs, files in os.walk(input_folder):
            if any(ignored in root for ignored in ignore_folders):
                continue
            
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    if any(ignored in file for ignored in ignore_filenames):
                        continue
                    yara_file_path = os.path.abspath(os.path.join(root, file))
                    fw.write(f'include "{yara_file_path}"\n')

        print(f"Generated YARA master file: {output_file}")

# Example usage
if __name__ == "__main__":
    generate_yara_master_index(".", "output.yarc", ignore_filenames={"ignore_me"}, ignore_folders={"skip_this_folder"})