import sys
import os
import pathlib
import shlex
import shutil

#This currently only works on the C:\ drive

input_file = "sysroot.out"
mnt_location = "/mnt"
output_file = "cleaned_sysroot.out"
output_dir ="./new_sysroot"

f = open(input_file,"r")
results = []

for l in f.readlines():
    line_items = shlex.split(l)
    code_path = line_items[0]
    code_size = line_items[2]
    code_base = line_items[1] 
    result = []
    path_parts_windows = pathlib.PureWindowsPath(code_path).parts[1:]
    path_unix = os.path.join(mnt_location , *path_parts_windows)
    clean_code_path =  path_unix.lower()
    for root, dirs, files in os.walk(mnt_location):
        for system_name in files:
            system_path = os.path.join(root, system_name)
            clean_system_path = system_path.lower()

            #print(f"`{clean_system_path}` == `{clean_code_path}`\n")
            if clean_system_path == clean_code_path:
                result.append([code_path, os.path.join(root, system_name), path_parts_windows, code_base, code_size])
    if 1 < len(result):
        sys.stderr.write(f"Panic because we found multiple possible files. This will require human intervention")
        exit(1)
    if 0 != len(result):
        results.append(result)
with open(output_file,"w") as out_file:
    for item in results:
        file_from = f"{item[0][1]}" #file to copy from 
        file_to = f"{os.path.join(output_dir , *(item[0][2]))}" #file to copy to
        file_new_dir = f"{os.path.join(output_dir , *((item[0][2])[0:-1]) )}" #dir to make
        os.makedirs(file_new_dir, mode=0o777, exist_ok = True)
        shutil.copy2(file_from, file_to,follow_symlinks=True)
        out_line = f"{file_to} {item[0][3]} {item[0][4]}" + "\n"
        out_file.write(out_line)
