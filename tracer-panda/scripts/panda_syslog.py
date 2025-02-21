import argparse
from os import remove, path
from pandare import Panda
import cffi

parser = argparse.ArgumentParser(
        prog="panda_sysroot_collector",
        description="this program collects the dll/so files alssociated with a recording."
        )
parser.add_argument('arch')
parser.add_argument('mem')
parser.add_argument('qcow')
parser.add_argument('recording')
parser.add_argument('process_name')
parser.add_argument('os_name')
parser.add_argument('out_file', default='sysroot.out')
#parser.add_argument('-e', '--extra_args')
#parser.add_argument('-l', '--libpanda_path')

args= parser.parse_args()

linenum = 0 

file_set = set()

panda = Panda(arch=args.arch, mem=args.mem, qcow=args.qcow)
panda.set_os_name(args.os_name)
@panda.cb_asid_changed
def asid_changed(env, oldASID, newASID):
    global file_set
    if args.process_name == panda.get_process_name(env):
        garray = panda.get_mappings(env)
#        print(garray.garray_len)
        if garray.garray_len > 0:
            for item in garray:
                ffi = cffi.FFI()
                #print (f"(item.modd) = {item.modd}")
                #print (f"(item.base) = {hex(item.base)}")
                #print (f"(item.size) = {item.size}")
                #print (f"ffi.string(item.name) = {ffi.string(item.name)}")
                #print (f"ffi.string(item.file) = {ffi.string(item.file)}")
                file_set.add("\"" + f"{(ffi.string(item.file)).decode()}" + "\" " +  f"{hex(item.base)} {item.size}")

panda.run_replay(args.recording)

myfile = open(args.out_file,"w")
for item in file_set:
    myfile.write(f"{item}\n")

print(file_set)
