# Author: Ruturaj Kiran Vaidya

import os
import sys
import pickle
# to work with dwarf
from elftools.elf.elffile import ELFFile

# disassembler
import capstone

# to parse data from objdump
# capstone gives me wierd errors - so using objdump instead
import re

# type modifiers are used in conjuction with base types
# to idetify correct base types, it is important to consider these constructs
# considering c language is the source
# also including pointer and array types in such constructs
type_modifiers = ["DW_TAG_const_type", "DW_TAG_restrict_type", "DW_TAG_volatile_type", "DW_TAG_pointer_type", "DW_TAG_array_type", "DW_TAG_typedef"]

# type excavation
def die_recursive(dies, offset):
    typeinfo = None
    for die in dies:
        if die.offset == offset:
            if die.tag in type_modifiers:
                # if no DW_AT_type tag is defined then the variable most certainly be of a void type
                if "DW_AT_type" in die.attributes:
                    typeinfo = die_recursive(dies, die.attributes["DW_AT_type"].value)
                else:
                    return "void"
            elif die.tag == "DW_TAG_base_type" or die.tag == "DW_TAG_structure_type":
                if "DW_AT_name" in die.attributes:
                    return die.attributes["DW_AT_name"].value.decode("utf-8")
                else:
                    return None
    return typeinfo

def parse_parameters(die):
    # detect function parameters
    if die.tag == "DW_TAG_formal_parameter":
        # print(DIE.attributes["DW_AT_name"].value.decode("utf-8"))
        typeinfo = die_recursive(dies, die.attributes["DW_AT_type"].value)
        functions[current_fun]["args_type"].append(typeinfo)
        functions[current_fun]["num_args"] +=1

# take input directory as an input from user
directory = sys.argv[1]
for filename in os.listdir(directory):
    path = os.path.join(directory, filename)
    print(path)
    with open(path, "rb") as f:
        # Get the object
        elffile = ELFFile(f)
        # Get text section address in hex
        txt_sec_addr = hex(elffile.get_section_by_name(".text")["sh_addr"])
        # get architecture
        # x86 or x86_64
        arch = "i386" if elffile.get_machine_arch() == "x86" else "amd64"
        # print(elffile.get_dwarf_info().config)

        # complete dictionary
        bin_info = {"functions":{}, "structures":{}, "text_addr":txt_sec_addr, "binRawBytes":"", "arch":arch, "binary_filename":filename, "function_calls":{}}

        # store "functions" information
        functions = {}

        # extract the dwarf symbol information
        dwarfinfo = elffile.get_dwarf_info()
        # get disassembly
        code = elffile.get_section_by_name(".text")

        # save binraw bytes
        #bin_info["binRawBytes"] = code.data().decode('unicode_escape').encode('utf-8')

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        # save disassembly
        disassembly = []
        for i in md.disasm(code.data(), code['sh_addr']):
            disassembly.append([hex(i.address), " ".join([i.mnemonic,i.op_str]).rstrip()])

        for CU in dwarfinfo.iter_CUs():
            # collect all dies for type detection
            dies = [die for die in CU.iter_DIEs()]
            # store the current function and structure values, so that it will be useful
            # in creating the dictionary
            current_fun = ""
            current_struct = ""
            for DIE in CU.iter_DIEs():
                try:
                    # Detect user defined routines
                    if DIE.tag == "DW_TAG_subprogram":
                        # get the current function name
                        current_fun = DIE.attributes["DW_AT_name"].value.decode("utf-8")
                        if current_fun != "main":
                            bin_info["function_calls"][current_fun] = []

                        functions[current_fun] = {"num_args":0, "args_type":[], "ret_type":"",
                            "inst_strings":[], "inst_bytes":[], "boundaries":()}
                        # get the lower bound
                        lowpc = DIE.attributes["DW_AT_low_pc"].value
                        # get the upper bound
                        highpc = DIE.attributes["DW_AT_high_pc"].value + lowpc
                        boundaries = lowpc, highpc-1
                        functions[current_fun]["boundaries"] = boundaries
                        # get the return type
                        for die in dies:
                            if die.offset == DIE.attributes["DW_AT_type"].value:
                                functions[current_fun]["ret_type"] = die.attributes["DW_AT_name"].value.decode("utf-8")
                        # prpare the disassembly per function
                        slice = False
                        for ins in disassembly:
                            if ins[0] == hex(lowpc) or slice:
                                functions[current_fun]["inst_strings"].append(ins[1])
                                slice = True
                            if ins[0] == hex(highpc-1):
                                break
                        # parse children for argument detection
                        if DIE.has_children:
                            for die in DIE.iter_children():
                                parse_parameters(die)

                    # Detect structures
                    if DIE.tag == "DW_TAG_structure_type":
                        if "DW_AT_name" not in DIE.attributes:
                            continue
                        if type(DIE.attributes["DW_AT_name"].raw_value) is not int and DIE.get_parent().tag == "DW_TAG_compile_unit":
                            current_struct = DIE.attributes["DW_AT_name"].value.decode("utf-8")
                            if DIE.has_children:
                                bin_info["structures"][current_struct] = []
                                for die in DIE.iter_children():
                                        # Detect structure members
                                    if die.tag == "DW_TAG_member":
                                        typeinfo = die_recursive(dies, die.attributes["DW_AT_type"].value)
                                        bin_info["structures"][current_struct].append(typeinfo)
                except KeyError:
                    continue
    # store call instruction indices in the current function
    called_ins = {}
    for func in functions:
        for i,ins in enumerate(functions[func]["inst_strings"]):
            if ins.split(" ")[0] == "call":
                for func2 in functions:
                    # if called function address matches
                    if ins.split(" ")[1] == hex(functions[func2]["boundaries"][0]):
                        if func2 not in called_ins:
                            called_ins[func2] = [{"caller":func,  "call_instr_indices":[i+1]}]
                        else:
                            # check if the caller function is already present
                            found = False
                            for j in called_ins[func2]:
                                if j["caller"] == func:
                                    j["call_instr_indices"].append(i+1)
                                    found = True
                                    break
                            if not found:
                                called_ins[func2].append({"caller":func,  "call_instr_indices":[i+1]})
        bin_info["function_calls"] = called_ins
    # print(functions)
    # prepare codebytes per function
    for func in functions:
        # Create objdump command to show one function only
        os.system(f"objdump -M intel -d {path} | awk -v RS= '/^[[:xdigit:]]+ <{func}>/' > bintemp")
        with open("bintemp", "r") as f:
            listing = []
            # loop line by line
            for line in f:
                m = re.match(r"^[ 0-9a-f]+:\t([a-f0-9 ]+)", line)
                if m is not None:
                    # convert each byte into hex
                    listing.append([int(i, 16) for i in m.group(1).split()])
            functions[func]['inst_bytes'] = listing
    # some names must be there, even if not used
    # set functions
    bin_info["functions"] = functions
    with open("pickled_coreutils/"+filename+".pkl", "wb") as f:
        pickle.dump(bin_info, f, protocol=0)
