#
#
# Deofuscate strings in go binaries that have been protected by Garble (https://github.com/burrowers/garble)
# Idea and emulation code from: https://research.openanalysis.net/garble/go/obfuscation/strings/2023/08/03/garble.html

# This snippet adds function comments and comments at the call site to show the string that was deobfuscated.
# Also renames all the string functions and places them in a component.

import gc
import re

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_X86,
    UC_MODE_64,
    UC_PROT_ALL,
    UC_HOOK_MEM_INVALID
)
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
    UC_X86_REG_R14,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX

)
COMPONENT_NAME = 'GarbleStringFunctions'

def decrypt(code):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    def hook_mem_invalid(uc, access, address, size, value, user_data):
        print("handling memory error")
        rip = uc.reg_read(UC_X86_REG_RIP)
        #tmp_code = uc.mem_read(rip, 15)
        # insn = next(cs.disasm(tmp_code, 0))
        print(f"\tRIP: {hex(rip)}")
        print(f"\tRead address: {hex(address)}")
        print(f"\tRead size: {size}")
        print(f"\tInstruction size: {insn.size}")
        #print(f"\t{insn.mnemonic}\t{insn.op_str}")
        #uc.mem_write(rip, b'\x90'*insn.size)
        #memory_fails.append((address,size))
        return False
    
    uc.hook_add(UC_HOOK_MEM_INVALID , hook_mem_invalid)

    # Setup the stack
    stack_base = 0x00100000
    stack_size = 0x00100000
    RSP = stack_base + (stack_size // 2)
    uc.mem_map(stack_base, stack_size)
    uc.mem_write(stack_base, b"\x00" * stack_size)

    uc.reg_write(UC_X86_REG_RSP, RSP)

    # Setup code 
    target_base = 0x00400000
    target_size = 0x00100000
    target_end = target_base + len(code)

    uc.mem_map(target_base, target_size, UC_PROT_ALL)
    uc.mem_write(target_base, b"\x00" * target_size)
    uc.mem_write(target_base, code)


    data_base = 0x00600000
    data_size = 0x00100000

    uc.mem_map(data_base, data_size, UC_PROT_ALL)
    uc.mem_write(data_base, b"\x00" * data_size)

    uc.reg_write(UC_X86_REG_R14, data_base)
    uc.emu_start(target_base, target_end, 0, 0)

    #print(uc.mem_read(stack_base, stack_size).replace(b'\x00', b''))
    ptr_string = uc.reg_read(UC_X86_REG_RBX)
    size = uc.reg_read(UC_X86_REG_RCX)
    string_data = uc.mem_read(ptr_string, size)
    try:
        string = string_data.decode('utf-8')
    except UnicodeDecodeError as exc:
        print(f'Failed to decode bytes: {string_data.hex()}')
        return None
    del uc
    gc.collect()
    return string

def is_string_func(raw: bytes) -> bool:
    egg =  rb'\x48\x8D\x5C..\xB9'
    for m in re.finditer(egg, raw, re.DOTALL):
        end = m.end()
        tmp_data = raw[:end]
        start = tmp_data.rfind(b'\x49\x3B\x66\x10\x0F\x86')
        if start == -1:
            # can probably break here
            return False
        # if we get thsi far we got a match
        return True
    return False

def collect_string_functions(target_func: binaryninja.function.Function) -> list[binaryninja.function.Function]:

    string_functions = []
    for func in target_func.callers:
    
        start = func.start
        size = func.highest_address - func.lowest_address
        func_bytes = bv.read(start, size)
        
        # check all bytes for 
        if is_string_func(func_bytes):
            string_functions.append(func)
    
    return string_functions

def add_comments(func: binaryninja.function.Function, s: str):
    comment = f'Result String: {s}'
    func.comment = comment
    for site in func.caller_sites:
        bv.set_comment_at(site.address, comment)


def find_slicebytetostring() -> binaryninja.function.Function:
    # meed a signature or something to make this entirely automated
    functions = bv.get_functions_by_name('runtime_slicebytetostring')
    if functions:
       target_func = functions[0]
    else:
        addr = get_int_input("Address of runtime_slicebytetostring function: ", "Ungarble Strings")
        target_func = bv.get_function_at(addr)

    return target_func

def main():

    print("++ Starting Garble String Deobfuscation ++ ")
    target_func = find_slicebytetostring() 
    if not target_func:
        print("Failed to find runtime_slicebytetostring function. Exiting.")
        return

    string_functions = collect_string_functions(target_func)

    state = bv.begin_undo_actions()

    counter = 0
    success = 0
    component = bv.get_component_by_path(COMPONENT_NAME)
    for func in string_functions:
        end = 0
        for site in func.call_sites:
            if site.mlil.dest.value.value == target_func.start:
                #print(f'found byteslice call: {site.address:#x}')
                end = site.address

        if end:
            counter += 1
            start = func.start
            size = end - start
            func_bytes = bv.read(start, size)
            try:
                s = decrypt(func_bytes)
                if s:
                    success += 1
                    func.name = f'StringDeobfuscate_{counter}'
                    add_comments(func, s)

                    if not component:
                        component = bv.create_component(COMPONENT_NAME)

                    component.add_function(func)
            except UcError as exc:
                print(f'emulation failed on: {start:#x}')
                func.name = f'StringDeobfuscate_FAIL_{counter}'
        else:
            print(f'No end found: {func.start:x}')

    bv.commit_undo_actions(state)

    print(f'String successfully deobfuscated: {success}')
    # only count funcs where we found byteslicetostring
    print(f'Total string functions: {counter}')

main()