#
import json

RC4_KEY = '{-l," +r3/#~&;v_'.encode('utf-8')
RC4 = Transform['RC4']

def find_encrypted_string(bv, ssa_var, input_len):
    ssa_func = ssa_var.function.ssa_form
    #ssa_def = ssa_func.get_ssa_var_definition(ssa_var)
    #print(ssa_func.get_ssa_var_uses(ssa_var))
    mv = ssa_func.get_ssa_memory_definition(ssa_var.ssa_memory_version)
    ct_int = mv.operands[2].value.value
    ct = ct_int.to_bytes(input_len, byteorder='little')
    return ct


def add_type_library(bv, module_name) -> bool:
    ret_val = False
    libraries = bv.platform.get_type_libraries_by_name(f'{module_name}.dll')
    if not libraries:
        return
    
    for library in libraries:
        if library.arch == bv.arch:
            bv.add_type_library(library)
            print(f'Loaded: {library}')
            ret_val = True

    return ret_val

    
# rc4 decrypt function
function_addr = get_int_input("Enter API resolution function address:", "BRC4 Helper")
json_file = interaction.get_open_filename_input('Select API Hash json file')

modules = []

with open(json_file, 'r') as fd:
    api_data = json.load(fd)

target_func = bv.get_function_at(function_addr)
print(target_func)
for xref in target_func.caller_sites:
    if isinstance(xref.mlil, MediumLevelILCall):
        key = xref.mlil.params[0]
        if isinstance(key, MediumLevelILConstPtr):
            if key.value.value == 0:
                hash_var = xref.mlil.params[2]
                input_len = xref.mlil.params[4].value.value
                ct = find_encrypted_string(bv, hash_var.ssa_form, input_len)
                pt = RC4.decode(ct, {'key': RC4_KEY})
                try:
                    modules.append(pt.decode('utf-8'))
                except:
                    continue

for module_name in modules:
    success = add_type_library(bv, module_name)
    if not success:
        print(f'Could not find type library for {module_name}')
                
               
        
