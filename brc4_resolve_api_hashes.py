#
#
import json
from typing import Any, Optional, cast

def resolve_hash(api_data: dict[str, Any], target_hash: str) -> Optional[str]:
    for dll_hash, dll_data in api_data.items():
           for func_hash, func_name in dll_data['exports'].items():
               if func_hash == target_hash:
                   print(f'Found: {func_name}')
                   return func_name

def set_global_name_and_type(bv, variable, func_name, proto_pointer):
    try:
        vrefs = variable.function.get_mlil_var_refs(variable)
    except AttributeError as e:
        print(f'ERROR {func_name}\t{e}')
        return
    for ref in vrefs:
        r = ReferenceSource(function=ref.func, arch=ref.arch, address=ref.address)
        if isinstance(r.mlil, MediumLevelILStore) and isinstance(r.mlil.dest, MediumLevelILConstPtr):
            global_var = bv.get_data_var_at(r.mlil.dest.value.value)
            global_var.name = func_name
            if proto_pointer:
                global_var.type = proto_pointer
    
def init_api_dict(bv):
    api_call_protos = {}
    for typelib in bv.type_libraries:
        for name, obj in typelib.named_objects.items():
            if not isinstance(obj, FunctionType):  # filter for function calls
                continue
            api_call_protos[name.name[0]] = obj

    return api_call_protos

def add_enum(bv, enum_name, enum_width, enum_value, func_name):
    # link to where this came from
    existing_type = bv.types.get(enum_name)
    if not existing_type:
        new_enum = EnumerationBuilder.create(width=enum_width)
        new_enum.append(func_name, enum_value)
        bv.define_user_type(name=QualifiedName(enum_name), type_obj=new_enum)
    else:
        if existing_type.type_class == TypeClass.EnumerationTypeClass:
            with Type.builder(bv, QualifiedName(enum_name)) as existing_enum:
                existing_enum = cast(EnumerationBuilder, existing_enum)  # typing
                # In Binary Ninja, enumeration members are not guaranteed to be unique.
                # It is possible to have 2 different enum members
                # with exactly the same name and the same value.
                # Therefore, we must take care to _replace_ any existing enum member
                # with the same name as the enum member we would like to add,
                # rather than _appending_ a duplicate member with the same name.

                # Create a list of member names to use for lookup.
                # EnumerationBuilder.replace requires a member index as an argument,
                # so we must save the original member index as well.
                
                        # Enum member with this name doesn't yet exist
                existing_enum.append(
                    func_name,  # new name
                    enum_value,  # new value
                    )



function_addr = get_int_input("Enter API resolution function address:", "BRC4 Helper")

json_file = interaction.get_open_filename_input('Select API Hash json file')

api_call_protos = init_api_dict(bv)


with open(json_file, 'r') as fd:
    api_data = json.load(fd)

bv.begin_undo_actions()
bv.set_analysis_hold(True)

target_func = bv.get_function_at(function_addr)
print(target_func)
for xref in target_func.caller_sites:
    if isinstance(xref.mlil, MediumLevelILCall):
        dest_variable = xref.mlil.output[0]
        # 2nd param
        hash_var = xref.mlil.params[0]
        if not isinstance(hash_var, MediumLevelILConst):
            continue
        target_hash = hash_var.value.value
        func_name = resolve_hash(api_data, f'{target_hash:#x}')
        if func_name:
            dest_variable.name = func_name
            add_enum(bv, 'BRC4_API_HASH', 4, target_hash, func_name)
            
            proto_pointer = None
            if func_name in api_call_protos.keys():
                proto = api_call_protos[func_name]
                proto_pointer = PointerType.create(bv.arch, proto)
                dest_variable.type = proto_pointer
                print(proto_pointer)
                print(f'set pointer for {func_name}')
            else:
                print(f'No type for {func_name}')

            set_global_name_and_type(bv, dest_variable, func_name, proto_pointer)

bv.commit_undo_actions()
bv.set_analysis_hold(False)
bv.update_analysis_and_wait()
