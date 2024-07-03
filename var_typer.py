from binaryninja import *

api_call_protos = {}


for typelib in bv.type_libraries:
    for name, obj in typelib.named_objects.items():
        if not isinstance(obj, FunctionType):  # filter for function calls
            continue
        api_call_protos[name.name[0]] = obj

bv.begin_undo_actions()

for func in bv.functions:
    for var in func.vars:
        if var.name in api_call_protos.keys():
            proto = api_call_protos[var.name]
            proto_pointer = PointerType.create(bv.arch, proto)
            var.type = proto_pointer

bv.commit_undo_actions()