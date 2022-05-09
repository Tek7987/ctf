from capstone import *
import sys

groups = dict(zip([CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET, CS_GRP_INVALID, CS_GRP_PRIVILEGE],
        ["CS_GRP_JUMP", "CS_GRP_CALL", "CS_GRP_RET", "CS_GRP_INT", "CS_GRP_IRET"]))

def isInvalid(ins):
    forbidden = [CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT,
        CS_GRP_IRET] # CS_GRP_BRANCH_RELATIVE only exists in C
    return any(filter(lambda group: group in forbidden, ins.groups))

def check(SC):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    ok = True
    for i in md.disasm(SC, 0):
        for g in i.groups:
            try:
                print(groups[g], end=" ")
            except KeyError:
                pass
        print(i)

        ok &= not isInvalid(i)
    return ok and (SC == SC[::-1])

SC = bytes.fromhex(open(sys.argv[1]).read().strip())
SC += SC[::-1]
print(len(SC))

assert len(SC) <= 1024

prolog = bytes.fromhex("4831C04831DB4831C94831D24831FF4831F64D31C04D31C94D31D24D31DB4D31E44D31ED4D31F64D31FF4831ED")
epilog = bytes.fromhex("0f05")
print(SC.hex())
with open("shellcode", "wb") as f:
    f.write(prolog + SC + epilog)

print(check(SC))


