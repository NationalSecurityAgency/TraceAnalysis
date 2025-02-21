import json, os
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

fns = {}
calls = {}
bbs = {}
succs = {}
members = {}

fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)
monitor = ConsoleTaskMonitor()
blockModel = BasicBlockModel(currentProgram)

for f in functions:
    addr = f.getEntryPoint().getOffset()
    low = f.getBody().getMinAddress().getOffset()
    hi = f.getBody().getMaxAddress().getOffset()
    fns[addr] = {"_key":str(addr),"namespace":f.getParentNamespace().getName(), "name":f.getName(), "addr":addr, "start":low, "end":hi}
    for ref in getReferencesTo(f.getEntryPoint()):
        xf = getFunctionContaining(ref.getFromAddress())
        if xf is None:
            continue
        fstart = xf.getEntryPoint().getOffset()
        calls[fstart] = {"_from":"functions/{}".format(xf.getEntryPoint().getOffset()), "_to":"functions/{}".format(addr), "callsite":ref.getFromAddress().getOffset()}
    blocks = blockModel.getCodeBlocksContaining(f.getBody(), monitor)
    while blocks.hasNext():
        bb = blocks.next()
        baddr = bb.getMinAddress().getOffset()
        bendaddr = bb.getMaxAddress().getOffset()
        bbs[baddr] = {"_key":str(baddr), "addr":baddr, "end":bendaddr}

        membersrc = "blocks/{}".format(baddr)
        memberdst = "functions/{}".format(addr)
        members["{}_{}".format(membersrc, memberdst)] = {"_from":membersrc, "_to":memberdst}

        successors = bb.getDestinations(monitor)
        while successors.hasNext():
            s = successors.next()
            ft = s.getFlowType()
            if ft.isJump() or ft.isConditional() or ft.isFallthrough():
                succsrc = "blocks/{}".format(s.getDestinationAddress().getOffset())
                succdst = "blocks/{}".format(baddr)

                succs["{}_{}".format(succsrc,succdst)] = {"_from":succsrc,"_to":succdst}

basepath = "/tmp"
with open(os.path.join(basepath, "block.jsonl"), "w") as f:
    for k in sorted(bbs.keys()):
        f.write(json.dumps(bbs[k])+"\n")
with open(os.path.join(basepath, "function.jsonl"), "w") as f:
    for k in sorted(fns.keys()):
        f.write(json.dumps(fns[k])+"\n")
with open(os.path.join(basepath, "callerof.jsonl"), "w") as f:
    for k in sorted(calls.keys()):
        f.write(json.dumps(calls[k])+"\n")
with open(os.path.join(basepath, "successorof.jsonl"), "w") as f:
    for k in sorted(succs.keys()):
        f.write(json.dumps(succs[k])+"\n")
with open(os.path.join(basepath, "blockof.jsonl"), "w") as f:
    for k in sorted(members.keys()):
        f.write(json.dumps(members[k])+"\n")
