#TODO write a description for this script
#@author David Alvarez Perez
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import ScriptMessage
from java.io import *

def decompile_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    return ifc.decompileFunction(func, 60, monitor)

# Step 1. Get functions that call the target function ('callers')
target_addr = 0
fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True) # True means 'forward'
println("Function;Address;callingConvention;Caller;\"\"\"Address And Parameters\"\"\"")
for func in funcs:
    callers = []
    csv=""
    csv += ("{};{};".format(func.getName(), func.getEntryPoint()))
    target_addr = func.getEntryPoint()
    references = getReferencesTo(target_addr)
    for xref in references:
        call_addr = xref.getFromAddress()
        caller = getFunctionContaining(call_addr)
        callers.append(caller)
    
    # Step 2. Get calling convention
    csv += (str(func.getCallingConvention())+";")

    # deduplicate callers
    callers = list(set(callers))
    if None in callers:
        callers.remove(None)
    for caller in callers:
        csv += (str(caller)+";")
        # Step 3. Decompile all callers and find PCODE CALL operations leading to `target_add`
        res = decompile_function(caller)
        high_func = res.getHighFunction()
        lsm = high_func.getLocalSymbolMap()
        symbols = lsm.getSymbols()
        if high_func:
            opiter = high_func.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                mnemonic = str(op.getMnemonic())
                if mnemonic == "CALL":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    args = inputs[1:] # List of VarnodeAST types
                    if addr == target_addr:
                        csv+="{},{};".format(op.getSeqnum().getTarget(), len(args))
    println(csv)
