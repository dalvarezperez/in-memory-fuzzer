from threading import Thread
from io import StringIO
import subprocess
import os
import csv
from config import *
import my_debugger_param_dumper
import my_debugger_inmemory_fuzzer

# 1. Perform lightweigh analysis on the put and write the analysis into the appropriate CSV file
open(INTERNAL_ANALYSIS_PUT_PATH, 'w').close()
subprocess.call([GHIDRA_HEADLESS_PATH, GHIDRA_PROJECT_DIR_PATH, GHIDRA_PROJECT_NAME, "-import", PUT_PATH, "-postScript", GHIDRA_SCRIPT_PATH, "-scriptlog", INTERNAL_ANALYSIS_PUT_PATH, "-overwrite"])
with open(INTERNAL_ANALYSIS_PUT_PATH,"rt") as f: lines = f.readlines()
scsv = ""
for l in lines:
  if(".py> " in l):
    scsv += l.split(".py> ")[1]
#print(scsv)

# 2. Initialize the param_dumper
param_dumper = my_debugger_param_dumper.param_dumper()
param_dumper.load(bytes(PUT_PATH+"\x00", encoding='utf8'))

# 3. Extract parameters
f = StringIO(scsv)
reader = csv.reader(f, delimiter=';')
for row in reader:
    if(row[0] in FUNCTIONS_INTRODUCED_BY_MINGW):
        continue # if the function was introduced by the compiler, we skip it
    if(row[1]=="Address"):
        continue
    function_address_hex_str = row[1]
    function_address = int("0x"+function_address_hex_str,0)
    param_dumper.bp_set(function_address)

param_dumper.debugger_active = True
param_dumper.run()

# 4. put breakpoints in the functions that was not covered
f = StringIO(scsv)
reader = csv.reader(f, delimiter=';')
functions_to_test = []
for row in reader:
    if(row[0] in FUNCTIONS_INTRODUCED_BY_MINGW):
        continue # if the function was introduced by the compiler, we skip it
    if(os.path.exists("parameters"+os.sep+row[0]+"_0")):
        continue
    if(row[1]=="Address"):
        continue
    function_address_hex_str = row[1]
    function_address = int("0x"+function_address_hex_str,0)
    functions_to_test.append(function_address)
for func in functions_to_test:
    print("It is neccessary to test: "+ hex(func))

# 5. Run the debugger with the flags debugger_active and fuzzing_mode enabled
inmemory_fuzzer = my_debugger_inmemory_fuzzer.inmemory_fuzzer()
inmemory_fuzzer.load(bytes(PUT_PATH+"\x00", encoding='utf8'))
inmemory_fuzzer.debugger_active = True
inmemory_fuzzer.run()