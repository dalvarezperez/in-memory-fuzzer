from my_debugger_defines import *
import csv
import os
import pefile

from my_debugger import *

class param_dumper(debugger):
    def dump_function_parameter(self, function_name, num_param, value):
        os.mkdir("parameters") if not os.path.exists("parameters") else None
        f=open("parameters"+os.sep+function_name+"_"+str(num_param), "wb")
        f.write(value)
        f.close()

    def exception_handler_breakpoint(self):
        print("[*] Exception address: 0x%08x" % self.exception_address)
        # check if the breakpoint is one that we set
        if self.exception_address not in self.breakpoints:
                if self.first_breakpoint == True:
                    self.first_breakpoint = False
                    print("[*] Hit the first breakpoint.")
        else:
            print("[*] Hit user defined breakpoint.")
            # this is where we handle the breakpoints we set 
            # first put the original byte back
            self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address][1])
            self.functions_file_descriptor.seek(0)
            reader =  csv.reader(self.functions_file_descriptor, delimiter=';')
            for row in reader:
                function_address_hex_str = row[1]
                if(function_address_hex_str == "Address"):
                    continue
                function_address = int("0x"+function_address_hex_str,0)
                if function_address == self.exception_address:
                    if(len(row[4].split(","))<2):
                        continue
                    function           = row[0]
                    num_parameters     = row[4].split(",")[1]
                    calling_convention = row[2]
                    print("[-] Breakpoint hit in the function " + function + " which receives " + num_parameters + " parameters and uses " + calling_convention + " calling convention")
                    if(function!="strcpy"):
                        continue
                    if(calling_convention == "__cdecl"):
                        # cdecl means parameters pass by register
                        self.context = self.get_thread_context(h_thread=self.h_thread)
                        if not self.context:
                            continue
                        array_params = [self.context.Rcx, self.context.Rdx, self.context.Rax]
                        for num_param in range(int(num_parameters)):
                            # print(hex(array_params[num_param]))
                            bytes_readed = self.read_process_memory(array_params[num_param], 40)
                            if not bytes_readed:
                                continue
                            print("  [-] Parameter {}: {}".format(str(num_param), ''.join(format(x, '02x') for x in bytes_readed)))
                            self.dump_function_parameter(function, num_param, bytes_readed)
                    else:
                        print("    [!] Calling convetion currently not supported.")
            #self.context = self.get_thread_context(h_thread=self.h_thread)
            #self.context.Eip -= 1
            #kernel32.SetThreadContext(self.h_thread,byref(self.context))
        return DBG_CONTINUE