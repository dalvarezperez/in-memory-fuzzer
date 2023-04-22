from my_debugger import *
import pefile


class inmemory_fuzzer(debugger):    
    def exception_handler_breakpoint(self):
        if self.context.Dr6 & 0x1 and 0 in self.hardware_breakpoints:
            slot = 0
        elif self.context.Dr6 & 0x2 and 1 in self.hardware_breakpoints:
            slot = 1
        elif self.context.Dr6 & 0x4 and 2 in self.hardware_breakpoints:
            slot = 2
        elif self.context.Dr6 & 0x8 and 3 in self.hardware_breakpoints:
            slot = 3
        else:
            #INT1 wasn't hw_breakpoint
            continue_status = DBG_EXCEPTION_NOT_HANDLED
        
        # removing breakpoint from list
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
            print("[*] Hardware breakpoint removed from list.")
        return continue_status
    
    def run(self):
        pe = pefile.PE(self.path_to_exe[:-1])
        entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if not self.bp_set_hw(entryPoint, 1, HW_EXECUTE):
            print("ERROR HW BP")
        super().run()