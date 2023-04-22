import configparser

config = configparser.ConfigParser()
config.read('config.ini')
sections = config.sections()

PUT_PATH = config['PUT']['path']
CMD_LINE = config['PUT']['arguments']
GHIDRA_HEADLESS_PATH = config['GHIDRA_SCRIPT']['headless_mode_path']
GHIDRA_SCRIPT_PATH = config['GHIDRA_SCRIPT']['ghidra_script_path']
GHIDRA_PROJECT_DIR_PATH = config['GHIDRA_SCRIPT']['project_dir_path']
GHIDRA_PROJECT_NAME = config['GHIDRA_SCRIPT']['project_name']
INTERNAL_ANALYSIS_PUT_PATH = config['GHIDRA_SCRIPT']['internal_analysis_put_path']
FUNCTIONS_INTRODUCED_BY_MINGW = ["_FindPESection", "__mingw_invalidParameterHandler", "pre_c_init", "pre_cpp_init", "__tmainCRTStartup", "WinMainCRTStartup", "mainCRTStartup", "_decode_pointer", "_encode_pointer", "_setargv", "__mingw_raise_matherr", "__mingw_setusermatherr", "_matherr", "__report_error", "__write_memory", "_pei386_runtime_relocator", "__mingw_SEH_error_handler", "__mingw_init_ehandler", "_gnu_exception_handler", "_fpreset", "__do_global_dtors", "__do_global_ctors", "__main", "__security_init_cookie", "__report_gsfailure", "__dyn_tls_dtor", "__dyn_tls_init", "__tlregdtor", "mingw_onexit", "atexit", "my_lconv_init", "_ValidateImageBase", "NonwritableInCurrentImage", "_ValidateImageBase", "2023-03-05 15:16:57 INFO  phd_ghidra_script.py> _FindPESection", "_FindPESectionByName", "__mingw_GetSectionForAddress", "__mingw_GetSectionCount", "_FindPESectionExec", "_GetPEImageBase", "_IsNonwritableInCurrentImage", "__mingw_enum_import_library_names", "__mingwthr_run_key_dtors", "___w64_mingwthr_add_key_dtor", "___w64_mingwthr_remove_key_dtor", "__mingw_TLScallback", "___chkstk_ms", "__C_specific_handler", "__set_app_type", "__getmainargs", "mingw_get_invalid_parameter_handler", "mingw_set_invalid_parameter_handler", "malloc", "strlen", "memcpy", "_cexit", "_amsg_exit", "_initterm", "exit", "__setusermatherr", "__iob_func", "fprintf", "fwrite", "vfprintf", "abort", "signal", "_lock", "__dllonexit", "_unlock", "_onexit", "strncmp", "calloc", "free", "Sleep", "SetUnhandledExceptionFilter", "GetStartupInfoA", "VirtualQuery", "VirtualProtect", "GetLastError", "RtlAddFunctionTable", "GetSystemTimeAsFileTime", "GetCurrentProcessId", "GetCurrentThreadId", "GetTickCount", "QueryPerformanceCounter", "RtlLookupFunctionEntry", "RtlVirtualUnwind", "UnhandledExceptionFilter", "GetCurrentProcess", "TerminateProcess", "EnterCriticalSection", "TlsGetValue", "LeaveCriticalSection", "DeleteCriticalSection", "InitializeCriticalSection"]