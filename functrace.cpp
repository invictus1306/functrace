#include "dr_api.h"
#include "drmgr.h"
#include "drsyms.h"
#include "drwrap.h"
#include "dr_defines.h"
#include "utils.h"

#include <stddef.h>
#include <iostream>
#include <list>
#include <algorithm>
#include <string.h>
#include <fstream>
#include <signal.h>

#define len 256

static void *mod_lock;
static void *wrap_lock;
static file_t fd;
static size_t towrap;
static drsym_info_t *syminfo;

typedef struct option_t {
    bool disassembly;
    bool verbose;
    bool disassembly_function;
    char function_name[len];
    bool report_file;
    char report_file_name[len];
    bool wrap_function;
    char wrap_function_name[len];
    size_t wrap_function_args;
} option_t;

static option_t options;

struct funct {
    const char *name_function;
    size_t start_addr;
    size_t end_addr;
    size_t pc;
};

static void wrap_pre(void *wrapcxt, OUT void **user_data) {
    size_t i;

    dr_mutex_lock(wrap_lock);
    for (i = 0; i < options.wrap_function_args; i++) {
        uint64 arg = (uint64) drwrap_get_arg(wrapcxt, i);
        DR_ASSERT(arg);
        dr_fprintf(fd, "[ARG] Function: %s Arg %d: 0x%llx \n\n", options.wrap_function_name, i, arg);
    }
    dr_mutex_unlock(wrap_lock);
}

static void wrap_post(void *wrapcxt, void *user_data) {
    dr_mutex_lock(wrap_lock);
    
    uint64 ret = (uint64) drwrap_get_retval(wrapcxt);
    
    dr_fprintf(fd, "[RET] Function: %s ret_value: 0x%llx \n\n", options.wrap_function_name, ret);
    
    dr_mutex_unlock(wrap_lock);
}

static bool enumerate_sym(const char *name, size_t modoffs, void *data) {
    if (*name!=0) {
        if (options.verbose)
            dr_fprintf(fd, "Offset: %x Name: %s\n", modoffs, name);
        if (!strcmp(name, options.wrap_function_name))
            towrap = modoffs;
    }
    return true;
}

static void event_module_load(void *drcontext, const module_data_t *mod, bool loaded) {
    app_pc mod_base = mod->start;
    module_data_t *data = dr_get_main_module();
    

    const char *module_name = mod->names.file_name;

    if (module_name == NULL) {
        module_name = dr_module_preferred_name(mod);
    }

    if (options.verbose)
        dr_fprintf(fd, "Module name: %s - Full path: %s \n", module_name, mod->full_path);


    if (mod_base != data->start)
        return;

    drsym_error_t symr;
    symr = drsym_enumerate_symbols(mod->full_path, enumerate_sym, NULL, DRSYM_DEFAULT_FLAGS);
    DR_ASSERT(symr == DRSYM_SUCCESS); 

    if (options.wrap_function) {
        bool wrapped = false;
        towrap = (size_t)mod_base + towrap;
        
        if (towrap != 0) {
            wrapped = drwrap_wrap((app_pc)towrap, wrap_pre, wrap_post);
        }

        if (wrapped) {
            dr_fprintf(STDERR, "WRAPPED function: %s \n", options.wrap_function_name);
        } else {
            dr_fprintf(STDERR, "FAILED to wrap %s \n", options.wrap_function_name);
        }
    }

    dr_free_module_data(data);
}

static drsym_info_t* drsym_obj() {
    drsym_info_t* drsym_o;
    drsym_o = (drsym_info_t*)malloc(sizeof(drsym_info_t));
    drsym_o->struct_size = sizeof(drsym_info_t);
    drsym_o->debug_kind = DRSYM_SYMBOLS;    
    drsym_o->name_size = len;
    drsym_o->file_size = len;
    drsym_o->file=(char*)malloc(len);
    drsym_o->name=(char*)malloc(len);
    return drsym_o;
}
 
static void free_drsmy_obj(drsym_info_t * drsym_o) {
    if (drsym_o->file != NULL) 
        free(drsym_o->file);
    if (drsym_o->name != NULL) 
        free(drsym_o->name);
    free(drsym_o);
}

static dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating, OUT void **user_data) {
    instr_t *instr;
    module_data_t *data;
    module_data_t *mod;
    struct funct functions;

    drsym_error_t symres;
    
    instr  = instrlist_first_app(bb);
    app_pc pc = instr_get_app_pc(instr);

    data = dr_get_main_module();
    mod = dr_lookup_module(pc);
    
    app_pc mod_base = mod->start;
    
    if (mod_base != data->start)
        return DR_EMIT_DEFAULT;
    
    dr_mutex_lock(mod_lock);

    syminfo = drsym_obj();

    drsym_info_t *  info;
    size_t offset = (size_t)pc - (size_t)mod_base;
    syminfo->start_offs = 0;
    syminfo->end_offs = 0;
    symres = drsym_lookup_address(mod->full_path, offset, syminfo, DRSYM_DEMANGLE);

    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        functions.name_function = syminfo->name;
        functions.start_addr = syminfo->start_offs + (size_t)mod_base;
        functions.end_addr = syminfo->end_offs + (size_t)mod_base;
        functions.pc = (size_t)pc;
        dr_fprintf(fd, "[ADDR] Start address: 0x%x End Address: 0x%x PC: 0x%x Function: %s\n", functions.start_addr, functions.end_addr, functions.pc, functions.name_function);
        if (options.disassembly && !options.disassembly_function)
            instrlist_disassemble(drcontext, (app_pc)tag, bb, fd);
        if (!options.disassembly && options.disassembly_function && !strcmp(options.function_name, functions.name_function)){
            instrlist_disassemble(drcontext, (app_pc)tag, bb, fd);
        }
    }
    else {
        functions.pc = (size_t)pc;
        dr_fprintf(fd, "[NOSYM] PC: 0x%x Function: NoSym\n", functions.pc);
        if (options.disassembly && !options.disassembly_function)
            instrlist_disassemble(drcontext, (app_pc)tag, bb, fd);
    }

    dr_fprintf(fd, "\n");
    dr_mutex_unlock(mod_lock);

    dr_free_module_data(data);
    dr_free_module_data(mod);

    return DR_EMIT_DEFAULT;
}

static dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *info) {
    if (info->sig == SIGTERM) {
        return DR_SIGNAL_SUPPRESS;
    } else if (info->sig == SIGSEGV || info->sig == SIGBUS || info->sig == SIGABRT) {
        dr_fprintf(fd, "[CRASH] signal number %d\n", info->sig);
    }        

    return DR_SIGNAL_DELIVER;
}

static void event_exit(void) {    
    dr_mutex_destroy(mod_lock);
    dr_mutex_destroy(wrap_lock);
    
    free_drsmy_obj(syminfo);
    dr_close_file(fd);

    drmgr_exit();
    drsym_exit();
    drwrap_exit();
}

static void usage() { 
    dr_printf("  -disassembly\t\t\t\t\t disassemble all the functions\n");
    dr_printf("  -disas_func function_name\t\t\t disassemble only the function function_name\n");      
    dr_printf("  -wrap_function function_name\t\t\t wrap the function function_name\n");                       
    dr_printf("  -wrap_function_args num_args\t\t\t number of arguments of the wrapped function\n");
    dr_printf("  -report_file file_name\t\t\t report file name\n");
    dr_printf("  -verbose\t\t\t\t\t verbose true\n");
}

static void options_init(int argc, const char *argv[]) {
    size_t i;
    const char *disassembly;
    const char *elem;
    
    if (argc < 2) {
        dr_printf("Invalid options!\n");
        usage();
        dr_abort();
    }

    options.disassembly = false;
    options.verbose = false;
    options.disassembly_function = false;
    options.report_file = false;
    options.wrap_function = false;
    options.wrap_function_args = 0;
    
    for (i = 1; i < argc; i++) {
        elem = argv[i];
        if (strcmp(elem, "-disassembly") == 0)
            options.disassembly = true;
        else if (strcmp(elem, "-verbose") == 0)
            options.verbose = true;
        else if (strcmp(elem, "-disas_func") == 0){
            USAGE_CHECK((i + 1) < argc, "missing disassembly function");
            elem = argv[++i];
            if (strlen(elem) < len) {
                options.disassembly_function = true;
                memcpy(options.function_name, elem, len);
            }
        }
        else if (strcmp(elem, "-report_file") == 0){
            USAGE_CHECK((i + 1) < argc, "missing report file");
            elem = argv[++i];
            if (strlen(elem) < len) {
                options.report_file = true;
                memcpy(options.report_file_name, elem, len);
            }
        }
        else if (strcmp(elem, "-wrap_function") == 0){
            USAGE_CHECK((i + 1) < argc, "missing function to wrap");
            elem = argv[++i];
            if (strlen(elem) < len) {
                options.wrap_function = true;
                memcpy(options.wrap_function_name, elem, len);
            }
        }
        else if (strcmp(elem, "-wrap_function_args") == 0){
            USAGE_CHECK((i + 1) < argc, "missing function arguments number");
            elem = argv[++i];
            if (options.wrap_function){
                options.wrap_function_args = strtoul(elem, NULL, 0);
            } else {
                dr_printf("missing function to wrap!\n");
                dr_abort();
            }
        } else {
            dr_printf("Invalid option %s \n", elem);
            dr_abort();
        }
    }
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("functrace", "@invictus1306");
    
    options_init(argc, argv);

    drmgr_init();
    drsym_init(0);
    drwrap_init();
    drmgr_register_signal_event(event_signal);

    disassemble_set_syntax(DR_DISASM_INTEL);

    mod_lock = dr_mutex_create();
    wrap_lock = dr_mutex_create();

    if (!options.report_file) {
        dr_printf("report file name required!\n");
        dr_abort();
    }

    fd = dr_open_file(options.report_file_name, DR_FILE_WRITE_OVERWRITE);
    if (fd == INVALID_FILE) {
        dr_printf("Unable to open log file %s\n", options.report_file_name);
        dr_abort();
    }
    
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_bb_instrumentation_event(event_bb_analysis, NULL, NULL);
}