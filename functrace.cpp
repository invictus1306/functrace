#include "utils.h"
#include "drmgr.h"
#include "drsyms.h"
#include "drwrap.h"
#include "dr_defines.h"
#include "bb_getinfo.h"

#include <stddef.h>
#include <iostream>
#include <list>
#include <algorithm>
#include <string.h>
#include <fstream>
#include <signal.h>

static void *mod_lock;
static void *wrap_lock;
static file_t fd;
static size_t towrap = 0;

typedef struct option_t {
    bool disassembly;
    bool verbose;
    bool disassembly_function;
    bool is_cbr;
    char function_name[LEN];
    bool report_file;
    char report_file_name[LEN];
    bool wrap_function;
    char wrap_function_name[LEN];
    size_t wrap_function_args;
} option_t;

static option_t options;

static void wrap_pre(void *wrapcxt, OUT void **user_data) {
    size_t i;

    dr_mutex_lock(wrap_lock);
    for (i = 0; i < options.wrap_function_args; i++) {
        app_pc arg = (app_pc) drwrap_get_arg(wrapcxt, i);
        DR_ASSERT(arg);
        dr_fprintf(fd, "[ARG];%s;%d;"PFX"\n", options.wrap_function_name, i, arg);
    }
    dr_mutex_unlock(wrap_lock);
}

static void wrap_post(void *wrapcxt, void *user_data) {
    dr_mutex_lock(wrap_lock);
    
    app_pc ret = (app_pc) drwrap_get_retval(wrapcxt);
    
    dr_fprintf(fd, "[RET];%s;"PFX"\n", options.wrap_function_name, ret);
    
    dr_mutex_unlock(wrap_lock);
}

static void iterate_imports(const module_data_t *mod)
{
    const char *mod_name = dr_module_preferred_name(mod);

    dr_symbol_import_iterator_t *imp_iter =
        dr_symbol_import_iterator_start(mod->handle, NULL);
    while (dr_symbol_import_iterator_hasnext(imp_iter)) {
        dr_symbol_import_t *sym = dr_symbol_import_iterator_next(imp_iter);
        dr_fprintf(fd, "Name %s\n", sym->name);
    }
    dr_symbol_import_iterator_stop(imp_iter);
}

static bool enumerate_sym(const char *name, size_t modoffs, void *data) {
    if (*name != 0) {
        if (options.verbose){
            dr_fprintf(fd, "Offset: %x Name: %s\n", modoffs, name);
        }
        if (!strcmp(name, options.wrap_function_name)) {
            towrap = modoffs;
        }
    }
    return true;
}

static void event_module_load(void *drcontext, const module_data_t *mod, bool loaded) {
    app_pc mod_base = mod->start;
    module_data_t *data = dr_get_main_module();

    if (data == NULL) {
        dr_fprintf(fd, "[ERR] No main module found! \n");
        return;
    }
    
    const char *module_name = mod->names.file_name;

    if (module_name == NULL) {
        module_name = dr_module_preferred_name(mod);
    }

    if (options.verbose)
        dr_fprintf(fd, "[MOD] Module name: %s - Full path: %s \n", module_name, mod->full_path);

    if (mod_base != data->start) {
        dr_free_module_data(data);
        return;
    }

    drsym_error_t symr;
    
    if (options.verbose) {
        dr_fprintf(fd, "[IMPORTS]: \n");
        iterate_imports(mod);
        dr_fprintf(fd, "[EXPORTS]: \n");
    }

    symr = drsym_enumerate_symbols(mod->full_path, enumerate_sym, NULL, DRSYM_DEFAULT_FLAGS);
    if (symr != DRSYM_SUCCESS && options.verbose)
        dr_fprintf(fd, "[ERR] search / enum error %d\n", symr);

    if (options.wrap_function) {
        bool wrapped = false;
        app_pc to_wrap = mod_base + towrap;
        
        if (towrap != 0) {
            wrapped = drwrap_wrap(to_wrap, wrap_pre, wrap_post);
            DR_ASSERT(wrapped);
        }
    }

    dr_free_module_data(data);
}

static void cbr_func(app_pc src, app_pc targ) {
    dr_mcontext_t mcontext = {sizeof(mcontext),DR_MC_ALL,};
    void *drcontext = dr_get_current_drcontext();

    dr_flush_region((app_pc)src, (size_t)targ - (size_t)src);
    dr_get_mcontext(drcontext, &mcontext);
    mcontext.pc = (app_pc)targ;
    dr_redirect_execution(&mcontext);
}

static dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating, OUT void **user_data) {
    instr_t *instr;
    instr_t *last;
    module_data_t *data;
    module_data_t *mod;
    char *ret_function;
    
    drsym_error_t symres;

    instr = instrlist_first_app(bb);
    last = instrlist_last_app(bb);

    if (instr == NULL || last == NULL)
        return DR_EMIT_DEFAULT;

    app_pc pc = instr_get_app_pc(instr);
    app_pc last_instr = instr_get_app_pc(last);
    app_pc next_instr = (app_pc)decode_next_pc(drcontext, (byte *)pc);

    if (pc == NULL || last_instr == NULL)
        return DR_EMIT_DEFAULT;

    mod = dr_lookup_module(pc);
    
    if (mod == NULL)
        return DR_EMIT_DEFAULT;
            
    app_pc mod_base = mod->start;

    data = dr_get_main_module();

    if (data == NULL)
        return DR_EMIT_DEFAULT;

    if (mod_base != data->start)
        return DR_EMIT_DEFAULT;

    if (options.is_cbr) {
        if (instr_is_cbr(last)) {
            dr_mutex_lock(mod_lock);

            app_pc next_instr = (app_pc)decode_next_pc(drcontext, (byte *)last_instr);

            ret_function = get_info(drcontext, pc, mod, last_instr, fd);

            if (options.disassembly && !options.disassembly_function)
                instrlist_disassemble(drcontext, (app_pc)tag, bb, fd);
            else if ((!options.disassembly && options.disassembly_function) && !strcmp(options.function_name, ret_function))
                instrlist_disassemble(drcontext, (app_pc)tag, bb, fd);

            dr_insert_clean_call(drcontext, bb, NULL,
                                (void*)cbr_func,
                                false,
                                2,
                                OPND_CREATE_INTPTR(pc),
                                OPND_CREATE_INTPTR(next_instr));

            free(ret_function);
            dr_free_module_data(mod);
            dr_free_module_data(data);

            dr_mutex_unlock(mod_lock);

            return DR_EMIT_STORE_TRANSLATIONS;
        }
    }
    
    dr_mutex_lock(mod_lock);
        
    ret_function = get_info(drcontext, pc, mod, last_instr, fd);

    if (options.disassembly && !options.disassembly_function)
        instrlist_disassemble(drcontext, (app_pc)tag, bb, fd);
    else if ((!options.disassembly && options.disassembly_function) && !strcmp(options.function_name, ret_function))
        instrlist_disassemble(drcontext, (app_pc)tag, bb, fd);

    free(ret_function);
    dr_free_module_data(mod);
    dr_free_module_data(data);

    dr_mutex_unlock(mod_lock);

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

    free_drsmy();
    
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
    dr_printf("  -cbr\t\t\t\t\t\t remove the bb from the cache (in case of conditional jump)\n");
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
    options.is_cbr = false;
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
            if (strlen(elem) < LEN) {
                options.disassembly_function = true;
                memcpy(options.function_name, elem, LEN);
            }
        }
        else if (strcmp(elem, "-report_file") == 0){
            USAGE_CHECK((i + 1) < argc, "missing report file");
            elem = argv[++i];
            if (strlen(elem) < LEN) {
                options.report_file = true;
                memcpy(options.report_file_name, elem, LEN);
            }
        }
        else if (strcmp(elem, "-wrap_function") == 0){
            USAGE_CHECK((i + 1) < argc, "missing function to wrap");
            elem = argv[++i];
            if (strlen(elem) < LEN) {
                options.wrap_function = true;
                memcpy(options.wrap_function_name, elem, LEN);
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
        }
        else if (strcmp(elem, "-cbr") == 0) {
            options.is_cbr = true;
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
        dr_printf("The report file name is required!\n");
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