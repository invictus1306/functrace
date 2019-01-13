#include "utils.h"
#include "drsyms.h"
#include "bb_getinfo.h"

#include <string.h>

static drsym_info_t *syminfo;

struct funct {
    const char *name_function;
    app_pc start_addr;
    app_pc end_addr;
    app_pc pc;
};

drsym_info_t* drsym_obj(const char *path) {
    drsym_info_t *drsym_o;
    drsym_o = (drsym_info_t *)malloc(sizeof(drsym_info_t));
    drsym_o->struct_size = sizeof(drsym_info_t);
    drsym_debug_kind_t kind;
    drsym_error_t symres = drsym_get_module_debug_kind(path, &kind);
    if (symres == DRSYM_SUCCESS)
        drsym_o->debug_kind = kind;    
    drsym_o->name_size = LEN;
    drsym_o->file_size = LEN;
    drsym_o->file = (char *)malloc(LEN);
    drsym_o->name = (char *)malloc(LEN);
    return drsym_o;
}

 
void free_drsmy_obj(drsym_info_t *drsym_o) {
    if (drsym_o) {
        if (drsym_o->file != NULL) 
            free(drsym_o->file);
        if (drsym_o->name != NULL) 
            free(drsym_o->name);
        free(drsym_o);
    }
}

void free_drsmy() {
	free_drsmy_obj(syminfo);
}

drsym_error_t get_sym(app_pc pc, module_data_t *mod) {
    drsym_error_t symres;
    syminfo = drsym_obj(mod->full_path);

    size_t offset = pc - mod->start;
    syminfo->start_offs = 0;
    syminfo->end_offs = 0;
    symres = drsym_lookup_address(mod->full_path, offset, syminfo, DRSYM_DEMANGLE); 
    return symres;   

}

char *get_info(void *drcontext, app_pc pc, module_data_t *mod, app_pc last_instr, file_t fd) {
    drsym_error_t symres;
    struct funct functions;
    char *ret_function;

    ret_function = (char *)malloc(LEN);
    memset(ret_function, 0, LEN);

    app_pc mod_base = mod->start;

    symres = get_sym(pc, mod);
    
    functions.pc = pc;

    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        functions.name_function = syminfo->name;
        functions.start_addr = syminfo->start_offs + mod_base;
        functions.end_addr = syminfo->end_offs + mod_base;
        dr_fprintf(fd, "[FUNC];0x%x;0x%x;"PFX";%s", functions.start_addr, functions.end_addr, functions.pc, functions.name_function);
        
        memcpy(ret_function, functions.name_function, BUFFER_SIZE_ELEMENTS(ret_function));

    } else {
        app_pc first_bb = pc;
        dr_fprintf(fd, "[NOFUNC];0x%x;0x%x;"PFX";None", first_bb, last_instr, pc);
    }

    dr_fprintf(fd, "\n");
    return ret_function;
    
}