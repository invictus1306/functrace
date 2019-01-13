#ifndef BB_GETINFO_H_
#define BB_GETINFO_H_

#define LEN 256

drsym_error_t get_sym(app_pc pc, module_data_t *mod);
char* get_info(void *drcontext, app_pc pc, module_data_t *mod, app_pc last_instr, file_t fd);
void free_drsmy();

#endif