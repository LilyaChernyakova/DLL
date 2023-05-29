#define _XOPEN_SOURCE 500   // for nftw()

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <ftw.h>
#include <getopt.h>
#include <dlfcn.h>
#include <errno.h>
#include <alloca.h>
#include <sys/types.h>
#include <dirent.h>

#include "plugin_api.h"

#define UNUSED(x) (void)(x)

static char *g_program_name = "lab1lvcN3248";
static char *g_version = "1.0";
static char *g_author = "Чернякова Лилия Владиславовна";
static char *g_group = "N3248";
static char *g_lab_variant = "18";

//массив handle’ов всех найденных плагинов
static void** handles;
static int number_of_plugins = 0;

// массив handle’ов плагинов, опции которых заданы пользователем
static void** in_handles;
static int in_handles_len = 0;

// массив всех найденных длинных опций
static struct option* long_options;
static int number_of_options = 0;

// массив длинных опций, переданных в программу пользователем
static struct option* in_opts;
static int in_opts_len = 0;

// группировка опций в соответствие с плагинами
static struct option** plugin_in_opts;
static int* plugin_in_opts_len;

// обработка опций -O, -A
static char flagAO = 'A';
static int flagN = 0;

// справочная информация
void print_help();
static void print_info();

// функции для рекурсивного поиска
int walk_func(const char*, const struct stat*, int, struct FTW*);
int find_plugin(const char*, const struct stat*, int, struct FTW*);

// получение handle’ов плагинов, опции которых заданы пользователем при данном запуске
int get_in_handles();

int main(int argc, char *argv[]) {
	char *DEBUG = getenv("LAB1DEBUG");
	char *path_to_dir = NULL;	
	int path_len;
	
	// обработка опции -Р - смена директории поиска плагинов
	if (strcmp(argv[argc-1], "-P") == 0)
	{
		fprintf(stderr, "%s: option '%s' requires an argument\n", argv[0], argv[argc-1]);
		goto END;
	}
	
	for (int i = 0; i < argc; ++i)
	{
		if (strcmp(argv[i], "-P") == 0)
		{
			path_len = strlen(argv[i + 1]);
			path_to_dir = malloc(path_len + 1);
			if (!path_to_dir)
			{
				fprintf(stderr, "ERROR: malloc() failed: %s\n", strerror(errno));
				goto END;
			}
			strcpy(path_to_dir, argv[i + 1]);
			void* dir = opendir(path_to_dir);
			if (!dir) {
				fprintf(stderr, "ERROR: directory not found: %s\n", path_to_dir);
				goto END;
			}
			else {
				printf("plugin search directory was changed to %s\n", path_to_dir);
				closedir(dir);
				break;
			}
		}
		else if (i == argc - 1) {
			char buf[4096];
			int rl_len = readlink("/proc/self/exe", buf, 4096);
			if (rl_len < 0) {
				fprintf(stderr, "ERROR: readlink() failed %s\n", strerror(errno));
				goto END;
			}
			int path_len = rl_len - strlen(argv[0]) + 1;
			path_to_dir = malloc(path_len + 1);
			path_to_dir[path_len] = '\0';
			strncpy(path_to_dir, buf, path_len);
			break;
		}
	}
	
	if (DEBUG) fprintf(stderr, "DEBUG: path_to_dir = %s\n", path_to_dir);
	
	if (nftw (path_to_dir, find_plugin, 10, FTW_PHYS) < 0) {
		perror("nftw");
		goto END;
	}
	
	if (!long_options) 
		printf ("WARNING: no plugins found in %s\n", path_to_dir);
	
	// обработка переданных опций 
	int c, option_index;
	int flagA = 0, flagO = 0;
	
	optind = 0;
	while(1) {
    	c = getopt_long (argc, argv, "P:AONvh", long_options, &option_index); //
    	if (c==-1) 
     		break;
    	switch(c) {
			case 'P':
				break;
			case 'A':
				flagA = 1;
				break;
			case 'O':
				flagO = 1;
				break;
			case 'N':
				flagN = 1;
				break;
			case 'v':;
				print_info();
				goto END;
			case ':':
				printf("option needs a value\n");
				break;
			case '?':
			case 'h':
				printf("Usage: %s [options] <start_dir>\n", argv[0]);
				print_help();
				goto END;
				break; 
			case 0:
				in_opts = (struct option*) realloc(in_opts, (in_opts_len+1)*sizeof(struct option));
				in_opts[in_opts_len] = long_options[option_index];
				in_opts[in_opts_len].flag = (int*) optarg;
				in_opts_len++;
				
				break;
			default:
				printf("WARNING: getopt couldn't resolve the option\n");
				break;
		}
	}

	// Обработка некорректных входных параметров
	if (argc - optind != 1)
	{
		fprintf(stderr, "Usage: %s [options] <start_dir>\n", argv[0]);
		print_help();
		goto END;
	}
	
	if (flagA && flagO)
	{
		fprintf(stderr, "ERROR: can't use -A and -O options together\n");
		goto END;
	}
	
	else if (flagO) flagAO = 'O';
	
	if (DEBUG)
		fprintf(stderr, "DEBUG: AO flag = %c; N flag = %d\n", flagAO, flagN);
	
	if (DEBUG)
	{
		fprintf(stderr, "DEBUG: Нужные опции:\n");
		for (int i = 0; i < in_opts_len; ++i)
		{
			fprintf(stderr, "\t%s\n", in_opts[i].name);
			fprintf(stderr, "\t%d\n", in_opts[i].has_arg);
			fprintf(stderr, "\t%s\n", (char*)in_opts[i].flag);
			fprintf(stderr, "\t%d\n", in_opts[i].val);
		}
	}
	
	// Получаем заполненные массивы in_handles и plugin_in_opts
	if (get_in_handles() < 0)
		goto END;
	
	if (DEBUG) {
		fprintf(stderr, "DEBUG: Plugin in opts:\n");
		for (int i = 0; i < in_handles_len; ++i) {
				fprintf(stderr, "\tHandle number %d, len = %d\n", i, plugin_in_opts_len[i]);
			for (int j = 0; j < plugin_in_opts_len[i]; ++j) {
				fprintf(stderr, "\t\t%s %s\n", plugin_in_opts[i][j].name, (char*)plugin_in_opts[i][j].flag);
			}
		}
	}
	
	
	if (DEBUG) {
		fprintf(stderr, "DEBUG: in_handles array:\n");
		typedef int (*pgi_func_t)(struct plugin_info*);
		for (int i = 0; i < in_handles_len; ++i)
		{
			fprintf(stderr, "\tHandle number %d:\n", i);
			void *func = dlsym(in_handles[i], "plugin_get_info");
			struct plugin_info pi = {0};
			pgi_func_t pgi_func = (pgi_func_t)func;            
			int ret = pgi_func(&pi);
			if (ret < 0) 
				fprintf(stderr, "DEBUG: WARNING: plugin_get_info ended with an error.\n");
			for (size_t j = 0; j < pi.sup_opts_len; ++j)
				fprintf(stderr, "\t\t%s\n", pi.sup_opts[j].opt.name);
		}
		fprintf(stderr, "DEBUG: in_handles_len = %d\n", in_handles_len);
	}
	
	if (DEBUG) fprintf(stderr, "DEBUG: Target directory = %s\n", argv[optind]);
	
	// поиск файлов, соответствующих заданным критериям
	int res = nftw(argv[optind], walk_func, 10, FTW_PHYS);
	if (res < 0) {
		perror("nftw");
		goto END;
	} 
	
	END:
	for (int i = 0; i < number_of_plugins; i++) 
		if (handles[i]) dlclose(handles[i]);
	if (handles) free(handles);
	if (in_handles) free(in_handles);
	if (path_to_dir) free(path_to_dir);
	if (long_options) free(long_options);
	if (in_opts) free (in_opts);
	for (int i = 0; i < in_handles_len; i++) 
		if (plugin_in_opts[i]) free(plugin_in_opts[i]);
	if (plugin_in_opts) free(plugin_in_opts);
	if (plugin_in_opts_len) free(plugin_in_opts_len);
	
	return 0;
}

int walk_func(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	UNUSED(sb); UNUSED(ftwbuf);
	char *DEBUG = getenv("LAB1DEBUG");
	errno = 0;
	
	if (typeflag == FTW_D || typeflag == FTW_DP || typeflag == FTW_DNR) return 0;
	
	int ret = 1;
	
	int *plugin_results = alloca(in_handles_len*sizeof(int));
	for (int i = 0; i < in_handles_len; ++i) {
		void *func = dlsym(in_handles[i], "plugin_process_file");
		if (!func) {
			fprintf(stderr, "ERROR: walk_func: no plugin_process_file() function found\n");
			return 0;
		}
		typedef int (*ppf_func_t)(const char*, struct option*, size_t);
		ppf_func_t ppf_func = (ppf_func_t)func;
		plugin_results[i] = ppf_func(fpath, plugin_in_opts[i], plugin_in_opts_len[i]);
		
		if (DEBUG)
			fprintf(stderr, "walk_func: plugin_process_file() returned %d\n", plugin_results[i]);
		if (errno == EINVAL || DEBUG) {
			fprintf(stderr, "ERROR: walk_func: file wasn't proccesed %s\n", strerror(errno));
			return 0;
		}
	}
	
	if (flagAO == 'A') {
		ret = 1;
		for (int i = 0; i < in_handles_len; ++i)
			ret = ret && !(plugin_results[i]);
	}
	else {
		ret = 0;
		for (int i = 0; i < in_handles_len; ++i)
			ret = ret || !(plugin_results[i]);
	}
	
	if (flagN) ret = !ret;
	
	if (ret) fprintf(stdout, "%s\n",fpath);
    
    return 0;
}

int find_plugin(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	UNUSED(sb); UNUSED(ftwbuf);
	char *DEBUG = getenv("LAB1DEBUG");
	
	if (typeflag == FTW_D || typeflag == FTW_DP || typeflag == FTW_DNR) return 0;

	void *handle;
	handle = dlopen(fpath, RTLD_LAZY);
	if (!handle) return 0;
	
	void *func = dlsym(handle, "plugin_get_info"); 
	if (!func) {
		if (DEBUG) fprintf(stderr, "WARNING: find_plugin: no plugin_get_info() function found\n");     
        if (handle) dlclose(handle);
        return 0;
    }
    struct plugin_info pi = {0};
    typedef int (*pgi_func_t)(struct plugin_info*);
    pgi_func_t pgi_func = (pgi_func_t)func;            
    int ret = pgi_func(&pi);
    if (ret < 0) {   
    	if (DEBUG) fprintf(stderr, "ERROR: find_plugin: plugin_get_info() function failed\n");     
        if (handle) dlclose(handle);
        return 0;
    }
    
    func = dlsym(handle, "plugin_process_file");
    if (!func) {
    	fprintf(stderr, "DEBUG: find_plugin: no_plugin_process_file() function found in %s\n", fpath);
    	if (handle) dlclose(handle);
    	return 0;
    }
    
    handles = (void**) realloc(handles, (number_of_plugins+1)*sizeof(void*));
    if (!handles) {
    	if (DEBUG) fprintf(stderr, "ERROR: find_plugin: realloc() failed: %s\n", strerror(errno));
    	if (handle) dlclose(handle);
    	return -1;
    }
    handles[number_of_plugins] = handle;
    number_of_plugins++;
    
    long_options = (struct option*) realloc(long_options, sizeof(struct option)*(pi.sup_opts_len+number_of_options));
    
    if (!long_options)
    {
    	fprintf(stderr, "ERROR: find_plugin: realloc() failed: %s\n", strerror(errno));
    	return -1;
    }
    for (size_t i = 0; i < pi.sup_opts_len; i++) {
		long_options[number_of_options] = pi.sup_opts[i].opt;
		number_of_options++;
	}

	return 0;
}

int get_in_handles() {
	typedef int (*pgi_func_t)(struct plugin_info*);
	for (int i = 0; i < number_of_plugins; ++i) {
		void *func = dlsym(handles[i], "plugin_get_info"); 
		if (!func) {
			fprintf(stderr, "ERROR: dlsym\n");     
		    return -1;
		}
		struct plugin_info pi = {0};
		pgi_func_t pgi_func = (pgi_func_t)func;            
		int ret = pgi_func(&pi);
		if (ret < 0) {   
			fprintf(stderr, "ERROR: get_in_handles: plugin_get_info() function failed\n");    
		    return -1;
		}
		
		int match = 0;

		plugin_in_opts_len = (int*) realloc(plugin_in_opts_len, (in_handles_len+1)*sizeof(int));
		plugin_in_opts_len[in_handles_len] = 0;
		

		for (int j = 0; j < in_opts_len; ++j) {
			for (size_t k = 0; k < pi.sup_opts_len; ++k) {			
				if (strcmp(pi.sup_opts[k].opt.name, in_opts[j].name) == 0) {
					plugin_in_opts_len[in_handles_len - match]++;
					if (!match) {
						in_handles = (void**) realloc(in_handles, (in_handles_len+1)*sizeof(void*));
						if (!in_handles) {
							fprintf(stderr, "ERROR: get_in_handles: realloc() failed: %s\n", strerror(errno));
							return -1;
						}

						in_handles[in_handles_len] = handles[i];
						plugin_in_opts = (struct option**) realloc(plugin_in_opts, (in_handles_len+1)*sizeof(struct option*));
						if (!plugin_in_opts) {
							fprintf(stderr, "ERROR: get_in_handles: realloc() failed: %s\n", strerror(errno));
							return -1;
						}
						in_handles_len++;
						match = 1;
					}
				}
			}
		}

		int ind = 0;
		if (match == 1) {
			plugin_in_opts[in_handles_len-1] = (struct option*) calloc(plugin_in_opts_len[in_handles_len-1], sizeof(struct option));
			if (!plugin_in_opts[in_handles_len-1]) {
				fprintf(stderr, "ERROR: get_in_handles: realloc() failed: %s\n", strerror(errno));
				return -1;
			}

			for (int j = 0; j < in_opts_len; j++) {
				for (size_t k = 0; k < pi.sup_opts_len; ++k) {			
					if (strcmp(pi.sup_opts[k].opt.name, in_opts[j].name) == 0) {
						plugin_in_opts[in_handles_len-1][ind++] = in_opts[j];
					}
				}
			}
		}
	}

	return 0;
}


void print_help() {
	printf("Доступные опции:\n");
	printf("-P dir\tКаталог с плагинами.\n");
	printf("-A\tОбъединение опций плагинов с помощью операции «И» (действует по умолчанию)..\n");
	printf("-O\tОбъединение опций плагинов с помощью операции «ИЛИ».\n");
	printf("-N\tИнвертирование условия поиска (после объединения опций плагинов с помощью -A или -O).\n");
	printf("-v\tВывод версии программы и информации о программе (ФИО исполнителя, номер группы, номер варианта лабораторной).\n");
	printf("-h\tВывод справки по опциям.\n");
	
	if (number_of_plugins > 0) {
		printf("\nДоступные длинные опции:\n");
		typedef int (*pgi_func_t)(struct plugin_info*);
		for (int i = 0; i < number_of_plugins; ++i) {
			void *func = dlsym(handles[i], "plugin_get_info");
			struct plugin_info pi = {0};
			pgi_func_t pgi_func = (pgi_func_t)func;            
			int ret = pgi_func(&pi);
			if (ret < 0) fprintf(stderr, "ERROR: print_help: plugin_get_info failed\n");
			
			printf("Опции из плагина №%d:\n", i+1);
			for (size_t j = 0; j < pi.sup_opts_len; ++j) {
				printf("%s\r", pi.sup_opts[j].opt.name);
				printf("\t\t\t%s\n", pi.sup_opts[j].opt_descr);
			}
		}
	}
}

void print_info() {
	printf("Программа %s. Версия: %s\n", g_program_name, g_version);
	printf("Автор программы: %s, группа %s\n", g_author, g_group);
	printf("Вариант лабораторной работы №1: %s\n", g_lab_variant);
}
       



       
