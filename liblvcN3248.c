#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "plugin_api.h"

static char *g_lib_name = "liblvcN3248.so";
static char *g_plugin_purpose = "File search MAC address in binary form";
static char *g_plugin_author = "Lilya Chernyakova";

#define MAC_ADDR_BIN_STR "mac-addr-bin"
#define PATTERN "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"

static struct plugin_option g_po_arr[] = {
    {
        {
            MAC_ADDR_BIN_STR,
            required_argument,
            0, 0,
        },
        "Target MAC address"
    }
};

static int g_po_arr_len = sizeof(g_po_arr)/sizeof(g_po_arr[0]);

// проверка адреса
int is_valid_addr(char* mac_addr_input);

// поиск адреса в файле
int find_mac_addr_bin(const char* fname, char* mac_addr_input);

// перевод из big-endian в little-endian
char* my_itoa(int, char*, int);

// получение адреса в big-endian и little-endian
void get_first_addr(char*, char*);
void get_second_addr(char*, char*);

int plugin_get_info(struct plugin_info* ppi) {

    if (!ppi) {
        fprintf(stderr, "ERROR: invalid argument\n");
        return -1;
    }
    
	ppi->plugin_purpose = g_plugin_purpose;
	ppi->plugin_author = g_plugin_author;
	ppi->sup_opts_len = g_po_arr_len;
	ppi->sup_opts = g_po_arr;

    return 0;
}

int plugin_process_file(const char *fname, struct option in_opts[], size_t in_opts_len) {

	int ret = -1;
	unsigned char *ptr = NULL; 
    char *DEBUG = getenv("LAB1DEBUG");
    FILE* fp = NULL;
    
    if (!fname || !in_opts || !in_opts_len) {
        errno = EINVAL;
        return -1;
    }  
    
    if (DEBUG) {
        for (size_t i = 0; i < in_opts_len; ++i)
            fprintf(stderr, "DEBUG: %s: Got option '%s' with arg '%s'\n", g_lib_name, in_opts[i].name, (char*)in_opts[i].flag);
    }
    
    char* mac_addr_input;
    int got_mac_addr_bin = 0;
    
    // проверка опции
    for (size_t i = 0; i < in_opts_len; ++i) {
    	if (!strcmp(in_opts[i].name, MAC_ADDR_BIN_STR) && got_mac_addr_bin == 0) {
            got_mac_addr_bin = 1;
            mac_addr_input = (char*)in_opts[i].flag;
        }
        else if (!strcmp(in_opts[i].name, MAC_ADDR_BIN_STR) && got_mac_addr_bin == 1){
        	if (DEBUG) 
            	fprintf(stderr, "DEBUG: %s: option '%s' was already supplied\n", g_lib_name, in_opts[i].name);
            errno = EINVAL;
           	return -1;
    	}
    }
    
    // проверка адреса
    if (is_valid_addr(mac_addr_input) != 0) {
		if (DEBUG) {
            fprintf(stderr, "DEBUG: %s: invalid mac_addr\n", g_lib_name);
        }
		errno = EINVAL;
        return -1;         
	}
    
    // получение значений адреса в бинарном виде (big-endian, little-endian)
    char* first = alloca(49);
    get_first_addr(first, mac_addr_input);
    char* second = alloca(49);
    get_second_addr(second, mac_addr_input);
    
    if (DEBUG) {
        fprintf(stderr, "DEBUG: %s: input: mac_addr = %s", g_lib_name, mac_addr_input);
    }
    
    int saved_errno = 0;   
    
    // проверка размера файла
    int fd = open(fname, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    struct stat st = {0};
    int res = fstat(fd, &st);
    if (res < 0) {
        saved_errno = errno;
        goto END;
    }
    
    if (st.st_size == 0) {
        if (DEBUG) {
            fprintf(stderr, "DEBUG: %s: File size should be > 0\n", g_lib_name);
        }
        saved_errno = ERANGE;
        goto END;
    }
     
    ptr = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        saved_errno = errno;
        goto END;
    }
    
    fp = fopen(fname, "r");
    if (fp == NULL) {
    	exit(EXIT_FAILURE);
    }

    char* line = NULL;
	size_t len = 0;
	size_t read;

	// чтение файла и поиск адреса
    while ((read = getline(&line, &len, fp)) != (size_t)-1) {	
		if ((strstr(line, first) != NULL) || (strstr(line, second) != NULL)) {
			ret = 0;
		}
	}
	
	fclose(fp);
	if (line) free(line);
	
	if (ret != 0) ret = 1;
	
    END:
	if (fd) close(fd);
	if (ptr != MAP_FAILED && ptr != NULL) munmap(ptr, st.st_size);

    // обновление errno
    errno = saved_errno;
    
    return ret;
}

int is_valid_addr(char* mac_addr_input) {

	char *DEBUG = getenv("LAB1DEBUG");
	
	regex_t preg;
	int err, regerr;
	
	err = regcomp (&preg, PATTERN, REG_EXTENDED);
    if (err != 0) {
        char buff[64];
        regerror(err, &preg, buff, sizeof(buff));
    }
    
    regmatch_t pm;
    regerr = regexec (&preg, mac_addr_input, 0, &pm, 0);
    
    regfree(&preg);
    
    if (regerr == 0) 
    	return 0;
    else {
    	if (DEBUG) 
    		fprintf(stderr, "DEBUG: %s: invalid mac_addr_input\n", g_lib_name);
    	char errbuf[64];
    	regerror(regerr, &preg, errbuf, sizeof(errbuf));
        return -1;
    }
}

char* my_itoa(int number, char* destination, int base) {
    int count = 0;
    do {
        int digit = number % base;
        destination[count++] = (digit > 9) ? digit - 10 + 'A' : digit + '0';
    } while ((number /= base) != 0);
    destination[count] = '\0';
    int i;
    for (i = 0; i < count / 2; ++i) {
        char symbol = destination[i];
        destination[i] = destination[count - i - 1];
        destination[count - i - 1] = symbol;
    }
    return destination;
}


void get_first_addr(char* binary, char* s)
{
    int bytes[6] = { 0 };
    int ind = 0;
    char* ptr = s;
    for (int i = 0; i < 17; i+=3) {
        int c = strtol(ptr, NULL, 16);
        bytes[ind++] = c;
        ptr += 3;
    }
    for (int i = 0; i < ind; i++) {
        my_itoa(bytes[i], binary + i*8, 2);
        //printf("%d %s\n", bytes[i], binary);
    }
    binary[48] = '\0';
}

void get_second_addr(char* binary, char* s) {
    int bytes[6] = { 0 };
    int ind = 0;
    char* ptr = s;
    for (int i = 0; i < 17; i += 3) {
        int c = strtol(ptr, NULL, 16);
        bytes[5 - ind++] = c;
        ptr += 3;
    }
    for (int i = 0; i < ind; i++) {
        my_itoa(bytes[i], binary + i * 8, 2);
        //printf("%d %s\n", bytes[i], binary);
    }
    binary[48] = '\0';
}
    
	
