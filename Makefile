CFLAGS=-g -Wall -Wextra -Werror -O2
TARGETS=lab2lvcN3248_server lab2lvcN3248_client

.PHONY: all clean

all: $(TARGETS)

clean:
	rm -rf *.o $(TARGETS)

lab2lvcN3248_server: lab2lvcN3248_server.c 
	gcc $(CFLAGS) -o lab2lvcN3248_server lab2lvcN3248_server.c 
	
lab2lvcN3248_client: lab2lvcN3248_client.c 
	gcc $(CFLAGS) -o lab2lvcN3248_client lab2lvcN3248_client.c 

