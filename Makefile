
all:
	$(CC) -shared -fvisibility=hidden -fPIC -o libsemevent.so sem-event.c  util.c -pthread -lrt 

clean:
	rm -rf *.o *.so

