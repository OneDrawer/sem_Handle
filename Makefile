
all:
	$(CC) -shared -fvisibility=hidden -fPIC -o libkbzevent.so kbz-event.c  util.c -pthread -lrt 

clean:
	rm -rf *.o *.so

