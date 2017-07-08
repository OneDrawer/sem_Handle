#include <sem-event.h>

void main() {
 
   for(;;) {
        char *buf;
        int len;

        if(sem_event_get(123, &buf, &len, 0) == 0) {
            printf("got:%s\n", buf);   
        }
    }
}
