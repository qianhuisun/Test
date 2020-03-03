#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>

#define EVENT_OBJECT_NUMBER 100

/* structure of custom event object */
typedef struct custom_event{
    int64_t timestamp;
    char hostname[32];
    char domain[32];
    char event_name[32];
    uint64_t cpu_id;
    int64_t tid;
    uint64_t custom_event_objects_size;
    int64_t payloads[];
} custom_event;


int main(int argc, char *argv[])
{
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5026);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);
    
    connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);

    /* size array of EVENT_OBJECT_NUMBER event objects */
    uint64_t custom_event_object_size[EVENT_OBJECT_NUMBER];
    /* point to the buffer to receive all EVENT_OBJECT_NUMBER event objects */
    char *custom_event_objects;
    /* point to next event object received */
    char *head;
    /* point to next event object received */
    custom_event* custom_event_object;
    
    while (true) {
        /* receive the size array of EVENT_OBJECT_NUMBER event objects */
        int recv_length = recv(connfd, custom_event_object_size, sizeof(uint64_t) * EVENT_OBJECT_NUMBER, 0);
        /* shut down server when client has shut down */
        if (recv_length == 0) break;
        /* get the total size of all EVENT_OBJECT_NUMBER event objects */
        uint64_t custom_event_objects_size = 0;
        for (int i = 0; i < EVENT_OBJECT_NUMBER; i++)
        {
            custom_event_objects_size += custom_event_object_size[i];
            //printf("event_size = %" PRIu64 "\n", custom_event_object_size[i]);
        }
        /* send response */
        char response[256] = "size array received";
        send(connfd, response, sizeof(response), 0);
        /* receive all EVENT_OBJECT_NUMBER event objects */
        custom_event_objects = malloc(custom_event_objects_size);
        recv(connfd, custom_event_objects, custom_event_objects_size, 0);
        head = custom_event_objects;

        for(int i = 0; i < EVENT_OBJECT_NUMBER; i++)
        {
            uint64_t object_size = custom_event_object_size[i];
            if (object_size == 0) continue;
            custom_event_object = (custom_event*)head;
            head += object_size;

            if (strcmp(custom_event_object->event_name, "syscall_entry_write") == 0) {
            /* if it's a syscall write event, print the first param in payload, which is fd in uint64_t */
                printf("%d\t event_name = %s cpu_id = %" PRIu64 " tid = %" PRIu64, i, custom_event_object->event_name, custom_event_object->cpu_id, custom_event_object->tid);
                printf(" fd = %" PRIu64, *(uint64_t *)(custom_event_object + 1));
                printf("\n");
            } else if (strcmp(custom_event_object->event_name, "syscall_entry_openat") == 0) {
            /* if it's a syscall openat event, print the second param in payload, which is filename in string */
                unsigned int string_offset = *(unsigned int *)((int64_t *)(custom_event_object + 1) + 1);
                unsigned int string_length = *(unsigned int *)((int *)((int64_t *)(custom_event_object + 1) + 1) + 1);
                char buf[256];
                memset(buf, 0, sizeof(buf));
                memcpy(buf, (char *)custom_event_object + string_offset, string_length);
                printf("%d\t event_name = %s cpu_id = %" PRIu64 " tid = %" PRIu64, i, custom_event_object->event_name, custom_event_object->cpu_id, custom_event_object->tid);
                printf(" filename = %s ", buf);
                printf("\n");
            }
        }

        free(custom_event_objects);
    }

    close(connfd);

    return 0;
}
