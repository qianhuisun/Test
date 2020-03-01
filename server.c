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

#define PACKET_NUMBER 100

typedef struct custom_event{
    // bool last_event;
    char timestamp[32];
    char hostname[32];
    char domain[32];
    char event_name[32];
    uint64_t cpu_id;
    int64_t tid;
    uint64_t payload_size;
    int64_t payloads[];
} custom_event;


int main(int argc, char *argv[])
{

    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    time_t ticks;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5026);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);
    
    connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);

    // recv data
    uint64_t packet_size[PACKET_NUMBER];
    custom_event* custom_event_object;
    // int i = 0;
    // receiver suppose to be blocked if there is no data coming
    
    while (true) {
        recv(connfd, packet_size, sizeof(uint64_t) * PACKET_NUMBER, 0);
        uint64_t payload_size = 0;
        for (int i = 0; i < PACKET_NUMBER; i++)
        {
            payload_size += packet_size[i];
        }
        char payload_packet[payload_size];
        void *pointer;
        // custom_event_object = (custom_event*) malloc (event_size);
        memset(payload_packet, 0, payload_size);
        pointer = payload_packet;
        //printf("%" PRIu64 "\n", event_size);
        recv(connfd, payload_packet, payload_size, 0);

        for(int i = 0; i < PACKET_NUMBER; i++)
        {
            int size = packet_size[i];
            if (size == 0) continue;
            custom_event_object = pointer;

            // if (custom_event_object->last_event) break;
            if (strcmp(custom_event_object->event_name, "syscall_entry_write") == 0) {
                printf("%d\t event_name = %s cpu_id = %" PRIu64 " tid = %" PRIu64, i, custom_event_object->event_name, custom_event_object->cpu_id, custom_event_object->tid);
                printf(" fd = %" PRIu64, *(uint64_t *)(custom_event_object + 1));
                printf("\n");
            } else if (strcmp(custom_event_object->event_name, "syscall_entry_openat") == 0) {
                printf("%d\t event_name = %s cpu_id = %" PRIu64 " tid = %" PRIu64, i, custom_event_object->event_name, custom_event_object->cpu_id, custom_event_object->tid);
                unsigned int string_offset = *(unsigned int *)((int64_t *)(custom_event_object + 1) + 1);
                unsigned int string_length = *(unsigned int *)((int *)((int64_t *)(custom_event_object + 1) + 1) + 1);
                char buf[256];
                memset(buf, 0, sizeof(buf));
                memcpy(buf, (char *)custom_event_object + string_offset, string_length);
                printf(" %s ", buf);
                printf("\n");
            }

        }
    }

    close(connfd);

    return 0;
}
