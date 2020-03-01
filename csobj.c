#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <babeltrace2/babeltrace.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define PACKET_NUMBER 100

uint64_t packet_index = 0;
uint64_t total_size = 0;
uint64_t packet_size[PACKET_NUMBER];
// will use htonl and ntohl to code and decode
uint64_t packet_size_send[PACKET_NUMBER];
// array which saves 100 custom_event, will be sent through TCP socket
char *event_objects = NULL;
char *pointer = NULL;

typedef struct custom_event{
    // bool last_event;
    char timestamp[32];
    char hostname[32];
    char domain[32];
    char event_name[32];
    uint64_t cpu_id;
    int64_t tid;
    uint64_t payload_size;
    int64_t payloads;
} custom_event;

/* Sink component's private data */
struct object_out {
    /* Upstream message iterator (owned by this) */
    bt_message_iterator *message_iterator;
 
    /* Current event message index */
    uint64_t index;

    int sockfd;
};

/* Copied from write.c in sink.text.details component */
static inline
void format_uint(char *buf, uint64_t value, unsigned int base)
{
    const char *spec = "%" PRIu64;
    char *buf_start = buf;

    switch (base) {
    case 2:
    case 16:
        /* TODO: Support binary format */
        spec = "%" PRIx64;
        strcpy(buf, "0x");
        buf_start = buf + 2;
        break;
    case 8:
        spec = "%" PRIo64;
        strcpy(buf, "0");
        buf_start = buf + 1;
        break;
    case 10:
        break;
    default:
        break;
    }

    sprintf(buf_start, spec, value);
}

static inline
void format_int(char *buf, int64_t value, unsigned int base)
{
    const char *spec = "%" PRIu64;
    char *buf_start = buf;
    uint64_t abs_value = value < 0 ? (uint64_t) -value : (uint64_t) value;

    if (value < 0) {
        buf[0] = '-';
        buf_start++;
    }

    switch (base) {
    case 2:
    case 16:
        /* TODO: Support binary format */
        spec = "%" PRIx64;
        strcpy(buf_start, "0x");
        buf_start += 2;
        break;
    case 8:
        spec = "%" PRIo64;
        strcpy(buf_start, "0");
        buf_start++;
        break;
    case 10:
        break;
    default:
        break;
    }

    sprintf(buf_start, spec, abs_value);
}

 
/*
 * Initializes the sink component.
 */
static
bt_component_class_initialize_method_status object_csobj_initialize(
        bt_self_component_sink *self_component_sink,
        bt_self_component_sink_configuration *configuration,
        const bt_value *params, void *initialize_method_data)
{
    /* Allocate a private data structure */
    struct object_out *object_out = malloc(sizeof(*object_out));
 
    /* Initialize the first event message's index */
    object_out->index = 1;
 
    /* Set the component's user data to our private data structure */
    bt_self_component_set_data(
        bt_self_component_sink_as_self_component(self_component_sink),
        object_out);
 
    /*
     * Add an input port named `in` to the sink component.
     *
     * This is needed so that this sink component can be connected to a
     * filter or a source component. With a connected upstream
     * component, this sink component can create a message iterator
     * to consume messages.
     */
    bt_self_component_sink_add_input_port(self_component_sink,
        "in", NULL, NULL);

    /*  Initialize the client socket */
    struct sockaddr_in server_addr;
    memset(&server_addr, '0', sizeof(server_addr));
    if((object_out->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5026);
    if(inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    }
    if(connect(object_out->sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("\n Error: Connect Failed \n");
        return 1;
    }

    event_objects = malloc(100000);
    pointer = event_objects;
 
    return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
}
 
/*
 * Finalizes the sink component.
 */
static
void object_csobj_finalize(bt_self_component_sink *self_component_sink)
{
    /* Retrieve our private data from the component's user data */
    struct object_out *object_out = bt_self_component_get_data(
        bt_self_component_sink_as_self_component(self_component_sink));
    for(; packet_index < PACKET_NUMBER; packet_index++)
    {
        packet_size[packet_index] = 0;
    }

    /* Send object size */
    send(object_out->sockfd, packet_size, sizeof(uint64_t) * PACKET_NUMBER, 0);
    /* Send object */
    send(object_out->sockfd, event_objects, total_size, 0);


    // custom_event *custom_event_object = (custom_event*) malloc (sizeof(custom_event));
    // custom_event_object->last_event = true;
    // send(object_out->sockfd, custom_event_object, sizeof(custom_event), 0);
    /* Free the allocated structure */
    free(object_out);
}
 
/*
 * Called when the trace processing graph containing the sink component
 * is configured.
 *
 * This is where we can create our upstream message iterator.
 */
static
bt_component_class_sink_graph_is_configured_method_status
object_csobj_graph_is_configured(bt_self_component_sink *self_component_sink)
{
    /* Retrieve our private data from the component's user data */
    struct object_out *object_out = bt_self_component_get_data(
        bt_self_component_sink_as_self_component(self_component_sink));
 
    /* Borrow our unique port */
    bt_self_component_port_input *in_port =
        bt_self_component_sink_borrow_input_port_by_index(
            self_component_sink, 0);
 
    /* Create the uptream message iterator */
    bt_message_iterator_create_from_sink_component(self_component_sink,
        in_port, &object_out->message_iterator);
 
    return BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_OK;
}


/* get the number of params and cumulative string size in payload field */
int get_payload_num_and_string_size(const bt_field *payload_field, uint64_t *payload_num, uint64_t *payload_string_size) {
    /* payload field must be a structure */
    if (bt_field_get_class_type(payload_field) == BT_FIELD_CLASS_TYPE_STRUCTURE) {
        const bt_field_class *payload_field_class = bt_field_borrow_class_const(payload_field);
        *payload_num = bt_field_class_structure_get_member_count(payload_field_class);
        *payload_string_size = 0;
        for (int i = 0; i < *payload_num; ++i) {
            const bt_field *member_field = bt_field_structure_borrow_member_field_by_index_const(payload_field, i);
            if (bt_field_get_class_type(member_field) == BT_FIELD_CLASS_TYPE_STRING) {
                const char *buf = bt_field_string_get_value(member_field);
                *payload_string_size += strlen(buf);
            }
        }
        return 0;
    } else {
        return -1;
    }
}

/* fill the values of payload params in our event object*/
void fill_payload_param_by_index(custom_event *custom_event_object, const bt_field *payload_field, int i, unsigned int *payload_string_offset) {
    const bt_field *member_field = bt_field_structure_borrow_member_field_by_index_const(payload_field, i);
    bt_field_class_type member_field_class_type = bt_field_get_class_type(member_field);
    if (member_field_class_type == BT_FIELD_CLASS_TYPE_BOOL) {
        int64_t bool_value = (int64_t)bt_field_bool_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &bool_value, sizeof(int64_t));
    } else if (member_field_class_type == BT_FIELD_CLASS_TYPE_BIT_ARRAY) {
        uint64_t bit_array_value = bt_field_bit_array_get_value_as_integer(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &bit_array_value, sizeof(int64_t));
    } else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER)) {
        uint64_t unsigned_integer_value = bt_field_integer_unsigned_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &unsigned_integer_value, sizeof(int64_t));
    } else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER)) {
        int64_t signed_integer_value = bt_field_integer_signed_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &signed_integer_value, sizeof(int64_t));
    } else if (member_field_class_type == BT_FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL) {
        double real_value = bt_field_real_single_precision_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &real_value, sizeof(int64_t));
    } else if (member_field_class_type == BT_FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL) {
        double real_value = bt_field_real_double_precision_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &real_value, sizeof(int64_t));
    } else if (member_field_class_type == BT_FIELD_CLASS_TYPE_STRING) {
        const char *string_value = bt_field_string_get_value(member_field);
        unsigned int string_offset = *payload_string_offset;
        unsigned int string_length = strlen(string_value);
        memcpy((int64_t *)(custom_event_object + 1) + i, &string_offset, sizeof(int));
        memcpy((int *)((int64_t *)(custom_event_object + 1) + i) + 1, &string_length, sizeof(int));
        memcpy((char *)custom_event_object + string_offset, string_value, string_length);
        *payload_string_offset += string_length;
    } else if (member_field_class_type == BT_FIELD_CLASS_TYPE_STRUCTURE) {
        /* do nothing for now */
    } else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_ARRAY)) {
        /* do nothing for now */
    } else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_OPTION)) {
        /* do nothing for now */
    } else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_VARIANT)) {
        /* do nothing for now */
    } 
}

/* get a parameter's value with type of uint64 */
static
uint64_t get_uint64_value_from_field(const char *target_name, const bt_field *field, const char *name) {
    bt_field_class_type field_class_type = bt_field_get_class_type(field);
    const bt_field_class *field_class;
    if (bt_field_class_type_is(field_class_type, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER)) {
        if (strcmp(target_name, name) == 0) {
            return bt_field_integer_unsigned_get_value(field);
        }
    } else if (field_class_type == BT_FIELD_CLASS_TYPE_STRUCTURE) {
        field_class = bt_field_borrow_class_const(field);
        uint64_t member_count = bt_field_class_structure_get_member_count(field_class);
        for (int i = 0; i < member_count; ++i) {
            const bt_field_class_structure_member *field_class_structure_member =
                bt_field_class_structure_borrow_member_by_index_const(field_class, i);
            const bt_field *member_field =
                bt_field_structure_borrow_member_field_by_index_const(field, i);
            const char *member_name = bt_field_class_structure_member_get_name(field_class_structure_member);
            if (strcmp(target_name, member_name) == 0) {
                return get_uint64_value_from_field(target_name, member_field, member_name);
            }
        }
        /* Error code 999999: target_name not in the structure */
        return 999999;
    } else {
        /* Error code 888888: field is not a structure */
        return 888888;
    }
}

/* get a parameter's value with type of int64 */
static
int64_t get_int64_value_from_field(const char *target_name, const bt_field *field, const char *name) {
    bt_field_class_type field_class_type = bt_field_get_class_type(field);
    const bt_field_class *field_class;
    if (bt_field_class_type_is(field_class_type, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER)) {
        if (strcmp(target_name, name) == 0) {
            return bt_field_integer_signed_get_value(field);
        }
    } else if (field_class_type == BT_FIELD_CLASS_TYPE_STRUCTURE) {
        field_class = bt_field_borrow_class_const(field);
        uint64_t member_count = bt_field_class_structure_get_member_count(field_class);
        for (int i = 0; i < member_count; ++i) {
            const bt_field_class_structure_member *field_class_structure_member =
                bt_field_class_structure_borrow_member_by_index_const(field_class, i);
            const bt_field *member_field =
                bt_field_structure_borrow_member_field_by_index_const(field, i);
            const char *member_name = bt_field_class_structure_member_get_name(field_class_structure_member);
            if (strcmp(target_name, member_name) == 0) {
                return get_int64_value_from_field(target_name, member_field, member_name);
            }
        }
        /* Error code 999999: target_name not in the structure */
        return 999999;
    } else {
        /* Error code 888888: field is not a structure */
        return 888888;
    }
}

/* get a parameter's value with type of string */
static
const char *get_string_value_from_field(const char *target_name, const bt_field *field, const char *name) {
    bt_field_class_type field_class_type = bt_field_get_class_type(field);
    const bt_field_class *field_class;
    if (field_class_type == BT_FIELD_CLASS_TYPE_STRING) {
        if (strcmp(target_name, name) == 0) {
            return bt_field_string_get_value(field);
        }
    } else if (field_class_type == BT_FIELD_CLASS_TYPE_STRUCTURE) {
        field_class = bt_field_borrow_class_const(field);
        uint64_t member_count = bt_field_class_structure_get_member_count(field_class);
        for (int i = 0; i < member_count; ++i) {
            const bt_field_class_structure_member *field_class_structure_member =
                bt_field_class_structure_borrow_member_by_index_const(field_class, i);
            const bt_field *member_field =
                bt_field_structure_borrow_member_field_by_index_const(field, i);
            const char *member_name = bt_field_class_structure_member_get_name(field_class_structure_member);
            if (strcmp(target_name, member_name) == 0) {
                return get_string_value_from_field(target_name, member_field, member_name);
            }
        }
        /* Error code 999999: target_name not in the structure */
        return "999999";
    } else {
        /* Error code 888888: field is not a structure */
        return "888888";
    }
}

/*
 * Prints a line for `message`, if it's an event message, to the
 * standard csobj.
 */
static
void print_message(struct object_out *object_out, const bt_message *message)
{
    /* Discard if it's not an event message */
    if (bt_message_get_type(message) != BT_MESSAGE_TYPE_EVENT) {
        goto end;
    }
 
    /* Borrow the event message's event and its class */
    const bt_event *event = bt_message_event_borrow_event_const(message);
    const bt_event_class *event_class = bt_event_borrow_class_const(event);
    
    /* Prepare timestamp */
    const bt_clock_snapshot *clock_snapshot = bt_message_event_borrow_default_clock_snapshot_const(message);

    /* Prepare hostname */
	const bt_stream *stream = bt_event_borrow_stream_const(event);
	const bt_trace *trace = bt_stream_borrow_trace_const(stream);
    const bt_value *hostname_value = bt_trace_borrow_environment_entry_value_by_name_const(trace, "hostname");

    /* Prepare domain */
    const bt_value *domain_value = bt_trace_borrow_environment_entry_value_by_name_const(trace, "domain");
	
    /* Prepare the context (aka stream packet context) field members */
    const bt_packet *packet = bt_event_borrow_packet_const(event);
    const bt_field *context_field = bt_packet_borrow_context_field_const(packet);
    
    /* Prepare the common context (aka stream event context) field members */
    const bt_field *common_context_field = bt_event_borrow_common_context_field_const(event);
    
    /* Prepare the payload field members */
    const bt_field *payload_field = bt_event_borrow_payload_field_const(event);
    
    /* Create event object to send */
    uint64_t payload_num, payload_string_size;
    int status_code = get_payload_num_and_string_size(payload_field, &payload_num, &payload_string_size);
    if (status_code == -1) {
        printf("Error in \"get_payload_num_and_string_size()\"\n");
        return;
    }
    uint64_t event_size = sizeof(custom_event) + payload_num * sizeof(int64_t) + payload_string_size;
    unsigned int payload_string_offset = sizeof(custom_event) + payload_num * sizeof(int64_t);
    custom_event *custom_event_object = (custom_event*) malloc (event_size);
    for (int i = 0; i < payload_num; ++i) {
        fill_payload_param_by_index(custom_event_object, payload_field, i, &payload_string_offset);
    }
    // custom_event_object->last_event = false;

    /* Get timestamp */
    int64_t ns_from_origin;
    bt_clock_snapshot_get_ns_from_origin_status cs_status = bt_clock_snapshot_get_ns_from_origin(clock_snapshot, &ns_from_origin);
    if (cs_status == BT_CLOCK_SNAPSHOT_GET_NS_FROM_ORIGIN_STATUS_OK) {
        format_int(custom_event_object->timestamp, ns_from_origin, 10);
    }

    /* Get hostname */
    strncpy(custom_event_object->hostname, bt_value_string_get(hostname_value), sizeof(custom_event_object->hostname));

    /* Get domain */
    strncpy(custom_event_object->domain, bt_value_string_get(domain_value), sizeof(custom_event_object->domain));

    /* Get event name */
    strncpy(custom_event_object->event_name, bt_event_class_get_name(event_class), sizeof(custom_event_object->event_name));

    /* Get cpu id */
    custom_event_object->cpu_id = get_uint64_value_from_field("cpu_id", context_field, NULL);
    
    /* Get tid */
    custom_event_object->tid = get_int64_value_from_field("tid", common_context_field, NULL);

    /*
    #define PACKET_NUMBER 100

    uint64_t index = 0;
    uint64_t packet_size[PACKET_NUMBER];
    // will use htonl and ntohl to code and decode
    uint64_t packet_size_send[PACKET_NUMBER];
    // array which saves 100 custom_event, will be sent through TCP socket
    int64_t event_objects[];
    void *pointer = event_objects;
    */
    printf("index = %lu\n", packet_index);
    printf(", \"event_name\":\"%s\"", custom_event_object->event_name);
    packet_size[packet_index] = event_size;
    // packet_size_send
    memcpy(pointer, custom_event_object, event_size);
    pointer += event_size;
    total_size += event_size;
    packet_index++;
    
    if(packet_index == PACKET_NUMBER)
    {

        /* Send object size */
        send(object_out->sockfd, packet_size, sizeof(uint64_t) * PACKET_NUMBER, 0);
        /* Send object */
        send(object_out->sockfd, event_objects, total_size, 0);
        memset(event_objects, 0, total_size);
        pointer = event_objects;
        total_size = 0;
        packet_index = 0;
    }




    /* Print index */
    printf("#%" PRIu64, object_out->index);

    //printf(" fd = %" PRIu64, *(uint64_t *)(custom_event_object + 1));

    /* Print timestamp (ns from origin) */
    //printf(", \"timestamp\":\"%s\"", custom_event_object->timestamp);

    /* Print hostname */
    //printf(", \"hostname\":\"%s\"", custom_event_object->hostname);

    /* Print domain */
    //printf(", \"domain\":\"%s\"", custom_event_object->domain);

    /* Print event name */
    printf(", \"event_name\":\"%s\"", custom_event_object->event_name);

    printf("\n");
 
    /* Increment the current event message's index */
    object_out->index++;
 
end:
    return;
}
 
/*
 * Consumes a batch of messages and writes the corresponding lines to
 * the standard csobj.
 */
bt_component_class_sink_consume_method_status object_csobj_consume(
        bt_self_component_sink *self_component_sink)
{
    bt_component_class_sink_consume_method_status status =
        BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
 
    /* Retrieve our private data from the component's user data */
    struct object_out *object_out = bt_self_component_get_data(
        bt_self_component_sink_as_self_component(self_component_sink));
 
    /* Consume a batch of messages from the upstream message iterator */
    bt_message_array_const messages;
    uint64_t message_count;
    bt_message_iterator_next_status next_status =
        bt_message_iterator_next(object_out->message_iterator, &messages,
            &message_count);
 
    switch (next_status) {
    case BT_MESSAGE_ITERATOR_NEXT_STATUS_END:
        /* End of iteration: put the message iterator's reference */
        bt_message_iterator_put_ref(object_out->message_iterator);
        status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_END;
        goto end;
    case BT_MESSAGE_ITERATOR_NEXT_STATUS_AGAIN:
        status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_AGAIN;
        goto end;
    case BT_MESSAGE_ITERATOR_NEXT_STATUS_MEMORY_ERROR:
        status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_MEMORY_ERROR;
        goto end;
    case BT_MESSAGE_ITERATOR_NEXT_STATUS_ERROR:
        status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
        goto end;
    default:
        break;
    }
 
    /* For each consumed message */
    for (uint64_t i = 0; i < message_count; i++) {
        /* Current message */
        const bt_message *message = messages[i];
 
        /* Print line for current message if it's an event message */
        print_message(object_out, message);
 
        /* Put this message's reference */
        bt_message_put_ref(message);
    }
 
end:
    return status;
}
 
/* Mandatory */
BT_PLUGIN_MODULE();
 
/* Define the `object` plugin */
BT_PLUGIN(object);
 
/* Define the `csobj` sink component class */
BT_PLUGIN_SINK_COMPONENT_CLASS(csobj, object_csobj_consume);
 
/* Set some of the `csobj` sink component class's optional methods */
BT_PLUGIN_SINK_COMPONENT_CLASS_INITIALIZE_METHOD(csobj,
    object_csobj_initialize);
BT_PLUGIN_SINK_COMPONENT_CLASS_FINALIZE_METHOD(csobj, object_csobj_finalize);
BT_PLUGIN_SINK_COMPONENT_CLASS_GRAPH_IS_CONFIGURED_METHOD(csobj,
    object_csobj_graph_is_configured);