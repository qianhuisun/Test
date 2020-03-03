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

/* This is a custom plugin to Babeltrace2.
 * Plugin name: object
 * Component name: csobj (refer to custom event object)
 * Component type: sink (output component)
 * This component can be used by adding option "--component=sink.object.csobj" to Babeltrace2 cmd"
 */

#define EVENT_OBJECT_NUMBER 100
#define SERVER_IPV4 "127.0.0.1"
#define SERVER_PORT 5026

/* structure of custom event object */
typedef struct custom_event
{
    int64_t timestamp;
    char hostname[32];
    char domain[32];
    char event_name[32];
    uint64_t cpu_id;
    int64_t tid;
    uint64_t payload_size;
    /* point to payload params */
    int64_t payloads[];
} custom_event;

/* Sink component's private data */
struct object_out
{
    /* Upstream message iterator (owned by this) */
    bt_message_iterator *message_iterator;
    /* Current event message index */
    uint64_t index;

    /* point to the buffer that saves all EVENT_OBJECT_NUMBER event objects, will be sent through TCP socket */
    char *custom_event_objects;
    /* point to the address within the buffer to which the next event object will be copied to */
    char *head;
    /* index of event object to be copied to buffer, loop among [0, EVENT_OBJECT_NUMBER - 1] */
    uint64_t custom_event_object_index;
    /* size array of EVENT_OBJECT_NUMBER event objects */
    uint64_t custom_event_object_size[EVENT_OBJECT_NUMBER];
    /* total size of all EVENT_OBJECT_NUMBER event objects */
    uint64_t custom_event_objects_size;
    /* client socket fd */
    int sockfd;
};


/*
 * Initializes the sink component.
 */
static bt_component_class_initialize_method_status object_csobj_initialize(
    bt_self_component_sink *self_component_sink,
    bt_self_component_sink_configuration *configuration,
    const bt_value *params, void *initialize_method_data)
{
    /* Allocate a private data structure */
    struct object_out *object_out = malloc(sizeof(*object_out));
    /* Initialize the first event message's index */
    object_out->index = 1;

    /*
     * We must allocate enough space for EVENT_OBJECT_NUMBER event objects.
     * Usually, the size of an event object won't be larger than 200 bytes,
     * but still we allocate 1000 * EVENT_OBJECT_NUMBER bytes for all the
     * EVENT_OBJECT_NUMBER objects just in case.
     */
    object_out->custom_event_objects = malloc(1000 * EVENT_OBJECT_NUMBER);
    object_out->head = object_out->custom_event_objects;
    object_out->custom_event_object_index = 0;
    object_out->custom_event_objects_size = 0;

    /*  Initialize the client socket */
    struct sockaddr_in server_addr;
    memset(&server_addr, '0', sizeof(server_addr));
    if ((object_out->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IPV4, &server_addr.sin_addr) <= 0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    }
    if (connect(object_out->sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("\n Error: Connect Failed \n");
        return 1;
    }

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

    return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

/*
 * Finalizes the sink component.
 */
static void object_csobj_finalize(bt_self_component_sink *self_component_sink)
{
    /* Retrieve our private data from the component's user data */
    struct object_out *object_out = bt_self_component_get_data(
        bt_self_component_sink_as_self_component(self_component_sink));

    /* set the rest element in size array to 0 */
    for (; object_out->custom_event_object_index < EVENT_OBJECT_NUMBER; object_out->custom_event_object_index++)
    {
        object_out->custom_event_object_size[object_out->custom_event_object_index] = 0;
    }

    /* Send size array of EVENT_OBJECT_NUMBER event objects */
    send(object_out->sockfd, object_out->custom_event_object_size, sizeof(uint64_t) * EVENT_OBJECT_NUMBER, 0);
    /* Send event objects */
    send(object_out->sockfd, object_out->custom_event_objects, object_out->custom_event_objects_size, 0);

    /* Free the allocated structure */
    free(object_out->custom_event_objects);
    free(object_out);
}

/*
 * Called when the trace processing graph containing the sink component
 * is configured.
 *
 * This is where we can create our upstream message iterator.
 */
static bt_component_class_sink_graph_is_configured_method_status
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
int get_payload_num_and_string_size(const bt_field *payload_field, uint64_t *payload_num, uint64_t *payload_string_size)
{
    /* payload field must be a structure */
    if (bt_field_get_class_type(payload_field) == BT_FIELD_CLASS_TYPE_STRUCTURE)
    {
        const bt_field_class *payload_field_class = bt_field_borrow_class_const(payload_field);
        *payload_num = bt_field_class_structure_get_member_count(payload_field_class);
        *payload_string_size = 0;
        for (int i = 0; i < *payload_num; ++i)
        {
            const bt_field *member_field = bt_field_structure_borrow_member_field_by_index_const(payload_field, i);
            if (bt_field_get_class_type(member_field) == BT_FIELD_CLASS_TYPE_STRING)
            {
                const char *buf = bt_field_string_get_value(member_field);
                *payload_string_size += strlen(buf);
            }
        }
        return 0;
    }
    else
    {
        return -1;
    }
}

/* fill the values of payload params in our event object*/
void fill_payload_param_by_index(custom_event *custom_event_object, const bt_field *payload_field, int i, unsigned int *payload_string_offset)
{
    const bt_field *member_field = bt_field_structure_borrow_member_field_by_index_const(payload_field, i);
    bt_field_class_type member_field_class_type = bt_field_get_class_type(member_field);
    if (member_field_class_type == BT_FIELD_CLASS_TYPE_BOOL)
    {
        int64_t bool_value = (int64_t)bt_field_bool_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &bool_value, sizeof(int64_t));
    }
    else if (member_field_class_type == BT_FIELD_CLASS_TYPE_BIT_ARRAY)
    {
        uint64_t bit_array_value = bt_field_bit_array_get_value_as_integer(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &bit_array_value, sizeof(int64_t));
    }
    else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER))
    {
        uint64_t unsigned_integer_value = bt_field_integer_unsigned_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &unsigned_integer_value, sizeof(int64_t));
    }
    else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER))
    {
        int64_t signed_integer_value = bt_field_integer_signed_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &signed_integer_value, sizeof(int64_t));
    }
    else if (member_field_class_type == BT_FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL)
    {
        double real_value = bt_field_real_single_precision_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &real_value, sizeof(int64_t));
    }
    else if (member_field_class_type == BT_FIELD_CLASS_TYPE_DOUBLE_PRECISION_REAL)
    {
        double real_value = bt_field_real_double_precision_get_value(member_field);
        memcpy((int64_t *)(custom_event_object + 1) + i, &real_value, sizeof(int64_t));
    }
    else if (member_field_class_type == BT_FIELD_CLASS_TYPE_STRING)
    {
        const char *string_value = bt_field_string_get_value(member_field);
        unsigned int string_offset = *payload_string_offset;
        unsigned int string_length = strlen(string_value);
        memcpy((int64_t *)(custom_event_object + 1) + i, &string_offset, sizeof(int));
        memcpy((int *)((int64_t *)(custom_event_object + 1) + i) + 1, &string_length, sizeof(int));
        memcpy((char *)custom_event_object + string_offset, string_value, string_length);
        *payload_string_offset += string_length;
    }
    else if (member_field_class_type == BT_FIELD_CLASS_TYPE_STRUCTURE)
    {
        /* To do: a structure in payload structure */
    }
    else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_ARRAY))
    {
        /* To do: an array in payload structure  */
    }
    else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_OPTION))
    {
        /* This type has never appeared before */
    }
    else if (bt_field_class_type_is(member_field_class_type, BT_FIELD_CLASS_TYPE_VARIANT))
    {   
        /* To do: a variant in payload structure */
        /* This type usually (if not always) wraps up only one structure */
    }
}

/* get a parameter's value with type of uint64 */
static uint64_t get_uint64_value_from_field(const char *target_name, const bt_field *field, const char *name)
{
    bt_field_class_type field_class_type = bt_field_get_class_type(field);
    const bt_field_class *field_class;
    if (bt_field_class_type_is(field_class_type, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER))
    {
        if (strcmp(target_name, name) == 0)
        {
            return bt_field_integer_unsigned_get_value(field);
        }
    }
    else if (field_class_type == BT_FIELD_CLASS_TYPE_STRUCTURE)
    {
        field_class = bt_field_borrow_class_const(field);
        uint64_t member_count = bt_field_class_structure_get_member_count(field_class);
        for (int i = 0; i < member_count; ++i)
        {
            const bt_field_class_structure_member *field_class_structure_member =
                bt_field_class_structure_borrow_member_by_index_const(field_class, i);
            const bt_field *member_field =
                bt_field_structure_borrow_member_field_by_index_const(field, i);
            const char *member_name = bt_field_class_structure_member_get_name(field_class_structure_member);
            if (strcmp(target_name, member_name) == 0)
            {
                return get_uint64_value_from_field(target_name, member_field, member_name);
            }
        }
        /* Error code 999999: target_name not in the structure */
        return 999999;
    }
    else
    {
        /* Error code 888888: field is not a structure */
        return 888888;
    }
}

/* get a parameter's value with type of int64 */
static int64_t get_int64_value_from_field(const char *target_name, const bt_field *field, const char *name)
{
    bt_field_class_type field_class_type = bt_field_get_class_type(field);
    const bt_field_class *field_class;
    if (bt_field_class_type_is(field_class_type, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER))
    {
        if (strcmp(target_name, name) == 0)
        {
            return bt_field_integer_signed_get_value(field);
        }
    }
    else if (field_class_type == BT_FIELD_CLASS_TYPE_STRUCTURE)
    {
        field_class = bt_field_borrow_class_const(field);
        uint64_t member_count = bt_field_class_structure_get_member_count(field_class);
        for (int i = 0; i < member_count; ++i)
        {
            const bt_field_class_structure_member *field_class_structure_member =
                bt_field_class_structure_borrow_member_by_index_const(field_class, i);
            const bt_field *member_field =
                bt_field_structure_borrow_member_field_by_index_const(field, i);
            const char *member_name = bt_field_class_structure_member_get_name(field_class_structure_member);
            if (strcmp(target_name, member_name) == 0)
            {
                return get_int64_value_from_field(target_name, member_field, member_name);
            }
        }
        /* Error code 999999: target_name not in the structure */
        return 999999;
    }
    else
    {
        /* Error code 888888: field is not a structure */
        return 888888;
    }
}

/* get a parameter's value with type of string */
static const char *get_string_value_from_field(const char *target_name, const bt_field *field, const char *name)
{
    bt_field_class_type field_class_type = bt_field_get_class_type(field);
    const bt_field_class *field_class;
    if (field_class_type == BT_FIELD_CLASS_TYPE_STRING)
    {
        if (strcmp(target_name, name) == 0)
        {
            return bt_field_string_get_value(field);
        }
    }
    else if (field_class_type == BT_FIELD_CLASS_TYPE_STRUCTURE)
    {
        field_class = bt_field_borrow_class_const(field);
        uint64_t member_count = bt_field_class_structure_get_member_count(field_class);
        for (int i = 0; i < member_count; ++i)
        {
            const bt_field_class_structure_member *field_class_structure_member =
                bt_field_class_structure_borrow_member_by_index_const(field_class, i);
            const bt_field *member_field =
                bt_field_structure_borrow_member_field_by_index_const(field, i);
            const char *member_name = bt_field_class_structure_member_get_name(field_class_structure_member);
            if (strcmp(target_name, member_name) == 0)
            {
                return get_string_value_from_field(target_name, member_field, member_name);
            }
        }
        /* Error code 999999: target_name not in the structure */
        return "999999";
    }
    else
    {
        /* Error code 888888: field is not a structure */
        return "888888";
    }
}

/*
 * Prints a line for `message`, if it's an event message, to the
 * standard csobj.
 */
static void print_message(struct object_out *object_out, const bt_message *message)
{
    /* Discard if it's not an event message */
    if (bt_message_get_type(message) != BT_MESSAGE_TYPE_EVENT)
    {
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
    if (status_code == -1)
    {
        printf("Error in \"get_payload_num_and_string_size()\"\n");
        return;
    }
    uint64_t event_size = sizeof(custom_event) + payload_num * sizeof(int64_t) + payload_string_size;
    unsigned int payload_string_offset = sizeof(custom_event) + payload_num * sizeof(int64_t);
    custom_event *custom_event_object = (custom_event *)malloc(event_size);
    for (int i = 0; i < payload_num; ++i)
    {
        fill_payload_param_by_index(custom_event_object, payload_field, i, &payload_string_offset);
    }

    /* Get timestamp */
    bt_clock_snapshot_get_ns_from_origin(clock_snapshot, &custom_event_object->timestamp);

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

    object_out->custom_event_object_size[object_out->custom_event_object_index] = event_size;
    memcpy(object_out->head, custom_event_object, event_size);
    object_out->head += event_size;
    object_out->custom_event_objects_size += event_size;
    object_out->custom_event_object_index++;

    if (object_out->custom_event_object_index == EVENT_OBJECT_NUMBER)
    {

        /* Send size array of EVENT_OBJECT_NUMBER event objects */
        send(object_out->sockfd, object_out->custom_event_object_size, sizeof(uint64_t) * EVENT_OBJECT_NUMBER, 0);
        /* Receive response from server */
        char response[256];
        recv(object_out->sockfd, response, sizeof(response), 0);
        //printf("%s\n", response);
        /* Send event objects */
        send(object_out->sockfd, object_out->custom_event_objects, object_out->custom_event_objects_size, 0);
        memset(object_out->custom_event_objects, 0, object_out->custom_event_objects_size);
        object_out->head = object_out->custom_event_objects;
        object_out->custom_event_objects_size = 0;
        object_out->custom_event_object_index = 0;
    }

    /* Debug: Print event name */
    //printf("#%" PRIu64 " \"custom_event_object_index\":%" PRIu64 ", \"event_name\":\"%s\"\n", object_out->index, object_out->custom_event_object_index , custom_event_object->event_name);
    
    free(custom_event_object);

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

    switch (next_status)
    {
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
    for (uint64_t i = 0; i < message_count; i++)
    {
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