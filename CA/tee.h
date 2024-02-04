typedef unsigned int size_t;

enum TEEC_ParamType {
    TEEC_NONE = 0x0,  /* unused parameter */
    TEEC_VALUE_INPUT = 0x01,  /* input type of value, refer TEEC_Value */
    TEEC_VALUE_OUTPUT = 0x02, /* output type of value, refer TEEC_Value */
    TEEC_VALUE_INOUT = 0x03,  /* value is used as both input and output, refer TEEC_Value */
    TEEC_MEMREF_TEMP_INPUT = 0x05,  /* input type of temp memory reference, refer TEEC_TempMemoryReference */
    TEEC_MEMREF_TEMP_OUTPUT = 0x06, /* output type of temp memory reference, refer TEEC_TempMemoryReference */
    TEEC_MEMREF_TEMP_INOUT = 0x07,  /* temp memory reference used as both input and output,
                                       refer TEEC_TempMemoryReference */
    TEEC_ION_INPUT = 0x08,  /* input type of icon memory reference, refer TEEC_IonReference */
    TEEC_ION_SGLIST_INPUT = 0x09, /* input type of ion memory block reference, refer TEEC_IonSglistReference */
    TEEC_MEMREF_SHARED_INOUT = 0x0a, /* no copy mem */
    TEEC_MEMREF_WHOLE = 0xc, /* use whole memory block, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_INPUT = 0xd, /* input type of memory reference, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_OUTPUT = 0xe, /* output type of memory reference, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_INOUT = 0xf /* memory reference used as both input and output,
                                        refer TEEC_RegisteredMemoryReference */
};

struct TEE_VALUE_Param
{
    size_t a;
    size_t b;
};

struct TEE_MEMREF_Param
{
    void *buffer;
    size_t size;
};


union TEE_Param
{
    struct TEE_VALUE_Param value;
    struct TEE_MEMREF_Param memref;
};
