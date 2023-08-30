//---------------------------------------------------------------- optee_client/public/tee_client_api.h

enum TEEC_CONFIG_PAYLOAD_REF_COUNT {
    TEEC_CONFIG_PAYLOAD_REF_COUNT = 4,
};

enum TEEC_CONFIG_SHAREDMEM_MAX_SIZE_{
    TEEC_CONFIG_SHAREDMEM_MAX_SIZE = ULONG_MAX,
};

enum TEEC_PARAM_TYPE {
    TEEC_NONE                  = 0x00000000,
    TEEC_VALUE_INPUT           = 0x00000001,
    TEEC_VALUE_OUTPUT          = 0x00000002,
    TEEC_VALUE_INOUT           = 0x00000003,
    TEEC_MEMREF_TEMP_INPUT     = 0x00000005,
    TEEC_MEMREF_TEMP_OUTPUT    = 0x00000006,
    TEEC_MEMREF_TEMP_INOUT     = 0x00000007,
    TEEC_MEMREF_WHOLE          = 0x0000000C,
    TEEC_MEMREF_PARTIAL_INPUT  = 0x0000000D,
    TEEC_MEMREF_PARTIAL_OUTPUT = 0x0000000E,
    TEEC_MEMREF_PARTIAL_INOUT  = 0x0000000F,
};

enum TEEC_MEM_TYPE {
    TEEC_MEM_INPUT  = 0x00000001,
    TEEC_MEM_OUTPUT = 0x00000002,
};

enum TEEC_ERROR_TYPE {
    TEEC_SUCCESS                     = 0x00000000,
    TEEC_ERROR_STORAGE_NOT_AVAILABLE = 0xF0100003,
    TEEC_ERROR_GENERIC               = 0xFFFF0000,
    TEEC_ERROR_ACCESS_DENIED         = 0xFFFF0001,
    TEEC_ERROR_CANCEL                = 0xFFFF0002,
    TEEC_ERROR_ACCESS_CONFLICT       = 0xFFFF0003,
    TEEC_ERROR_EXCESS_DATA           = 0xFFFF0004,
    TEEC_ERROR_BAD_FORMAT            = 0xFFFF0005,
    TEEC_ERROR_BAD_PARAMETERS        = 0xFFFF0006,
    TEEC_ERROR_BAD_STATE             = 0xFFFF0007,
    TEEC_ERROR_ITEM_NOT_FOUND        = 0xFFFF0008,
    TEEC_ERROR_NOT_IMPLEMENTED       = 0xFFFF0009,
    TEEC_ERROR_NOT_SUPPORTED         = 0xFFFF000A,
    TEEC_ERROR_NO_DATA               = 0xFFFF000B,
    TEEC_ERROR_OUT_OF_MEMORY         = 0xFFFF000C,
    TEEC_ERROR_BUSY                  = 0xFFFF000D,
    TEEC_ERROR_COMMUNICATION         = 0xFFFF000E,
    TEEC_ERROR_SECURITY              = 0xFFFF000F,
    TEEC_ERROR_SHORT_BUFFER          = 0xFFFF0010,
    TEEC_ERROR_EXTERNAL_CANCEL       = 0xFFFF0011,
    TEEC_ERROR_TARGET_DEAD           = 0xFFFF3024,
};

enum TEEC_ORIGIN_TYPE {
    TEEC_ORIGIN_API         = 0x00000001,
    TEEC_ORIGIN_COMMS       = 0x00000002,
    TEEC_ORIGIN_TEE         = 0x00000003,
    TEEC_ORIGIN_TRUSTED_APP = 0x00000004,
};

enum TEEC_LOGIN_TYPE {
    TEEC_LOGIN_PUBLIC            = 0x00000000,
    TEEC_LOGIN_USER              = 0x00000001,
    TEEC_LOGIN_GROUP             = 0x00000002,
    TEEC_LOGIN_APPLICATION       = 0x00000004,
    TEEC_LOGIN_USER_APPLICATION  = 0x00000005,
    TEEC_LOGIN_GROUP_APPLICATION = 0x00000006,
};

typedef uint32_t TEEC_Result;

struct TEEC_Context {
    /* Implementation defined */
    int fd;
    bool reg_mem;
    bool memref_null;
};

struct TEEC_UUID {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[8];
};

struct TEEC_SharedMemory {
    void *buffer;
    size_t size;
    uint32_t flags;
    /* Implementation-Defined */
    int id;
    size_t alloced_size;
    void *shadow_buffer;
    int registered_fd;
    union {
        bool dummy;
        uint8_t flags;
    } internal;
};

struct TEEC_TempMemoryReference {
    void *buffer;
    size_t size;
};

struct TEEC_RegisteredMemoryReference {
    struct TEEC_SharedMemory *parent;
    size_t size;
    size_t offset;
};

struct TEEC_Value {
    uint32_t a;
    uint32_t b;
};

union TEEC_Parameter {
    struct TEEC_TempMemoryReference tmpref;
    struct TEEC_RegisteredMemoryReference memref;
    struct TEEC_Value value;
};

struct TEEC_Session {
    /* Implementation defined */
    struct TEEC_Context *ctx;
    uint32_t session_id;
};

struct TEEC_Operation {
    uint32_t started;
    uint32_t paramTypes;
    struct TEEC_Parameter params[4];
    /* Implementation-Defined */
    struct TEEC_Session *session;
};

//---------------------------------------------------------------- optee_os/lib/libdl/include/dlfcn.h

enum DL_RTDL {
    /* Relocations are performed when the object is loaded. */
    RTLD_NOW = 2,
    /* All symbols are available for relocation processing of other modules. */
    RTLD_GLOBAL = 0x100,
    /* Do not unload the shared object during dlclose(). */
    RTLD_NODELETE = 0x1000,
};

//---------------------------------------------------------------- optee_os/lib/libunw/include/unw/unwind.h

struct unwind_state_arm32 {
    uint32_t registers[16];
    uint32_t start_pc;
    uintptr_t insn;
    unsigned int entries;
    unsigned int byte;
    uint16_t update_mask;
};

struct unwind_state_arm64 {
    uint64_t fp;
    uint64_t sp;
    uint64_t pc;
};

//---------------------------------------------------------------- optee_os/lib/libutee/arch/arm/user_ta_entry.c

struct ta_session {
    uint32_t session_id;
    void *session_ctx;
    struct {
        struct ta_session *tqe_next;  /* next element */
        struct ta_session **tqe_prev; /* address of previous next element */
    };
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/tee_api_defines.h

enum TEE_INT_CORE_API_SPEC_VERSION {
    TEE_INT_CORE_API_SPEC_VERSION = 0x0000000A,
};

enum TEE_HANDLE_NULL {
    TEE_HANDLE_NULL = 0,
};

enum TEE_TIMEOUT_INFINITE {
    TEE_TIMEOUT_INFINITE = 0xFFFFFFFF,
};

/* API Error Codes */
enum TEE_ERROR_TYPE {
    TEE_SUCCESS                       = 0x00000000,
    TEE_ERROR_CORRUPT_OBJECT          = 0xF0100001,
    TEE_ERROR_CORRUPT_OBJECT_2        = 0xF0100002,
    TEE_ERROR_STORAGE_NOT_AVAILABLE   = 0xF0100003,
    TEE_ERROR_STORAGE_NOT_AVAILABLE_2 = 0xF0100004,
    TEE_ERROR_CIPHERTEXT_INVALID      = 0xF0100006,
    TEE_ERROR_GENERIC                 = 0xFFFF0000,
    TEE_ERROR_ACCESS_DENIED           = 0xFFFF0001,
    TEE_ERROR_CANCEL                  = 0xFFFF0002,
    TEE_ERROR_ACCESS_CONFLICT         = 0xFFFF0003,
    TEE_ERROR_EXCESS_DATA             = 0xFFFF0004,
    TEE_ERROR_BAD_FORMAT              = 0xFFFF0005,
    TEE_ERROR_BAD_PARAMETERS          = 0xFFFF0006,
    TEE_ERROR_BAD_STATE               = 0xFFFF0007,
    TEE_ERROR_ITEM_NOT_FOUND          = 0xFFFF0008,
    TEE_ERROR_NOT_IMPLEMENTED         = 0xFFFF0009,
    TEE_ERROR_NOT_SUPPORTED           = 0xFFFF000A,
    TEE_ERROR_NO_DATA                 = 0xFFFF000B,
    TEE_ERROR_OUT_OF_MEMORY           = 0xFFFF000C,
    TEE_ERROR_BUSY                    = 0xFFFF000D,
    TEE_ERROR_COMMUNICATION           = 0xFFFF000E,
    TEE_ERROR_SECURITY                = 0xFFFF000F,
    TEE_ERROR_SHORT_BUFFER            = 0xFFFF0010,
    TEE_ERROR_EXTERNAL_CANCEL         = 0xFFFF0011,
    TEE_ERROR_OVERFLOW                = 0xFFFF300F,
    TEE_ERROR_TARGET_DEAD             = 0xFFFF3024,
    TEE_ERROR_STORAGE_NO_SPACE        = 0xFFFF3041,
    TEE_ERROR_MAC_INVALID             = 0xFFFF3071,
    TEE_ERROR_SIGNATURE_INVALID       = 0xFFFF3072,
    TEE_ERROR_TIME_NOT_SET            = 0xFFFF5000,
    TEE_ERROR_TIME_NEEDS_RESET        = 0xFFFF5001,
};

/* Parameter Type Constants */
enum TEE_PARAM_TYPE {
    TEE_PARAM_TYPE_NONE          = 0,
    TEE_PARAM_TYPE_VALUE_INPUT   = 1,
    TEE_PARAM_TYPE_VALUE_OUTPUT  = 2,
    TEE_PARAM_TYPE_VALUE_INOUT   = 3,
    TEE_PARAM_TYPE_MEMREF_INPUT  = 5,
    TEE_PARAM_TYPE_MEMREF_OUTPUT = 6,
    TEE_PARAM_TYPE_MEMREF_INOUT  = 7,
};

/* Login Type Constants */
enum TEE_LOGIN_TYPE {
    TEE_LOGIN_PUBLIC            = 0x00000000,
    TEE_LOGIN_USER              = 0x00000001,
    TEE_LOGIN_GROUP             = 0x00000002,
    TEE_LOGIN_APPLICATION       = 0x00000004,
    TEE_LOGIN_APPLICATION_USER  = 0x00000005,
    TEE_LOGIN_APPLICATION_GROUP = 0x00000006,
    TEE_LOGIN_TRUSTED_APP       = 0xF0000000,
};

/* Origin Code Constants */
enum TEE_ORIGIN_TYPE {
    TEE_ORIGIN_API         = 0x00000001,
    TEE_ORIGIN_COMMS       = 0x00000002,
    TEE_ORIGIN_TEE         = 0x00000003,
    TEE_ORIGIN_TRUSTED_APP = 0x00000004,
};

/* Property Sets pseudo handles */
enum TEE_PROPSET_TYPE {
    TEE_PROPSET_TEE_IMPLEMENTATION = 0xFFFFFFFD,
    TEE_PROPSET_CURRENT_CLIENT     = 0xFFFFFFFE,
    TEE_PROPSET_CURRENT_TA         = 0xFFFFFFFF,
};

/* Memory Access Rights Constants */
enum TEE_MEMORY_ACCESS_TYPE {
    TEE_MEMORY_ACCESS_READ      = 0x00000001,
    TEE_MEMORY_ACCESS_WRITE     = 0x00000002,
    TEE_MEMORY_ACCESS_ANY_OWNER = 0x00000004,
};

/* Memory Management Constant */
enum TEE_MALLOC_FILL_ZERO {
    TEE_MALLOC_FILL_ZERO = 0x00000000,
};

/* Other constants */
enum TEE_STORAGE_TYPE {
    TEE_STORAGE_PRIVATE = 0x00000001,
};

enum TEE_DATA_FLAG {
    TEE_DATA_FLAG_ACCESS_READ       = 0x00000001,
    TEE_DATA_FLAG_ACCESS_WRITE      = 0x00000002,
    TEE_DATA_FLAG_ACCESS_WRITE_META = 0x00000004,
    TEE_DATA_FLAG_SHARE_READ        = 0x00000010,
    TEE_DATA_FLAG_SHARE_WRITE       = 0x00000020,
    TEE_DATA_FLAG_OVERWRITE         = 0x00000400,
};

enum TEE_DATA_MAX_POSITION {
    TEE_DATA_MAX_POSITION = 0xFFFFFFFF,
};

enum TEE_OBJECT_ID_MAX_LEN {
    TEE_OBJECT_ID_MAX_LEN = 64,
};

enum TEE_USAGE_FLAG {
    TEE_USAGE_EXTRACTABLE = 0x00000001,
    TEE_USAGE_ENCRYPT     = 0x00000002,
    TEE_USAGE_DECRYPT     = 0x00000004,
    TEE_USAGE_MAC         = 0x00000008,
    TEE_USAGE_SIGN        = 0x00000010,
    TEE_USAGE_VERIFY      = 0x00000020,
    TEE_USAGE_DERIVE      = 0x00000040,
};

enum TEE_HANDLE_FLAG_TYPE {
    TEE_HANDLE_FLAG_PERSISTENT      = 0x00010000,
    TEE_HANDLE_FLAG_INITIALIZED     = 0x00020000,
    TEE_HANDLE_FLAG_KEY_SET         = 0x00040000,
    TEE_HANDLE_FLAG_EXPECT_TWO_KEYS = 0x00080000,
};

enum TEE_OPERATION_TYPE {
    TEE_OPERATION_CIPHER               = 1,
    TEE_OPERATION_MAC                  = 3,
    TEE_OPERATION_AE                   = 4,
    TEE_OPERATION_DIGEST               = 5,
    TEE_OPERATION_ASYMMETRIC_CIPHER    = 6,
    TEE_OPERATION_ASYMMETRIC_SIGNATURE = 7,
    TEE_OPERATION_KEY_DERIVATION       = 8
};

enum TEE_OPERATION_STATE_TYPE {
    TEE_OPERATION_STATE_INITIAL = 0x00000000,
    TEE_OPERATION_STATE_ACTIVE  = 0x00000001,
};

/* Algorithm Identifiers */
enum TEE_ALG_TYPE {
    TEE_ALG_AES_ECB_NOPAD                = 0x10000010,
    TEE_ALG_AES_CBC_NOPAD                = 0x10000110,
    TEE_ALG_AES_CTR                      = 0x10000210,
    TEE_ALG_AES_CTS                      = 0x10000310,
    TEE_ALG_AES_XTS                      = 0x10000410,
    TEE_ALG_AES_CBC_MAC_NOPAD            = 0x30000110,
    TEE_ALG_AES_CBC_MAC_PKCS5            = 0x30000510,
    TEE_ALG_AES_CMAC                     = 0x30000610,
    TEE_ALG_AES_CCM                      = 0x40000710,
    TEE_ALG_AES_GCM                      = 0x40000810,
    TEE_ALG_DES_ECB_NOPAD                = 0x10000011,
    TEE_ALG_DES_CBC_NOPAD                = 0x10000111,
    TEE_ALG_DES_CBC_MAC_NOPAD            = 0x30000111,
    TEE_ALG_DES_CBC_MAC_PKCS5            = 0x30000511,
    TEE_ALG_DES3_ECB_NOPAD               = 0x10000013,
    TEE_ALG_DES3_CBC_NOPAD               = 0x10000113,
    TEE_ALG_DES3_CBC_MAC_NOPAD           = 0x30000113,
    TEE_ALG_DES3_CBC_MAC_PKCS5           = 0x30000513,
    TEE_ALG_SM4_ECB_NOPAD                = 0x10000014,
    TEE_ALG_SM4_CBC_NOPAD                = 0x10000114,
    TEE_ALG_SM4_CTR                      = 0x10000214,
    TEE_ALG_RSASSA_PKCS1_V1_5_MD5        = 0x70001830,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA1       = 0x70002830,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA224     = 0x70003830,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA256     = 0x70004830,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA384     = 0x70005830,
    TEE_ALG_RSASSA_PKCS1_V1_5_SHA512     = 0x70006830,
    TEE_ALG_RSASSA_PKCS1_V1_5_MD5SHA1    = 0x7000F830,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1   = 0x70212930,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 = 0x70313930,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 = 0x70414930,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 = 0x70515930,
    TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 = 0x70616930,
    TEE_ALG_RSAES_PKCS1_V1_5             = 0x60000130,
    TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1   = 0x60210230,
    TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224 = 0x60310230,
    TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 = 0x60410230,
    TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384 = 0x60510230,
    TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 = 0x60610230,
    TEE_ALG_RSA_NOPAD                    = 0x60000030,
    TEE_ALG_DSA_SHA1                     = 0x70002131,
    TEE_ALG_DSA_SHA224                   = 0x70003131,
    TEE_ALG_DSA_SHA256                   = 0x70004131,
    TEE_ALG_SM2_DSA_SM3                  = 0x70006045,
    TEE_ALG_DH_DERIVE_SHARED_SECRET      = 0x80000032,
    TEE_ALG_SM2_KEP                      = 0x60000045,
    TEE_ALG_MD5                          = 0x50000001,
    TEE_ALG_SHA1                         = 0x50000002,
    TEE_ALG_SHA224                       = 0x50000003,
    TEE_ALG_SHA256                       = 0x50000004,
    TEE_ALG_SHA384                       = 0x50000005,
    TEE_ALG_SHA512                       = 0x50000006,
    TEE_ALG_MD5SHA1                      = 0x5000000F,
    TEE_ALG_HMAC_MD5                     = 0x30000001,
    TEE_ALG_HMAC_SHA1                    = 0x30000002,
    TEE_ALG_HMAC_SHA224                  = 0x30000003,
    TEE_ALG_HMAC_SHA256                  = 0x30000004,
    TEE_ALG_HMAC_SHA384                  = 0x30000005,
    TEE_ALG_HMAC_SHA512                  = 0x30000006,
    TEE_ALG_HMAC_SM3                     = 0x30000007,
    TEE_ALG_ECDSA_P192                   = 0x70001041,
    TEE_ALG_ECDSA_P224                   = 0x70002041,
    TEE_ALG_ECDSA_P256                   = 0x70003041,
    TEE_ALG_ECDSA_P384                   = 0x70004041,
    TEE_ALG_ECDSA_P521                   = 0x70005041,
    TEE_ALG_ECDH_P192                    = 0x80001042,
    TEE_ALG_ECDH_P224                    = 0x80002042,
    TEE_ALG_ECDH_P256                    = 0x80003042,
    TEE_ALG_ECDH_P384                    = 0x80004042,
    TEE_ALG_ECDH_P521                    = 0x80005042,
    TEE_ALG_SM2_PKE                      = 0x80000045,
    TEE_ALG_SM3                          = 0x50000007,
    TEE_ALG_ILLEGAL_VALUE                = 0xEFFFFFFF,
};

enum TEEE_OBJECT_TYPE {
    TEE_TYPE_AES                = 0xA0000010,
    TEE_TYPE_DES                = 0xA0000011,
    TEE_TYPE_DES3               = 0xA0000013,
    TEE_TYPE_SM4                = 0xA0000014,
    TEE_TYPE_HMAC_MD5           = 0xA0000001,
    TEE_TYPE_HMAC_SHA1          = 0xA0000002,
    TEE_TYPE_HMAC_SHA224        = 0xA0000003,
    TEE_TYPE_HMAC_SHA256        = 0xA0000004,
    TEE_TYPE_HMAC_SHA384        = 0xA0000005,
    TEE_TYPE_HMAC_SHA512        = 0xA0000006,
    TEE_TYPE_HMAC_SM3           = 0xA0000007, /* Not in spec */
    TEE_TYPE_RSA_PUBLIC_KEY     = 0xA0000030,
    TEE_TYPE_RSA_KEYPAIR        = 0xA1000030,
    TEE_TYPE_DSA_PUBLIC_KEY     = 0xA0000031,
    TEE_TYPE_DSA_KEYPAIR        = 0xA1000031,
    TEE_TYPE_DH_KEYPAIR         = 0xA1000032,
    TEE_TYPE_ECDSA_PUBLIC_KEY   = 0xA0000041,
    TEE_TYPE_ECDSA_KEYPAIR      = 0xA1000041,
    TEE_TYPE_ECDH_PUBLIC_KEY    = 0xA0000042,
    TEE_TYPE_ECDH_KEYPAIR       = 0xA1000042,
    TEE_TYPE_SM2_DSA_PUBLIC_KEY = 0xA0000045,
    TEE_TYPE_SM2_DSA_KEYPAIR    = 0xA1000045,
    TEE_TYPE_SM2_KEP_PUBLIC_KEY = 0xA0000046,
    TEE_TYPE_SM2_KEP_KEYPAIR    = 0xA1000046,
    TEE_TYPE_SM2_PKE_PUBLIC_KEY = 0xA0000047,
    TEE_TYPE_SM2_PKE_KEYPAIR    = 0xA1000047,
    TEE_TYPE_GENERIC_SECRET     = 0xA0000000,
    TEE_TYPE_CORRUPTED_OBJECT   = 0xA00000BE,
    TEE_TYPE_DATA               = 0xA00000BF,
};

enum TEE_ATTR_TYPE {
    TEE_ATTR_SECRET_VALUE                 = 0xC0000000,
    TEE_ATTR_RSA_MODULUS                  = 0xD0000130,
    TEE_ATTR_RSA_PUBLIC_EXPONENT          = 0xD0000230,
    TEE_ATTR_RSA_PRIVATE_EXPONENT         = 0xC0000330,
    TEE_ATTR_RSA_PRIME1                   = 0xC0000430,
    TEE_ATTR_RSA_PRIME2                   = 0xC0000530,
    TEE_ATTR_RSA_EXPONENT1                = 0xC0000630,
    TEE_ATTR_RSA_EXPONENT2                = 0xC0000730,
    TEE_ATTR_RSA_COEFFICIENT              = 0xC0000830,
    TEE_ATTR_DSA_PRIME                    = 0xD0001031,
    TEE_ATTR_DSA_SUBPRIME                 = 0xD0001131,
    TEE_ATTR_DSA_BASE                     = 0xD0001231,
    TEE_ATTR_DSA_PUBLIC_VALUE             = 0xD0000131,
    TEE_ATTR_DSA_PRIVATE_VALUE            = 0xC0000231,
    TEE_ATTR_DH_PRIME                     = 0xD0001032,
    TEE_ATTR_DH_SUBPRIME                  = 0xD0001132,
    TEE_ATTR_DH_BASE                      = 0xD0001232,
    TEE_ATTR_DH_X_BITS                    = 0xF0001332,
    TEE_ATTR_DH_PUBLIC_VALUE              = 0xD0000132,
    TEE_ATTR_DH_PRIVATE_VALUE             = 0xC0000232,
    TEE_ATTR_RSA_OAEP_LABEL               = 0xD0000930,
    TEE_ATTR_RSA_PSS_SALT_LENGTH          = 0xF0000A30,
    TEE_ATTR_ECC_PUBLIC_VALUE_X           = 0xD0000141,
    TEE_ATTR_ECC_PUBLIC_VALUE_Y           = 0xD0000241,
    TEE_ATTR_ECC_PRIVATE_VALUE            = 0xC0000341,
    TEE_ATTR_ECC_CURVE                    = 0xF0000441,
    TEE_ATTR_SM2_ID_INITIATOR             = 0xD0000446,
    TEE_ATTR_SM2_ID_RESPONDER             = 0xD0000546,
    TEE_ATTR_SM2_KEP_USER                 = 0xF0000646,
    TEE_ATTR_SM2_KEP_CONFIRMATION_IN      = 0xD0000746,
    TEE_ATTR_SM2_KEP_CONFIRMATION_OUT     = 0xD0000846,
    TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_X = 0xD0000946, /* Missing in 1.2.1 */
    TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_Y = 0xD0000A46, /* Missing in 1.2.1 */
    TEE_ATTR_FLAG_PUBLIC                  = 0x10000000,
    TEE_ATTR_FLAG_VALUE                   = 0x20000000,
    TEE_ATTR_BIT_PROTECTED                = 0x10000000,
    TEE_ATTR_BIT_VALUE                    = 0x20000000,
};

/* List of Supported ECC Curves */
enum TEE_ECC_TYPE {
    TEE_CRYPTO_ELEMENT_NONE = 0x00000000,
    TEE_ECC_CURVE_NIST_P192 = 0x00000001,
    TEE_ECC_CURVE_NIST_P224 = 0x00000002,
    TEE_ECC_CURVE_NIST_P256 = 0x00000003,
    TEE_ECC_CURVE_NIST_P384 = 0x00000004,
    TEE_ECC_CURVE_NIST_P521 = 0x00000005,
    TEE_ECC_CURVE_SM2       = 0x00000400,
};

/* Panicked Functions Identification */
enum TEE_PANIC_ID {
/* TA Interface */
    TEE_PANIC_ID_TA_CLOSESESSIONENTRYPOINT              = 0x00000101,
    TEE_PANIC_ID_TA_CREATEENTRYPOINT                    = 0x00000102,
    TEE_PANIC_ID_TA_DESTROYENTRYPOINT                   = 0x00000103,
    TEE_PANIC_ID_TA_INVOKECOMMANDENTRYPOINT             = 0x00000104,
    TEE_PANIC_ID_TA_OPENSESSIONENTRYPOINT               = 0x00000105,
/* Property Access */
    TEE_PANIC_ID_TEE_ALLOCATEPROPERTYENUMERATOR         = 0x00000201,
    TEE_PANIC_ID_TEE_FREEPROPERTYENUMERATOR             = 0x00000202,
    TEE_PANIC_ID_TEE_GETNEXTPROPERTY                    = 0x00000203,
    TEE_PANIC_ID_TEE_GETPROPERTYASBINARYBLOCK           = 0x00000204,
    TEE_PANIC_ID_TEE_GETPROPERTYASBOOL                  = 0x00000205,
    TEE_PANIC_ID_TEE_GETPROPERTYASIDENTITY              = 0x00000206,
    TEE_PANIC_ID_TEE_GETPROPERTYASSTRING                = 0x00000207,
    TEE_PANIC_ID_TEE_GETPROPERTYASU32                   = 0x00000208,
    TEE_PANIC_ID_TEE_GETPROPERTYASUUID                  = 0x00000209,
    TEE_PANIC_ID_TEE_GETPROPERTYNAME                    = 0x0000020A,
    TEE_PANIC_ID_TEE_RESETPROPERTYENUMERATOR            = 0x0000020B,
    TEE_PANIC_ID_TEE_STARTPROPERTYENUMERATOR            = 0x0000020C,
/* Panic Function */
    TEE_PANIC_ID_TEE_PANIC                              = 0x00000301,
/* Internal Client API */
    TEE_PANIC_ID_TEE_CLOSETASESSION                     = 0x00000401,
    TEE_PANIC_ID_TEE_INVOKETACOMMAND                    = 0x00000402,
    TEE_PANIC_ID_TEE_OPENTASESSION                      = 0x00000403,
/* Cancellation */
    TEE_PANIC_ID_TEE_GETCANCELLATIONFLAG                = 0x00000501,
    TEE_PANIC_ID_TEE_MASKCANCELLATION                   = 0x00000502,
    TEE_PANIC_ID_TEE_UNMASKCANCELLATION                 = 0x00000503,
/* Memory Management */
    TEE_PANIC_ID_TEE_CHECKMEMORYACCESSRIGHTS            = 0x00000601,
    TEE_PANIC_ID_TEE_FREE                               = 0x00000602,
    TEE_PANIC_ID_TEE_GETINSTANCEDATA                    = 0x00000603,
    TEE_PANIC_ID_TEE_MALLOC                             = 0x00000604,
    TEE_PANIC_ID_TEE_MEMCOMPARE                         = 0x00000605,
    TEE_PANIC_ID_TEE_MEMFILL                            = 0x00000606,
    TEE_PANIC_ID_TEE_MEMMOVE                            = 0x00000607,
    TEE_PANIC_ID_TEE_REALLOC                            = 0x00000608,
    TEE_PANIC_ID_TEE_SETINSTANCEDATA                    = 0x00000609,
/* Generic Object */
    TEE_PANIC_ID_TEE_CLOSEOBJECT                        = 0x00000701,
    TEE_PANIC_ID_TEE_GETOBJECTBUFFERATTRIBUTE           = 0x00000702,
/* deprecated */
    TEE_PANIC_ID_TEE_GETOBJECTINFO                      = 0x00000703,
    TEE_PANIC_ID_TEE_GETOBJECTVALUEATTRIBUTE            = 0x00000704,
/* deprecated */
    TEE_PANIC_ID_TEE_RESTRICTOBJECTUSAGE                = 0x00000705,
    TEE_PANIC_ID_TEE_GETOBJECTINFO1                     = 0x00000706,
    TEE_PANIC_ID_TEE_RESTRICTOBJECTUSAGE1               = 0x00000707,
/* Transient Object */
    TEE_PANIC_ID_TEE_ALLOCATETRANSIENTOBJECT            = 0x00000801,
/* deprecated */
    TEE_PANIC_ID_TEE_COPYOBJECTATTRIBUTES               = 0x00000802,
    TEE_PANIC_ID_TEE_FREETRANSIENTOBJECT                = 0x00000803,
    TEE_PANIC_ID_TEE_GENERATEKEY                        = 0x00000804,
    TEE_PANIC_ID_TEE_INITREFATTRIBUTE                   = 0x00000805,
    TEE_PANIC_ID_TEE_INITVALUEATTRIBUTE                 = 0x00000806,
    TEE_PANIC_ID_TEE_POPULATETRANSIENTOBJECT            = 0x00000807,
    TEE_PANIC_ID_TEE_RESETTRANSIENTOBJECT               = 0x00000808,
    TEE_PANIC_ID_TEE_COPYOBJECTATTRIBUTES1              = 0x00000809,
/* Persistent Object */
/* deprecated */
    TEE_PANIC_ID_TEE_CLOSEANDDELETEPERSISTENTOBJECT     = 0x00000901,
    TEE_PANIC_ID_TEE_CREATEPERSISTENTOBJECT             = 0x00000902,
    TEE_PANIC_ID_TEE_OPENPERSISTENTOBJECT               = 0x00000903,
    TEE_PANIC_ID_TEE_RENAMEPERSISTENTOBJECT             = 0x00000904,
    TEE_PANIC_ID_TEE_CLOSEANDDELETEPERSISTENTOBJECT1    = 0x00000905,
/* Persistent Object Enumeration */
    TEE_PANIC_ID_TEE_ALLOCATEPERSISTENTOBJECTENUMERATOR = 0x00000A01,
    TEE_PANIC_ID_TEE_FREEPERSISTENTOBJECTENUMERATOR     = 0x00000A02,
    TEE_PANIC_ID_TEE_GETNEXTPERSISTENTOBJECT            = 0x00000A03,
    TEE_PANIC_ID_TEE_RESETPERSISTENTOBJECTENUMERATOR    = 0x00000A04,
    TEE_PANIC_ID_TEE_STARTPERSISTENTOBJECTENUMERATOR    = 0x00000A05,
/* Data Stream Access */
    TEE_PANIC_ID_TEE_READOBJECTDATA                     = 0x00000B01,
    TEE_PANIC_ID_TEE_SEEKOBJECTDATA                     = 0x00000B02,
    TEE_PANIC_ID_TEE_TRUNCATEOBJECTDATA                 = 0x00000B03,
    TEE_PANIC_ID_TEE_WRITEOBJECTDATA                    = 0x00000B04,
/* Generic Operation */
    TEE_PANIC_ID_TEE_ALLOCATEOPERATION                  = 0x00000C01,
    TEE_PANIC_ID_TEE_COPYOPERATION                      = 0x00000C02,
    TEE_PANIC_ID_TEE_FREEOPERATION                      = 0x00000C03,
    TEE_PANIC_ID_TEE_GETOPERATIONINFO                   = 0x00000C04,
    TEE_PANIC_ID_TEE_RESETOPERATION                     = 0x00000C05,
    TEE_PANIC_ID_TEE_SETOPERATIONKEY                    = 0x00000C06,
    TEE_PANIC_ID_TEE_SETOPERATIONKEY2                   = 0x00000C07,
    TEE_PANIC_ID_TEE_GETOPERATIONINFOMULTIPLE           = 0x00000C08,
/* Message Digest */
    TEE_PANIC_ID_TEE_DIGESTDOFINAL                      = 0x00000D01,
    TEE_PANIC_ID_TEE_DIGESTUPDATE                       = 0x00000D02,
/* Symmetric Cipher */
    TEE_PANIC_ID_TEE_CIPHERDOFINAL                      = 0x00000E01,
    TEE_PANIC_ID_TEE_CIPHERINIT                         = 0x00000E02,
    TEE_PANIC_ID_TEE_CIPHERUPDATE                       = 0x00000E03,
/* MAC */
    TEE_PANIC_ID_TEE_MACCOMPAREFINAL                    = 0x00000F01,
    TEE_PANIC_ID_TEE_MACCOMPUTEFINAL                    = 0x00000F02,
    TEE_PANIC_ID_TEE_MACINIT                            = 0x00000F03,
    TEE_PANIC_ID_TEE_MACUPDATE                          = 0x00000F04,
/* Authenticated Encryption */
    TEE_PANIC_ID_TEE_AEDECRYPTFINAL                     = 0x00001001,
    TEE_PANIC_ID_TEE_AEENCRYPTFINAL                     = 0x00001002,
    TEE_PANIC_ID_TEE_AEINIT                             = 0x00001003,
    TEE_PANIC_ID_TEE_AEUPDATE                           = 0x00001004,
    TEE_PANIC_ID_TEE_AEUPDATEAAD                        = 0x00001005,
/* Asymmetric */
    TEE_PANIC_ID_TEE_ASYMMETRICDECRYPT                  = 0x00001101,
    TEE_PANIC_ID_TEE_ASYMMETRICENCRYPT                  = 0x00001102,
    TEE_PANIC_ID_TEE_ASYMMETRICSIGNDIGEST               = 0x00001103,
    TEE_PANIC_ID_TEE_ASYMMETRICVERIFYDIGEST             = 0x00001104,
/* Key Derivation */
    TEE_PANIC_ID_TEE_DERIVEKEY                          = 0x00001201,
/* Random Data Generation */
    TEE_PANIC_ID_TEE_GENERATERANDOM                     = 0x00001301,
/* Time */
    TEE_PANIC_ID_TEE_GETREETIME                         = 0x00001401,
    TEE_PANIC_ID_TEE_GETSYSTEMTIME                      = 0x00001402,
    TEE_PANIC_ID_TEE_GETTAPERSISTENTTIME                = 0x00001403,
    TEE_PANIC_ID_TEE_SETTAPERSISTENTTIME                = 0x00001404,
    TEE_PANIC_ID_TEE_WAIT                               = 0x00001405,
/* Memory Allocation and Size of Objects */
    TEE_PANIC_ID_TEE_BIGINTFMMCONTEXTSIZEINU32          = 0x00001501,
    TEE_PANIC_ID_TEE_BIGINTFMMSIZEINU32                 = 0x00001502,
/* Initialization */
    TEE_PANIC_ID_TEE_BIGINTINIT                         = 0x00001601,
    TEE_PANIC_ID_TEE_BIGINTINITFMM                      = 0x00001602,
    TEE_PANIC_ID_TEE_BIGINTINITFMMCONTEXT               = 0x00001603,
/* Converter */
    TEE_PANIC_ID_TEE_BIGINTCONVERTFROMOCTETSTRING       = 0x00001701,
    TEE_PANIC_ID_TEE_BIGINTCONVERTFROMS32               = 0x00001702,
    TEE_PANIC_ID_TEE_BIGINTCONVERTTOOCTETSTRING         = 0x00001703,
    TEE_PANIC_ID_TEE_BIGINTCONVERTTOS32                 = 0x00001704,
/* Logical Operation */
    TEE_PANIC_ID_TEE_BIGINTCMP                          = 0x00001801,
    TEE_PANIC_ID_TEE_BIGINTCMPS32                       = 0x00001802,
    TEE_PANIC_ID_TEE_BIGINTGETBIT                       = 0x00001803,
    TEE_PANIC_ID_TEE_BIGINTGETBITCOUNT                  = 0x00001804,
    TEE_PANIC_ID_TEE_BIGINTSHIFTRIGHT                   = 0x00001805,
/* Basic Arithmetic */
    TEE_PANIC_ID_TEE_BIGINTADD                          = 0x00001901,
    TEE_PANIC_ID_TEE_BIGINTDIV                          = 0x00001902,
    TEE_PANIC_ID_TEE_BIGINTMUL                          = 0x00001903,
    TEE_PANIC_ID_TEE_BIGINTNEG                          = 0x00001904,
    TEE_PANIC_ID_TEE_BIGINTSQUARE                       = 0x00001905,
    TEE_PANIC_ID_TEE_BIGINTSUB                          = 0x00001906,
/* Modular Arithmetic */
    TEE_PANIC_ID_TEE_BIGINTADDMOD                       = 0x00001A01,
    TEE_PANIC_ID_TEE_BIGINTINVMOD                       = 0x00001A02,
    TEE_PANIC_ID_TEE_BIGINTMOD                          = 0x00001A03,
    TEE_PANIC_ID_TEE_BIGINTMULMOD                       = 0x00001A04,
    TEE_PANIC_ID_TEE_BIGINTSQUAREMOD                    = 0x00001A05,
    TEE_PANIC_ID_TEE_BIGINTSUBMOD                       = 0x00001A06,
/* Other Arithmetic */
    TEE_PANIC_ID_TEE_BIGINTCOMPUTEEXTENDEDGCD           = 0x00001B01,
    TEE_PANIC_ID_TEE_BIGINTISPROBABLEPRIME              = 0x00001B02,
    TEE_PANIC_ID_TEE_BIGINTRELATIVEPRIME                = 0x00001B03,
/* Fast Modular Multiplication */
    TEE_PANIC_ID_TEE_BIGINTCOMPUTEFMM                   = 0x00001C01,
    TEE_PANIC_ID_TEE_BIGINTCONVERTFROMFMM               = 0x00001C02,
    TEE_PANIC_ID_TEE_BIGINTCONVERTTOFMM                 = 0x00001C03,
};

enum TEE_NUM_PARAMS {
    TEE_NUM_PARAMS = 4,
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/tee_api_types.h

typedef uint32_t TEE_Result;

struct TEE_UUID {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[8];
};

struct TEE_Identity {
    uint32_t login;
    struct TEE_UUID uuid;
};

union TEE_Param {
    struct {
        void *buffer;
        uint32_t size;
    } memref;
    struct {
        uint32_t a;
        uint32_t b;
    } value;
};

typedef uint32_t TEE_ObjectType;

struct TEE_ObjectInfo {
    uint32_t objectType;
    union {
        uint32_t keySize;       /* used in 1.1 spec */
        uint32_t objectSize;    /* used in 1.1.1 spec */
    } size1;
    union {
        uint32_t maxKeySize;    /* used in 1.1 spec */
        uint32_t maxObjectSize; /* used in 1.1.1 spec */
    } size2;
    uint32_t objectUsage;
    uint32_t dataSize;
    uint32_t dataPosition;
    uint32_t handleFlags;
};

enum TEE_Whence {
    TEE_DATA_SEEK_SET = 0,
    TEE_DATA_SEEK_CUR = 1,
    TEE_DATA_SEEK_END = 2,
};

struct TEE_Attribute {
    uint32_t attributeID;
    union {
        struct {
            void *buffer;
            uint32_t length;
        } ref;
        struct {
            uint32_t a, b;
        } value;
    } content;
};

enum TEE_OperationMode {
    TEE_MODE_ENCRYPT = 0,
    TEE_MODE_DECRYPT = 1,
    TEE_MODE_SIGN    = 2,
    TEE_MODE_VERIFY  = 3,
    TEE_MODE_MAC     = 4,
    TEE_MODE_DIGEST  = 5,
    TEE_MODE_DERIVE  = 6,
};

struct TEE_OperationInfo {
    uint32_t algorithm;
    uint32_t operationClass;
    uint32_t mode;
    uint32_t digestLength;
    uint32_t maxKeySize;
    uint32_t keySize;
    uint32_t requiredKeyUsage;
    uint32_t handleState;
};

struct TEE_OperationInfoKey {
    uint32_t keySize;
    uint32_t requiredKeyUsage;
};

struct TEE_OperationInfoMultiple {
    uint32_t algorithm;
    uint32_t operationClass;
    uint32_t mode;
    uint32_t digestLength;
    uint32_t maxKeySize;
    uint32_t handleState;
    uint32_t operationState;
    uint32_t numberOfKeys;
    struct TEE_OperationInfoKey keyInformation[];
};

struct TEE_Time {
    uint32_t seconds;
    uint32_t millis;
};

typedef uint32_t TEE_BigInt;
typedef uint32_t TEE_BigIntFMM;
typedef uint32_t TEE_BigIntFMMContext;

struct TEE_SEReaderProperties {
    bool sePresent;
    bool teeOnly;
    bool selectResponseEnable;
};

struct TEE_SEAID {
    uint8_t *buffer;
    size_t bufferLen;
};

typedef uint32_t TEE_ErrorOrigin;
typedef void *TEE_Session;

enum TEE_MEM_TYPE {
    TEE_MEM_INPUT  = 0x00000001,
    TEE_MEM_OUTPUT = 0x00000002,
};

enum TEE_MEMREF_FLAG {
    TEE_MEMREF_0_USED = 0x00000001,
    TEE_MEMREF_1_USED = 0x00000002,
    TEE_MEMREF_2_USED = 0x00000004,
    TEE_MEMREF_3_USED = 0x00000008,
};

enum TEE_SE_READER_NAME_MAX {
    TEE_SE_READER_NAME_MAX = 20,
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/__tee_ipsocket.h

enum TEE_ipSocket_ipVersion {
    TEE_IP_VERSION_DC = 0, /* don’t care */
    TEE_IP_VERSION_4 = 1,
    TEE_IP_VERSION_6 = 2
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/__tee_isocket_defines.h

enum TEE_ISOCKET_VERSION {
    TEE_ISOCKET_VERSION = 0x01000000,
};

enum TEE_ISOCKET_ERROR {
    TEE_ISOCKET_ERROR_PROTOCOL         = 0xF1007001,
    TEE_ISOCKET_ERROR_REMOTE_CLOSED    = 0xF1007002,
    TEE_ISOCKET_ERROR_TIMEOUT          = 0xF1007003,
    TEE_ISOCKET_ERROR_OUT_OF_RESOURCES = 0xF1007004,
    TEE_ISOCKET_ERROR_LARGE_BUFFER     = 0xF1007005,
    TEE_ISOCKET_WARNING_PROTOCOL       = 0xF1007006,
    TEE_ISOCKET_ERROR_HOSTNAME         = 0xF1007007,
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/tee_isocket.h

typedef void *TEE_iSocketHandle;

struct TEE_iSocket {
    uint32_t TEE_iSocketVersion;
    uint8_t protocolID;
    TEE_Result (*open)(TEE_iSocketHandle *ctx, void *setup, uint32_t *protocolError);
    TEE_Result (*close)(TEE_iSocketHandle ctx);
    TEE_Result (*send)(TEE_iSocketHandle ctx, const void *buf, uint32_t *length, uint32_t timeout);
    TEE_Result (*recv)(TEE_iSocketHandle ctx, void *buf, uint32_t *length, uint32_t timeout);
    uint32_t (*error)(TEE_iSocketHandle ctx);
    TEE_Result (*ioctl)(TEE_iSocketHandle ctx, uint32_t commandCode, void *buf, uint32_t *length);
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/tee_syscall_numbers.h

enum TEE_SYSCALL {
    TEE_SCN_RETURN                                 = 0,
    TEE_SCN_LOG                                    = 1,
    TEE_SCN_PANIC                                  = 2,
    TEE_SCN_GET_PROPERTY                           = 3,
    TEE_SCN_GET_PROPERTY_NAME_TO_INDEX             = 4,
    TEE_SCN_OPEN_TA_SESSION                        = 5,
    TEE_SCN_CLOSE_TA_SESSION                       = 6,
    TEE_SCN_INVOKE_TA_COMMAND                      = 7,
    TEE_SCN_CHECK_ACCESS_RIGHTS                    = 8,
    TEE_SCN_GET_CANCELLATION_FLAG                  = 9,
    TEE_SCN_UNMASK_CANCELLATION                    = 10,
    TEE_SCN_MASK_CANCELLATION                      = 11,
    TEE_SCN_WAIT                                   = 12,
    TEE_SCN_GET_TIME                               = 13,
    TEE_SCN_SET_TA_TIME                            = 14,
    TEE_SCN_CRYP_STATE_ALLOC                       = 15,
    TEE_SCN_CRYP_STATE_COPY                        = 16,
    TEE_SCN_CRYP_STATE_FREE                        = 17,
    TEE_SCN_HASH_INIT                              = 18,
    TEE_SCN_HASH_UPDATE                            = 19,
    TEE_SCN_HASH_FINAL                             = 20,
    TEE_SCN_CIPHER_INIT                            = 21,
    TEE_SCN_CIPHER_UPDATE                          = 22,
    TEE_SCN_CIPHER_FINAL                           = 23,
    TEE_SCN_CRYP_OBJ_GET_INFO                      = 24,
    TEE_SCN_CRYP_OBJ_RESTRICT_USAGE                = 25,
    TEE_SCN_CRYP_OBJ_GET_ATTR                      = 26,
    TEE_SCN_CRYP_OBJ_ALLOC                         = 27,
    TEE_SCN_CRYP_OBJ_CLOSE                         = 28,
    TEE_SCN_CRYP_OBJ_RESET                         = 29,
    TEE_SCN_CRYP_OBJ_POPULATE                      = 30,
    TEE_SCN_CRYP_OBJ_COPY                          = 31,
    TEE_SCN_CRYP_DERIVE_KEY                        = 32,
    TEE_SCN_CRYP_RANDOM_NUMBER_GENERATE            = 33,
    TEE_SCN_AUTHENC_INIT                           = 34,
    TEE_SCN_AUTHENC_UPDATE_AAD                     = 35,
    TEE_SCN_AUTHENC_UPDATE_PAYLOAD                 = 36,
    TEE_SCN_AUTHENC_ENC_FINAL                      = 37,
    TEE_SCN_AUTHENC_DEC_FINAL                      = 38,
    TEE_SCN_ASYMM_OPERATE                          = 39,
    TEE_SCN_ASYMM_VERIFY                           = 40,
    TEE_SCN_STORAGE_OBJ_OPEN                       = 41,
    TEE_SCN_STORAGE_OBJ_CREATE                     = 42,
    TEE_SCN_STORAGE_OBJ_DEL                        = 43,
    TEE_SCN_STORAGE_OBJ_RENAME                     = 44,
    TEE_SCN_STORAGE_ENUM_ALLOC                     = 45,
    TEE_SCN_STORAGE_ENUM_FREE                      = 46,
    TEE_SCN_STORAGE_ENUM_RESET                     = 47,
    TEE_SCN_STORAGE_ENUM_START                     = 48,
    TEE_SCN_STORAGE_ENUM_NEXT                      = 49,
    TEE_SCN_STORAGE_OBJ_READ                       = 50,
    TEE_SCN_STORAGE_OBJ_WRITE                      = 51,
    TEE_SCN_STORAGE_OBJ_TRUNC                      = 52,
    TEE_SCN_STORAGE_OBJ_SEEK                       = 53,
    TEE_SCN_CRYP_OBJ_GENERATE_KEY                  = 54,
    /* Deprecated Secure Element API syscalls return TEE_ERROR_NOT_SUPPORTED */
    TEE_SCN_SE_SERVICE_OPEN__DEPRECATED            = 55,
    TEE_SCN_SE_SERVICE_CLOSE__DEPRECATED           = 56,
    TEE_SCN_SE_SERVICE_GET_READERS__DEPRECATED     = 57,
    TEE_SCN_SE_READER_GET_PROP__DEPRECATED         = 58,
    TEE_SCN_SE_READER_GET_NAME__DEPRECATED         = 59,
    TEE_SCN_SE_READER_OPEN_SESSION__DEPRECATED     = 60,
    TEE_SCN_SE_READER_CLOSE_SESSIONS__DEPRECATED   = 61,
    TEE_SCN_SE_SESSION_IS_CLOSED__DEPRECATED       = 62,
    TEE_SCN_SE_SESSION_GET_ATR__DEPRECATED         = 63,
    TEE_SCN_SE_SESSION_OPEN_CHANNEL__DEPRECATED    = 64,
    TEE_SCN_SE_SESSION_CLOSE__DEPRECATED           = 65,
    TEE_SCN_SE_CHANNEL_SELECT_NEXT__DEPRECATED     = 66,
    TEE_SCN_SE_CHANNEL_GET_SELECT_RESP__DEPRECATED = 67,
    TEE_SCN_SE_CHANNEL_TRANSMIT__DEPRECATED        = 68,
    TEE_SCN_SE_CHANNEL_CLOSE__DEPRECATED           = 69,
    TEE_SCN_CACHE_OPERATION                        = 70,
    TEE_SCN_MAX                                    = TEE_SCN_CACHE_OPERATION
};

enum TEE_SVC_MAX_ARGS {
    TEE_SVC_MAX_ARGS = 8,
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/__tee_tcpsocket_defines_extensions.h

enum TEE_TCP_BUF_TYPE {
    TEE_TCP_SET_RECVBUF = 0x65f00000,
    TEE_TCP_SET_SENDBUF = 0x65f00001,
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/__tee_tcpsocket_defines.h

/* Protocol identifier */
enum TEE_ISOCKET_PROTOCOLID_TCP {
    TEE_ISOCKET_PROTOCOLID_TCP = 0x65,
};

/* Instance specific errors */
enum TEE_ISOCKET_TCP_WARNING_UNKNOWN_OUT_OF_BAND {
    TEE_ISOCKET_TCP_WARNING_UNKNOWN_OUT_OF_BAND = 0xF1010002,
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/tee_tcpsocket.h

struct TEE_tcpSocket_Setup {
    TEE_ipSocket_ipVersion ipVersion;
    char *server_addr;
    uint16_t server_port;
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/__tee_udpsocket_defines.h

/* Protocol identifier */
enum TEE_ISOCKET_PROTOCOLID_UDP {
    TEE_ISOCKET_PROTOCOLID_UDP = 0x66,
};

/* Instance specific errors */
enum TEE_ISOCKET_UDP_WARNING_UNKNOWN_OUT_OF_BAND {
    TEE_ISOCKET_UDP_WARNING_UNKNOWN_OUT_OF_BAND = 0xF1020002,
};

/* Instance specific ioctl functions */
enum TEE_UDP_CHANGE_ADDR_PORT {
    TEE_UDP_CHANGEADDR = 0x66000001,
    TEE_UDP_CHANGEPORT = 0x66000002,
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/tee_udpsocket.h

struct TEE_udpSocket_Setup {
        TEE_ipSocket_ipVersion ipVersion;
        char *server_addr;
        uint16_t server_port;
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/user_ta_header.h

enum TA_FLAG {
    TA_FLAG_USER_MODE           = 0,        /* Deprecated, was (1 << 0) */
    TA_FLAG_EXEC_DDR            = 0,        /* Deprecated, was (1 << 1) */
    TA_FLAG_SINGLE_INSTANCE     = (1 << 2),
    TA_FLAG_MULTI_SESSION       = (1 << 3),
    TA_FLAG_INSTANCE_KEEP_ALIVE = (1 << 4), /* remains after last close */
    TA_FLAG_SECURE_DATA_PATH    = (1 << 5), /* accesses SDP memory */
    TA_FLAG_REMAP_SUPPORT       = 0,        /* Deprecated, was (1 << 6) */
    TA_FLAG_CACHE_MAINTENANCE   = (1 << 7), /* use cache flush syscall */
    TA_FLAG_CONCURRENT          = (1 << 8),
    TA_FLAG_DEVICE_ENUM         = (1 << 9),  /* without tee-supplicant */
    TA_FLAG_DEVICE_ENUM_SUPP    = (1 << 10), /* with tee-supplicant */
};

struct ta_head {
    struct TEE_UUID uuid;
    uint32_t stack_size;
    uint32_t flags;
    uint64_t depr_entry;
};

union compat_ptr {
    uint64_t ptr64;
    struct {
        uint32_t lo;
        uint32_t hi;
    } ptr32;
};

struct __ftrace_info {
    union compat_ptr buf_start;
    union compat_ptr buf_end;
    union compat_ptr ret_ptr;
};

struct ftrace_buf {
    uint64_t ret_func_ptr;  /* __ftrace_return pointer */
    uint64_t ret_stack[50]; /* Return stack */
    uint32_t ret_idx;       /* Return stack index */
    uint32_t lr_idx;        /* lr index used for stack unwinding */
    uint64_t begin_time[50]; /* Timestamp */
    uint64_t suspend_time;  /* Suspend timestamp */
    uint32_t curr_size;     /* Size of ftrace buffer */
    uint32_t max_size;      /* Max allowed size of ftrace buffer */
    uint32_t head_off;      /* Ftrace buffer header offset */
    uint32_t buf_off;       /* Ftrace buffer offset */
    bool syscall_trace_enabled; /* Some syscalls are never traced */
    bool syscall_trace_suspended; /* By foreign interrupt or RPC */
};

struct __elf_phdr_info {
    uint32_t reserved;
    uint16_t count;
    uint8_t reserved2;
    char zero;
    struct dl_phdr_info *dlpi; /* @count entries */
};

struct __elf_phdr_info32 {
    uint32_t reserved;
    uint16_t count;
    uint8_t reserved2;
    char zero;
    uint32_t dlpi;
};

enum user_ta_prop_type {
    USER_TA_PROP_TYPE_BOOL, /* bool */
    USER_TA_PROP_TYPE_U32,  /* uint32_t */
    USER_TA_PROP_TYPE_UUID, /* TEE_UUID */
    USER_TA_PROP_TYPE_IDENTITY,     /* TEE_Identity */
    USER_TA_PROP_TYPE_STRING,       /* zero terminated string of char */
    USER_TA_PROP_TYPE_BINARY_BLOCK, /* zero terminated base64 coded string */
};

struct user_ta_property {
    const char *name;
    enum user_ta_prop_type type;
    const void *value;
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/utee_defines.h

enum TEE_MAIN_ALGO {
    TEE_MAIN_ALGO_MD5         = 0x01,
    TEE_MAIN_ALGO_SHA1        = 0x02,
    TEE_MAIN_ALGO_SHA224      = 0x03,
    TEE_MAIN_ALGO_SHA256      = 0x04,
    TEE_MAIN_ALGO_SHA384      = 0x05,
    TEE_MAIN_ALGO_SHA512      = 0x06,
    TEE_MAIN_ALGO_SM3         = 0x07,
    TEE_MAIN_ALGO_AES         = 0x10,
    TEE_MAIN_ALGO_DES         = 0x11,
    TEE_MAIN_ALGO_DES2        = 0x12,
    TEE_MAIN_ALGO_DES3        = 0x13,
    TEE_MAIN_ALGO_SM4         = 0x14, /* Not in v1.2, extrapolated */
    TEE_MAIN_ALGO_RSA         = 0x30,
    TEE_MAIN_ALGO_DSA         = 0x31,
    TEE_MAIN_ALGO_DH          = 0x32,
    TEE_MAIN_ALGO_ECDSA       = 0x41,
    TEE_MAIN_ALGO_ECDH        = 0x42,
    TEE_MAIN_ALGO_SM2_DSA_SM3 = 0x45, /* Not in v1.2 spec */
    TEE_MAIN_ALGO_SM2_KEP     = 0x46, /* Not in v1.2 spec */
    TEE_MAIN_ALGO_SM2_PKE     = 0x47, /* Not in v1.2 spec */
    TEE_MAIN_ALGO_HKDF        = 0xC0, /* OP-TEE extension */
    TEE_MAIN_ALGO_CONCAT_KDF  = 0xC1, /* OP-TEE extension */
    TEE_MAIN_ALGO_PBKDF2      = 0xC2, /* OP-TEE extension */
};

enum TEE_CHAIN_MODE {
    TEE_CHAIN_MODE_ECB_NOPAD     = 0x0,
    TEE_CHAIN_MODE_CBC_NOPAD     = 0x1,
    TEE_CHAIN_MODE_CTR           = 0x2,
    TEE_CHAIN_MODE_CTS           = 0x3,
    TEE_CHAIN_MODE_XTS           = 0x4,
    TEE_CHAIN_MODE_CBC_MAC_PKCS5 = 0x5,
    TEE_CHAIN_MODE_CMAC          = 0x6,
    TEE_CHAIN_MODE_CCM           = 0x7,
    TEE_CHAIN_MODE_GCM           = 0x8,
    TEE_CHAIN_MODE_PKCS1_PSS_MGF1= 0x9,     /* ??? */
};

enum t_block_size {
    TEE_AES_BLOCK_SIZE  = 16,
    TEE_DES_BLOCK_SIZE  = 8,
    TEE_SM4_BLOCK_SIZE  = 16,
};

enum TEE_AES_MAX_KEY_SIZE {
    TEE_AES_MAX_KEY_SIZE = 32,
};

enum t_hash_size {
    TEE_MD5_HASH_SIZE = 16,
    TEE_SHA1_HASH_SIZE = 20,
    TEE_SHA224_HASH_SIZE = 28,
    TEE_SHA256_HASH_SIZE = 32,
    TEE_SM3_HASH_SIZE = 32,
    TEE_SHA384_HASH_SIZE = 48,
    TEE_SHA512_HASH_SIZE = 64,
    TEE_MD5SHA1_HASH_SIZE = (TEE_MD5_HASH_SIZE + TEE_SHA1_HASH_SIZE),
    TEE_MAX_HASH_SIZE = 64,
};

//---------------------------------------------------------------- optee_os/lib/libutee/include/utee_types.h

enum utee_time_category {
    UTEE_TIME_CAT_SYSTEM        = 0,
    UTEE_TIME_CAT_TA_PERSISTENT = 1,
    UTEE_TIME_CAT_REE           = 2,
};

enum utee_entry_func {
    UTEE_ENTRY_FUNC_OPEN_SESSION   = 0,
    UTEE_ENTRY_FUNC_CLOSE_SESSION  = 1,
    UTEE_ENTRY_FUNC_INVOKE_COMMAND = 2,
};

/*
 * Cache operation types.
 * Used when extensions TEE_CacheClean() / TEE_CacheFlush() /
 * TEE_CacheInvalidate() are used
 */
enum utee_cache_operation {
    TEE_CACHECLEAN      = 0,
    TEE_CACHEFLUSH      = 1,
    TEE_CACHEINVALIDATE = 2,
};

struct utee_params {
    uint64_t types;
    /* vals[n * 2]     corresponds to either value.a or memref.buffer
     * vals[n * 2 + ]  corresponds to either value.b or memref.size
     * when converting to/from struct tee_ta_param
     */
    uint64_t vals[4 * 2];
};

struct utee_attribute {
    uint64_t a;        /* also serves as a pointer for references */
    uint64_t b;        /* also serves as a length for references */
    uint32_t attribute_id;
};

//---------------------------------------------------------------- optee_os/lib/libutils/isoc/bget.c

typedef long bufsize;

struct qlinks {
    struct bfhead *flink;             /* Forward link */
    struct bfhead *blink;             /* Backward link */
};

struct bhead {
    bufsize prevfree;                 /* Relative link back to previous free buffer in memory or 0 if previous buffer is allocated.  */
    bufsize bsize;                    /* Buffer size: positive if free, negative if allocated. */
};

struct bdhead {
    bufsize tsize;                    /* Total size, including overhead */
    bufsize offs;                     /* Offset from allocated buffer */
    struct bhead bh;                  /* Common header */
};

struct bfhead {
    struct bhead bh;                  /* Common allocated/free header */
    struct qlinks ql;                 /* Links on free list */
};

struct bpoolset {
    struct bfhead freelist;
//#ifdef BufStats
    bufsize totalloc;                 /* Total space currently allocated */
    long numget;                      /* Number of bget() calls */
    long numrel;                      /* Number of brel() calls */
//#ifdef BECtl
//    long numpblk;                     /* Number of pool blocks */
//    long numpget;                     /* Number of block gets and rels */
//    long numprel;
//    long numdget;                     /* Number of direct gets and rels */
//    long numdrel;
//#endif /* BECtl */
//#endif /* BufStats */

//#ifdef BECtl
//    /* Automatic expansion block management functions */
//
//    int (*compfcn) _((bufsize sizereq, int sequence));
//    void *(*acqfcn) _((bufsize size));
//    void (*relfcn) _((void *buf));
//
//    bufsize exp_incr;                 /* Expansion block size */
//    bufsize pool_len;                 /* 0: no bpool calls have been made
//                                         -1: not all pool blocks are
//                                             the same size
//                                         >0: (common) block size for all
//                                             bpool calls made so far
//                                      */
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libutils/isoc/include/malloc.h

#define TEE_ALLOCATOR_DESC_LENGTH 32

struct malloc_stats {
    char desc[TEE_ALLOCATOR_DESC_LENGTH];
    uint32_t allocated;               /* Bytes currently allocated */
    uint32_t max_allocated;           /* Tracks max value of allocated */
    uint32_t size;                    /* Total size for this allocator */
    uint32_t num_alloc_fail;          /* Number of failed alloc requests */
    uint32_t biggest_alloc_fail;      /* Size of biggest failed alloc */
    uint32_t biggest_alloc_fail_used; /* Alloc bytes when above occurred */
};

//---------------------------------------------------------------- optee_os/lib/libutils/isoc/bget_malloc.c

struct malloc_pool {
    void *buf;
    size_t len;
};

struct malloc_ctx {
    struct bpoolset poolset;
    struct malloc_pool *pool;
    size_t pool_len;
//#ifdef BufStats
    struct malloc_stats mstats;
//#endif
//#ifdef __KERNEL__
//    unsigned int spinlock;
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libutils/ext/include/mempool.h

struct mempool_item {
    size_t size;
    size_t prev_item_offset;
    size_t next_item_offset;
};

//---------------------------------------------------------------- optee_os/lib/libutils/ext/mempool.c

struct mempool {
    size_t size;  /* size of the memory pool, in bytes */
    size_t data;
    struct malloc_ctx *mctx;
//#ifdef CFG_MEMPOOL_REPORT_LAST_OFFSET
    size_t max_allocated;
//#endif
//#if defined(__KERNEL__)
//    void (*release_mem)(void *ptr, size_t size);
//    struct recursive_mutex mu;
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libutils/ext/include/memtag.h

struct __memtag_ops {
    void *(*set_tags)(void *addr, size_t size, uint8_t tag);
    void *(*set_random_tags)(void *addr, size_t size);
    void (*clear_mem)(void *addr, size_t size);
    uint8_t (*read_tag)(const void *addr);
};

//---------------------------------------------------------------- optee_os/lib/libutils/ext/include/trace_levels.h

enum TRACE_LEVEL {
    TRACE_MIN   = 0,
    TRACE_ERROR = 1,
    TRACE_INFO  = 2,
    TRACE_DEBUG = 3,
    TRACE_FLOW  = 4,
    TRACE_MAX   = TRACE_FLOW,
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/include/aes_alt.h

struct mbedtls_aes_context {
    uint32_t key[60];
    unsigned int round_count;
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/*.h

enum MBEDTLS_ERR {
    /* aes.h */
    MBEDTLS_ERR_AES_INVALID_KEY_LENGTH                = -0x0020,  /**< Invalid key length. */
    MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH              = -0x0022,  /**< Invalid data input length. */
    MBEDTLS_ERR_AES_BAD_INPUT_DATA                    = -0x0021,  /**< Invalid input data. */
    MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE               = -0x0023,  /**< Feature not available. For example, an unsupported AES key size. */
    MBEDTLS_ERR_AES_HW_ACCEL_FAILED                   = -0x0025,  /**< AES hardware accelerator failed. */

    /* arc4.h */
    MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED                  = -0x0019,  /**< ARC4 hardware accelerator failed. */

    /* aria.h */
    MBEDTLS_ERR_ARIA_INVALID_KEY_LENGTH               = -0x005C,
    MBEDTLS_ERR_ARIA_BAD_INPUT_DATA                   = -0x005C, /**< Bad input data. */
    MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH             = -0x005E, /**< Invalid data input length. */
    MBEDTLS_ERR_ARIA_FEATURE_UNAVAILABLE              = -0x005A,  /**< Feature not available. For example, an unsupported ARIA key size. */
    MBEDTLS_ERR_ARIA_HW_ACCEL_FAILED                  = -0x0058,  /**< ARIA hardware accelerator failed. */

    /* asn1.h */
    MBEDTLS_ERR_ASN1_OUT_OF_DATA                      = -0x0060,  /**< Out of data when parsing an ASN1 data structure. */
    MBEDTLS_ERR_ASN1_UNEXPECTED_TAG                   = -0x0062,  /**< ASN1 tag was of an unexpected value. */
    MBEDTLS_ERR_ASN1_INVALID_LENGTH                   = -0x0064,  /**< Error when trying to determine the length or invalid length. */
    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH                  = -0x0066,  /**< Actual length differs from expected length. */
    MBEDTLS_ERR_ASN1_INVALID_DATA                     = -0x0068,  /**< Data is invalid. */
    MBEDTLS_ERR_ASN1_ALLOC_FAILED                     = -0x006A,  /**< Memory allocation failed */
    MBEDTLS_ERR_ASN1_BUF_TOO_SMALL                    = -0x006C,  /**< Buffer too small when writing ASN.1 data structure. */

    /* base64.h */
    MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL               = -0x002A,  /**< Output buffer too small. */
    MBEDTLS_ERR_BASE64_INVALID_CHARACTER              = -0x002C,  /**< Invalid character in input. */

    /* bignum.h */
    MBEDTLS_ERR_MPI_FILE_IO_ERROR                     = -0x0002,  /**< An error occurred while reading from or writing to a file. */
    MBEDTLS_ERR_MPI_BAD_INPUT_DATA                    = -0x0004,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_MPI_INVALID_CHARACTER                 = -0x0006,  /**< There is an invalid character in the digit string. */
    MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL                  = -0x0008,  /**< The buffer is too small to write to. */
    MBEDTLS_ERR_MPI_NEGATIVE_VALUE                    = -0x000A,  /**< The input arguments are negative or result in illegal output. */
    MBEDTLS_ERR_MPI_DIVISION_BY_ZERO                  = -0x000C,  /**< The input argument for division is zero, which is not allowed. */
    MBEDTLS_ERR_MPI_NOT_ACCEPTABLE                    = -0x000E,  /**< The input arguments are not acceptable. */
    MBEDTLS_ERR_MPI_ALLOC_FAILED                      = -0x0010,  /**< Memory allocation failed. */

    /* blowfish.h */
    MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH           = -0x0016,
    MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA               = -0x0016, /**< Bad input data. */
    MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH         = -0x0018, /**< Invalid data input length. */
    MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED              = -0x0017,  /**< Blowfish hardware accelerator failed. */

    /* camellia.h */
    MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH           = -0x0024,
    MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA               = -0x0024, /**< Bad input data. */
    MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH         = -0x0026, /**< Invalid data input length. */
    MBEDTLS_ERR_CAMELLIA_HW_ACCEL_FAILED              = -0x0027,  /**< Camellia hardware accelerator failed. */

    /* ccm.h */
    MBEDTLS_ERR_CCM_BAD_INPUT                         = -0x000D, /**< Bad input parameters to the function. */
    MBEDTLS_ERR_CCM_AUTH_FAILED                       = -0x000F, /**< Authenticated decryption failed. */
    MBEDTLS_ERR_CCM_HW_ACCEL_FAILED                   = -0x0011, /**< CCM hardware accelerator failed. */

    /* chacha20.h */
    MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA               = -0x0051, /**< Invalid input parameter(s). */
    MBEDTLS_ERR_CHACHA20_FEATURE_UNAVAILABLE          = -0x0053, /**< Feature not available. For example, s part of the API is not implemented. */
    MBEDTLS_ERR_CHACHA20_HW_ACCEL_FAILED              = -0x0055,  /**< Chacha20 hardware accelerator failed. */

    /* chachapoly.h */
    MBEDTLS_ERR_CHACHAPOLY_BAD_STATE                  = -0x0054, /**< The requested operation is not permitted in the current state. */
    MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED                = -0x0056, /**< Authenticated decryption failed: data was not authentic. */

    /* cipher.h */
    MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE            = -0x6080,  /**< The selected feature is not available. */
    MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA                 = -0x6100,  /**< Bad input parameters. */
    MBEDTLS_ERR_CIPHER_ALLOC_FAILED                   = -0x6180,  /**< Failed to allocate memory. */
    MBEDTLS_ERR_CIPHER_INVALID_PADDING                = -0x6200,  /**< Input data contains invalid padding and is rejected. */
    MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED            = -0x6280,  /**< Decryption of block requires a full block. */
    MBEDTLS_ERR_CIPHER_AUTH_FAILED                    = -0x6300,  /**< Authentication failed (for AEAD modes). */
    MBEDTLS_ERR_CIPHER_INVALID_CONTEXT                = -0x6380,  /**< The context is invalid. For example, because it was freed. */
    MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED                = -0x6400,  /**< Cipher hardware accelerator failed. */

    /* cmac.h */
    MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED                  = -0x007A,  /**< CMAC hardware accelerator failed. */

    /* ctr_drbg.h */
    MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED        = -0x0034,  /**< The entropy source failed. */
    MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG              = -0x0036,  /**< The requested random buffer length is too big. */
    MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG                = -0x0038,  /**< The input (entropy + additional data) is too large. */
    MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR                = -0x003A,  /**< Read or write error in file. */

    /* des.h */
    MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH              = -0x0032,  /**< The data input has an invalid length. */
    MBEDTLS_ERR_DES_HW_ACCEL_FAILED                   = -0x0033,  /**< DES hardware accelerator failed. */

    /* dhm.h */
    MBEDTLS_ERR_DHM_BAD_INPUT_DATA                    = -0x3080,  /**< Bad input parameters. */
    MBEDTLS_ERR_DHM_READ_PARAMS_FAILED                = -0x3100,  /**< Reading of the DHM parameters failed. */
    MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED                = -0x3180,  /**< Making of the DHM parameters failed. */
    MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED                = -0x3200,  /**< Reading of the public values failed. */
    MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED                = -0x3280,  /**< Making of the public value failed. */
    MBEDTLS_ERR_DHM_CALC_SECRET_FAILED                = -0x3300,  /**< Calculation of the DHM secret failed. */
    MBEDTLS_ERR_DHM_INVALID_FORMAT                    = -0x3380,  /**< The ASN.1 data is not formatted correctly. */
    MBEDTLS_ERR_DHM_ALLOC_FAILED                      = -0x3400,  /**< Allocation of memory failed. */
    MBEDTLS_ERR_DHM_FILE_IO_ERROR                     = -0x3480,  /**< Read or write of file failed. */
    MBEDTLS_ERR_DHM_HW_ACCEL_FAILED                   = -0x3500,  /**< DHM hardware accelerator failed. */
    MBEDTLS_ERR_DHM_SET_GROUP_FAILED                  = -0x3580,  /**< Setting the modulus and generator failed. */

    /* ecp.h */
    MBEDTLS_ERR_ECP_BAD_INPUT_DATA                    = -0x4F80,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL                  = -0x4F00,  /**< The buffer is too small to write to. */
    MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE               = -0x4E80,  /**< The requested feature is not available, for example, the requested curve is not supported. */
    MBEDTLS_ERR_ECP_VERIFY_FAILED                     = -0x4E00,  /**< The signature is not valid. */
    MBEDTLS_ERR_ECP_ALLOC_FAILED                      = -0x4D80,  /**< Memory allocation failed. */
    MBEDTLS_ERR_ECP_RANDOM_FAILED                     = -0x4D00,  /**< Generation of random value, such as ephemeral key, failed. */
    MBEDTLS_ERR_ECP_INVALID_KEY                       = -0x4C80,  /**< Invalid private or public key. */
    MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH                  = -0x4C00,  /**< The buffer contains a valid signature followed by more data. */
    MBEDTLS_ERR_ECP_HW_ACCEL_FAILED                   = -0x4B80,  /**< The ECP hardware accelerator failed. */
    MBEDTLS_ERR_ECP_IN_PROGRESS                       = -0x4B00,  /**< Operation in progress, call again with the same parameters to continue. */

    /* entropy.h */
    MBEDTLS_ERR_ENTROPY_SOURCE_FAILED                 = -0x003C,  /**< Critical entropy source failure. */
    MBEDTLS_ERR_ENTROPY_MAX_SOURCES                   = -0x003E,  /**< No more sources can be added. */
    MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED            = -0x0040,  /**< No sources have been added to poll. */
    MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE              = -0x003D,  /**< No strong sources have been added to poll. */
    MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR                 = -0x003F,  /**< Read/write error in file. */

    /* error.h */
    MBEDTLS_ERR_ERROR_GENERIC_ERROR                   = -0x0001,  /**< Generic error */
    MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED             = -0x006E,  /**< This is a bug in the library */

    /* gcm.h */
    MBEDTLS_ERR_GCM_AUTH_FAILED                       = -0x0012,  /**< Authenticated decryption failed. */
    MBEDTLS_ERR_GCM_HW_ACCEL_FAILED                   = -0x0013,  /**< GCM hardware accelerator failed. */
    MBEDTLS_ERR_GCM_BAD_INPUT                         = -0x0014,  /**< Bad input parameters to function. */

    /* hkdf.h */
    MBEDTLS_ERR_HKDF_BAD_INPUT_DATA                   = -0x5F80,  /**< Bad input parameters to function. */

    /* hmac_drbg.h */
    MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG             = -0x0003,  /**< Too many random requested in single call. */
    MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG               = -0x0005,  /**< Input too large (Entropy + additional). */
    MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR               = -0x0007,  /**< Read/write error in file. */
    MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED       = -0x0009,  /**< The entropy source failed. */

    /* md.h */
    MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE                = -0x5080,  /**< The selected feature is not available. */
    MBEDTLS_ERR_MD_BAD_INPUT_DATA                     = -0x5100,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_MD_ALLOC_FAILED                       = -0x5180,  /**< Failed to allocate memory. */
    MBEDTLS_ERR_MD_FILE_IO_ERROR                      = -0x5200,  /**< Opening or reading of file failed. */
    MBEDTLS_ERR_MD_HW_ACCEL_FAILED                    = -0x5280,  /**< MD hardware accelerator failed. */

    /* md2.h */
    MBEDTLS_ERR_MD2_HW_ACCEL_FAILED                   = -0x002B,  /**< MD2 hardware accelerator failed */

    /* md4.h */
    MBEDTLS_ERR_MD4_HW_ACCEL_FAILED                   = -0x002D,  /**< MD4 hardware accelerator failed */

    /* md5.h */
    MBEDTLS_ERR_MD5_HW_ACCEL_FAILED                   = -0x002F,  /**< MD5 hardware accelerator failed */

    /* net_sockets.h */
    MBEDTLS_ERR_NET_SOCKET_FAILED                     = -0x0042,  /**< Failed to open a socket. */
    MBEDTLS_ERR_NET_CONNECT_FAILED                    = -0x0044,  /**< The connection to the given server / port failed. */
    MBEDTLS_ERR_NET_BIND_FAILED                       = -0x0046,  /**< Binding of the socket failed. */
    MBEDTLS_ERR_NET_LISTEN_FAILED                     = -0x0048,  /**< Could not listen on the socket. */
    MBEDTLS_ERR_NET_ACCEPT_FAILED                     = -0x004A,  /**< Could not accept the incoming connection. */
    MBEDTLS_ERR_NET_RECV_FAILED                       = -0x004C,  /**< Reading information from the socket failed. */
    MBEDTLS_ERR_NET_SEND_FAILED                       = -0x004E,  /**< Sending information through the socket failed. */
    MBEDTLS_ERR_NET_CONN_RESET                        = -0x0050,  /**< Connection was reset by peer. */
    MBEDTLS_ERR_NET_UNKNOWN_HOST                      = -0x0052,  /**< Failed to get an IP address for the given hostname. */
    MBEDTLS_ERR_NET_BUFFER_TOO_SMALL                  = -0x0043,  /**< Buffer is too small to hold the data. */
    MBEDTLS_ERR_NET_INVALID_CONTEXT                   = -0x0045,  /**< The context is invalid, eg because it was free()ed. */
    MBEDTLS_ERR_NET_POLL_FAILED                       = -0x0047,  /**< Polling the net context failed. */
    MBEDTLS_ERR_NET_BAD_INPUT_DATA                    = -0x0049,  /**< Input invalid. */

    /* oid.h */
    MBEDTLS_ERR_OID_NOT_FOUND                         = -0x002E,  /**< OID is not found. */
    MBEDTLS_ERR_OID_BUF_TOO_SMALL                     = -0x000B,  /**< output buffer is too small */

    /* padlock.h */
    MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED               = -0x0030,  /**< Input data should be aligned. */

    /* pem.h */
    MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT          = -0x1080,  /**< No PEM header or footer found. */
    MBEDTLS_ERR_PEM_INVALID_DATA                      = -0x1100,  /**< PEM string is not as expected. */
    MBEDTLS_ERR_PEM_ALLOC_FAILED                      = -0x1180,  /**< Failed to allocate memory. */
    MBEDTLS_ERR_PEM_INVALID_ENC_IV                    = -0x1200,  /**< RSA IV is not in hex-format. */
    MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG                   = -0x1280,  /**< Unsupported key encryption algorithm. */
    MBEDTLS_ERR_PEM_PASSWORD_REQUIRED                 = -0x1300,  /**< Private key password can't be empty. */
    MBEDTLS_ERR_PEM_PASSWORD_MISMATCH                 = -0x1380,  /**< Given private key password does not allow for correct decryption. */
    MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE               = -0x1400,  /**< Unavailable feature, e.g. hashing/encryption combination. */
    MBEDTLS_ERR_PEM_BAD_INPUT_DATA                    = -0x1480,  /**< Bad input parameters to function. */

    /* pk.h */
    MBEDTLS_ERR_PK_ALLOC_FAILED                       = -0x3F80,  /**< Memory allocation failed. */
    MBEDTLS_ERR_PK_TYPE_MISMATCH                      = -0x3F00,  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
    MBEDTLS_ERR_PK_BAD_INPUT_DATA                     = -0x3E80,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_PK_FILE_IO_ERROR                      = -0x3E00,  /**< Read/write of file failed. */
    MBEDTLS_ERR_PK_KEY_INVALID_VERSION                = -0x3D80,  /**< Unsupported key version */
    MBEDTLS_ERR_PK_KEY_INVALID_FORMAT                 = -0x3D00,  /**< Invalid key tag or value. */
    MBEDTLS_ERR_PK_UNKNOWN_PK_ALG                     = -0x3C80,  /**< Key algorithm is unsupported (only RSA and EC are supported). */
    MBEDTLS_ERR_PK_PASSWORD_REQUIRED                  = -0x3C00,  /**< Private key password can't be empty. */
    MBEDTLS_ERR_PK_PASSWORD_MISMATCH                  = -0x3B80,  /**< Given private key password does not allow for correct decryption. */
    MBEDTLS_ERR_PK_INVALID_PUBKEY                     = -0x3B00,  /**< The pubkey tag or value is invalid (only RSA and EC are supported). */
    MBEDTLS_ERR_PK_INVALID_ALG                        = -0x3A80,  /**< The algorithm tag or value is invalid. */
    MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE                = -0x3A00,  /**< Elliptic curve is unsupported (only NIST curves are supported). */
    MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE                = -0x3980,  /**< Unavailable feature, e.g. RSA disabled for RSA key. */
    MBEDTLS_ERR_PK_SIG_LEN_MISMATCH                   = -0x3900,  /**< The buffer contains a valid signature followed by more data. */
    MBEDTLS_ERR_PK_HW_ACCEL_FAILED                    = -0x3880,  /**< PK hardware accelerator failed. */

    /* pkcs12.h */
    MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA                 = -0x1F80,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE            = -0x1F00,  /**< Feature not available, e.g. unsupported encryption scheme. */
    MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT             = -0x1E80,  /**< PBE ASN.1 data not as expected. */
    MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH              = -0x1E00,  /**< Given private key password does not allow for correct decryption. */

    /* pkcs5.h */
    MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA                  = -0x2f80,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_PKCS5_INVALID_FORMAT                  = -0x2f00,  /**< Unexpected ASN.1 data. */
    MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE             = -0x2e80,  /**< Requested encryption or digest alg not available. */
    MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH               = -0x2e00,  /**< Given private key password does not allow for correct decryption. */

    /* platform.h */
    MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED              = -0x0070, /**< Hardware accelerator failed */
    MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED          = -0x0072, /**< The requested feature is not supported by the platform */

    /* poly1305.h */
    MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA               = -0x0057, /**< Invalid input parameter(s). */
    MBEDTLS_ERR_POLY1305_FEATURE_UNAVAILABLE          = -0x0059, /**< Feature not available. For example, s part of the API is not implemented. */
    MBEDTLS_ERR_POLY1305_HW_ACCEL_FAILED              = -0x005B,  /**< Poly1305 hardware accelerator failed. */

    /* ripemd160.h */
    MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED             = -0x0031,  /**< RIPEMD160 hardware accelerator failed */

    /* rsa.h */
    MBEDTLS_ERR_RSA_BAD_INPUT_DATA                    = -0x4080,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_RSA_INVALID_PADDING                   = -0x4100,  /**< Input data contains invalid padding and is rejected. */
    MBEDTLS_ERR_RSA_KEY_GEN_FAILED                    = -0x4180,  /**< Something failed during generation of a key. */
    MBEDTLS_ERR_RSA_KEY_CHECK_FAILED                  = -0x4200,  /**< Key failed to pass the validity check of the library. */
    MBEDTLS_ERR_RSA_PUBLIC_FAILED                     = -0x4280,  /**< The public key operation failed. */
    MBEDTLS_ERR_RSA_PRIVATE_FAILED                    = -0x4300,  /**< The private key operation failed. */
    MBEDTLS_ERR_RSA_VERIFY_FAILED                     = -0x4380,  /**< The PKCS#1 verification failed. */
    MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE                  = -0x4400,  /**< The output buffer for decryption is not large enough. */
    MBEDTLS_ERR_RSA_RNG_FAILED                        = -0x4480,  /**< The random generator failed to generate non-zeros. */
    MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION             = -0x4500,  /**< The implementation does not offer the requested operation, for example, because of security violations or lack of functionality. */
    MBEDTLS_ERR_RSA_HW_ACCEL_FAILED                   = -0x4580,  /**< RSA hardware accelerator failed. */

    /* sha1.h */
    MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED                  = -0x0035,  /**< SHA-1 hardware accelerator failed */
    MBEDTLS_ERR_SHA1_BAD_INPUT_DATA                   = -0x0073,  /**< SHA-1 input data was malformed. */

    /* sha256.h */
    MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED                = -0x0037,  /**< SHA-256 hardware accelerator failed */
    MBEDTLS_ERR_SHA256_BAD_INPUT_DATA                 = -0x0074,  /**< SHA-256 input data was malformed. */

    /* sha512.h */
    MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED                = -0x0039,  /**< SHA-512 hardware accelerator failed */
    MBEDTLS_ERR_SHA512_BAD_INPUT_DATA                 = -0x0075,  /**< SHA-512 input data was malformed. */

    /* ssl.h */
    MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE               = -0x7080,  /**< The requested feature is not available. */
    MBEDTLS_ERR_SSL_BAD_INPUT_DATA                    = -0x7100,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_SSL_INVALID_MAC                       = -0x7180,  /**< Verification of the message MAC failed. */
    MBEDTLS_ERR_SSL_INVALID_RECORD                    = -0x7200,  /**< An invalid SSL record was received. */
    MBEDTLS_ERR_SSL_CONN_EOF                          = -0x7280,  /**< The connection indicated an EOF. */
    MBEDTLS_ERR_SSL_UNKNOWN_CIPHER                    = -0x7300,  /**< An unknown cipher was received. */
    MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN                  = -0x7380,  /**< The server has no ciphersuites in common with the client. */
    MBEDTLS_ERR_SSL_NO_RNG                            = -0x7400,  /**< No RNG was provided to the SSL module. */
    MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE             = -0x7480,  /**< No client certification received from the client, but required by the authentication mode. */
    MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE             = -0x7500,  /**< Our own certificate(s) is/are too large to send in an SSL message. */
    MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED              = -0x7580,  /**< The own certificate is not set, but needed by the server. */
    MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED              = -0x7600,  /**< The own private key or pre-shared key is not set, but needed. */
    MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED                 = -0x7680,  /**< No CA Chain is set, but required to operate. */
    MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE                = -0x7700,  /**< An unexpected message was received from our peer. */
    MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE               = -0x7780,  /**< A fatal alert message was received from our peer. */
    MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED                = -0x7800,  /**< Verification of our peer failed. */
    MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY                 = -0x7880,  /**< The peer notified us that the connection is going to be closed. */
    MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO               = -0x7900,  /**< Processing of the ClientHello handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO               = -0x7980,  /**< Processing of the ServerHello handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE                = -0x7A00,  /**< Processing of the Certificate handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST        = -0x7A80,  /**< Processing of the CertificateRequest handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE        = -0x7B00,  /**< Processing of the ServerKeyExchange handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE          = -0x7B80,  /**< Processing of the ServerHelloDone handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE        = -0x7C00,  /**< Processing of the ClientKeyExchange handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP     = -0x7C80,  /**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public. */
    MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS     = -0x7D00,  /**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret. */
    MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY         = -0x7D80,  /**< Processing of the CertificateVerify handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC         = -0x7E00,  /**< Processing of the ChangeCipherSpec handshake message failed. */
    MBEDTLS_ERR_SSL_BAD_HS_FINISHED                   = -0x7E80,  /**< Processing of the Finished handshake message failed. */
    MBEDTLS_ERR_SSL_ALLOC_FAILED                      = -0x7F00,  /**< Memory allocation failed */
    MBEDTLS_ERR_SSL_HW_ACCEL_FAILED                   = -0x7F80,  /**< Hardware acceleration function returned with error */
    MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH              = -0x6F80,  /**< Hardware acceleration function skipped / left alone data */
    MBEDTLS_ERR_SSL_COMPRESSION_FAILED                = -0x6F00,  /**< Processing of the compression / decompression failed */
    MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION           = -0x6E80,  /**< Handshake protocol not within min/max boundaries */
    MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET         = -0x6E00,  /**< Processing of the NewSessionTicket handshake message failed. */
    MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED            = -0x6D80,  /**< Session ticket has expired. */
    MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH                  = -0x6D00,  /**< Public key type mismatch (eg, asked for RSA key exchange and presented EC key) */
    MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY                  = -0x6C80,  /**< Unknown identity received (eg, PSK identity) */
    MBEDTLS_ERR_SSL_INTERNAL_ERROR                    = -0x6C00,  /**< Internal error (eg, unexpected failure in lower-level module) */
    MBEDTLS_ERR_SSL_COUNTER_WRAPPING                  = -0x6B80,  /**< A counter would wrap (eg, too many messages exchanged). */
    MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO       = -0x6B00,  /**< Unexpected message at ServerHello in renegotiation. */
    MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED             = -0x6A80,  /**< DTLS client must retry for hello verification */
    MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL                  = -0x6A00,  /**< A buffer is too small to receive or write a message */
    MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE             = -0x6980,  /**< None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages). */
    MBEDTLS_ERR_SSL_WANT_READ                         = -0x6900,  /**< No data of requested type currently available on underlying transport. */
    MBEDTLS_ERR_SSL_WANT_WRITE                        = -0x6880,  /**< Connection requires a write call. */
    MBEDTLS_ERR_SSL_TIMEOUT                           = -0x6800,  /**< The operation timed out. */
    MBEDTLS_ERR_SSL_CLIENT_RECONNECT                  = -0x6780,  /**< The client initiated a reconnect from the same port. */
    MBEDTLS_ERR_SSL_UNEXPECTED_RECORD                 = -0x6700,  /**< Record header looks valid but is not expected. */
    MBEDTLS_ERR_SSL_NON_FATAL                         = -0x6680,  /**< The alert message received indicates a non-fatal error. */
    MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH               = -0x6600,  /**< Couldn't set the hash for verifying CertificateVerify */
    MBEDTLS_ERR_SSL_CONTINUE_PROCESSING               = -0x6580,  /**< Internal-only message signaling that further message-processing should be done */
    MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS                 = -0x6500,  /**< The asynchronous operation is not completed yet. */
    MBEDTLS_ERR_SSL_EARLY_MESSAGE                     = -0x6480,  /**< Internal-only message signaling that a message arrived early. */
    MBEDTLS_ERR_SSL_UNEXPECTED_CID                    = -0x6000,  /**< An encrypted DTLS-frame with an unexpected CID was received. */
    MBEDTLS_ERR_SSL_VERSION_MISMATCH                  = -0x5F00,  /**< An operation failed due to an unexpected version or configuration. */
    MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS                = -0x7000,  /**< A cryptographic operation is in progress. Try again later. */
    MBEDTLS_ERR_SSL_BAD_CONFIG                        = -0x5E80,  /**< Invalid value in SSL config */

    /* threading.h */
    MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE         = -0x001A,  /**< The selected feature is not available. */
    MBEDTLS_ERR_THREADING_BAD_INPUT_DATA              = -0x001C,  /**< Bad input parameters to function. */
    MBEDTLS_ERR_THREADING_MUTEX_ERROR                 = -0x001E,  /**< Locking / unlocking / free failed with error code. */

    /* x509.h */
    MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE              = -0x2080,  /**< Unavailable feature, e.g. RSA hashing/encryption combination. */
    MBEDTLS_ERR_X509_UNKNOWN_OID                      = -0x2100,  /**< Requested OID is unknown. */
    MBEDTLS_ERR_X509_INVALID_FORMAT                   = -0x2180,  /**< The CRT/CRL/CSR format is invalid, e.g. different type expected. */
    MBEDTLS_ERR_X509_INVALID_VERSION                  = -0x2200,  /**< The CRT/CRL/CSR version element is invalid. */
    MBEDTLS_ERR_X509_INVALID_SERIAL                   = -0x2280,  /**< The serial tag or value is invalid. */
    MBEDTLS_ERR_X509_INVALID_ALG                      = -0x2300,  /**< The algorithm tag or value is invalid. */
    MBEDTLS_ERR_X509_INVALID_NAME                     = -0x2380,  /**< The name tag or value is invalid. */
    MBEDTLS_ERR_X509_INVALID_DATE                     = -0x2400,  /**< The date tag or value is invalid. */
    MBEDTLS_ERR_X509_INVALID_SIGNATURE                = -0x2480,  /**< The signature tag or value invalid. */
    MBEDTLS_ERR_X509_INVALID_EXTENSIONS               = -0x2500,  /**< The extension tag or value is invalid. */
    MBEDTLS_ERR_X509_UNKNOWN_VERSION                  = -0x2580,  /**< CRT/CRL/CSR has an unsupported version number. */
    MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG                  = -0x2600,  /**< Signature algorithm (oid) is unsupported. */
    MBEDTLS_ERR_X509_SIG_MISMATCH                     = -0x2680,  /**< Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid) */
    MBEDTLS_ERR_X509_CERT_VERIFY_FAILED               = -0x2700,  /**< Certificate verification failed, e.g. CRL, CA or signature check failed. */
    MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT              = -0x2780,  /**< Format not recognized as DER or PEM. */
    MBEDTLS_ERR_X509_BAD_INPUT_DATA                   = -0x2800,  /**< Input invalid. */
    MBEDTLS_ERR_X509_ALLOC_FAILED                     = -0x2880,  /**< Allocation of memory failed. */
    MBEDTLS_ERR_X509_FILE_IO_ERROR                    = -0x2900,  /**< Read/write of file failed. */
    MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 = -0x2980,  /**< Destination buffer is too small. */
    MBEDTLS_ERR_X509_FATAL_ERROR                      = -0x3000,  /**< A fatal error occurred, eg the chain is too long or the vrfy callback failed. */

    /* xtea.h */
    MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH             = -0x0028,  /**< The data input has an invalid length. */
    MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED                  = -0x0029,  /**< XTEA hardware accelerator failed. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/aes.h

enum MBEDTLS_AES_ENC_TYPE {
    MBEDTLS_AES_ENCRYPT = 1, /**< AES encryption. */
    MBEDTLS_AES_DECRYPT = 0, /**< AES decryption. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/arc4.h

struct mbedtls_arc4_context {
    int x;                      /*!< permutation index */
    int y;                      /*!< permutation index */
    unsigned char m[256];       /*!< permutation table */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/aria.h

enum MBEDTLS_ARIA_ENC_TYPE {
    MBEDTLS_ARIA_ENCRYPT = 1, /**< ARIA encryption. */
    MBEDTLS_ARIA_DECRYPT = 0, /**< ARIA decryption. */
};

enum MBEDTLS_ARIA_BLOCKSIZE {
    MBEDTLS_ARIA_BLOCKSIZE = 16, /**< ARIA block size in bytes. */
};

enum MBEDTLS_ARIA_MAX_ROUNDS {
    MBEDTLS_ARIA_MAX_ROUNDS = 16, /**< Maxiumum number of rounds in ARIA. */
};

enum MBEDTLS_ARIA_MAX_KEYSIZE {
    MBEDTLS_ARIA_MAX_KEYSIZE = 32, /**< Maximum size of an ARIA key in bytes. */
};

struct mbedtls_aria_context {
    unsigned char nr;           /*!< The number of rounds (12, 14 or 16) */
    /*! The ARIA round keys. */
    uint32_t rk[16 + 1][16 / 4];
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/asn1.h

enum MBEDTLS_ASN1_TYPE {
    MBEDTLS_ASN1_BOOLEAN          = 0x01,
    MBEDTLS_ASN1_INTEGER          = 0x02,
    MBEDTLS_ASN1_BIT_STRING       = 0x03,
    MBEDTLS_ASN1_OCTET_STRING     = 0x04,
    MBEDTLS_ASN1_NULL             = 0x05,
    MBEDTLS_ASN1_OID              = 0x06,
    MBEDTLS_ASN1_ENUMERATED       = 0x0A,
    MBEDTLS_ASN1_UTF8_STRING      = 0x0C,
    MBEDTLS_ASN1_SEQUENCE         = 0x10,
    MBEDTLS_ASN1_SET              = 0x11,
    MBEDTLS_ASN1_PRINTABLE_STRING = 0x13,
    MBEDTLS_ASN1_T61_STRING       = 0x14,
    MBEDTLS_ASN1_IA5_STRING       = 0x16,
    MBEDTLS_ASN1_UTC_TIME         = 0x17,
    MBEDTLS_ASN1_GENERALIZED_TIME = 0x18,
    MBEDTLS_ASN1_UNIVERSAL_STRING = 0x1C,
    MBEDTLS_ASN1_BMP_STRING       = 0x1E,
    MBEDTLS_ASN1_PRIMITIVE        = 0x00,
    MBEDTLS_ASN1_CONSTRUCTED      = 0x20,
    MBEDTLS_ASN1_CONTEXT_SPECIFIC = 0x80,
};

enum MBEDTLS_ASN1_TAG_MASK {
    MBEDTLS_ASN1_TAG_CLASS_MASK = 0xC0,
    MBEDTLS_ASN1_TAG_PC_MASK    = 0x20,
    MBEDTLS_ASN1_TAG_VALUE_MASK = 0x1F,
};

struct mbedtls_asn1_buf {
    int tag;                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
};

struct mbedtls_asn1_bitstring {
    size_t len;                 /**< ASN1 length, in octets. */
    unsigned char unused_bits;  /**< Number of unused bits at the end of the string */
    unsigned char *p;           /**< Raw ASN1 data for the bit string */
};

struct mbedtls_asn1_sequence {
    struct mbedtls_asn1_buf buf;            /**< Buffer containing the given ASN.1 item. */
    struct mbedtls_asn1_sequence *next;     /**< The next entry in the sequence. */
};

struct mbedtls_asn1_named_data {
    struct mbedtls_asn1_buf oid;            /**< The object identifier. */
    struct mbedtls_asn1_buf val;            /**< The named value. */
    struct mbedtls_asn1_named_data *next;   /**< The next entry in the sequence. */
    unsigned char next_merged;              /**< Merge next item into the current one? */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/bignum.h

enum MBEDTLS_MPI_MAX_LIMBS {
    MBEDTLS_MPI_MAX_LIMBS = 10000,
};

enum MBEDTLS_MPI_WINDOW_SIZE {
    MBEDTLS_MPI_WINDOW_SIZE = 6, /**< Maximum window size used. */
};

enum MBEDTLS_MPI_MAX_SIZE {
    MBEDTLS_MPI_MAX_SIZE = 1024, /**< Maximum number of bytes for usable MPIs. */
};

enum MBEDTLS_MPI_MAX_BITS {
    MBEDTLS_MPI_MAX_BITS = ( 8 * 1024 ),
};

enum MBEDTLS_MPI_MAX_BITS_SCALE100 {
    MBEDTLS_MPI_MAX_BITS_SCALE100 = ( 100 * 8 * 1024 ),
};

enum MBEDTLS_LN_2_DIV_LN_10_SCALE100 {
    MBEDTLS_LN_2_DIV_LN_10_SCALE100 = 332,
};

enum MBEDTLS_MPI_RW_BUFFER_SIZE {
    MBEDTLS_MPI_RW_BUFFER_SIZE = ( ((( 100 * 8 * 1024 ) + 332 - 1) / 332) + 10 + 6 ),
};

typedef  int32_t mbedtls_mpi_sint;
typedef uint32_t mbedtls_mpi_uint;

struct mbedtls_mpi {
    short s;                /*!<  Sign: -1 if the mpi is negative, 1 otherwise */
    short use_mempool;
    size_t n;               /*!<  total # of limbs  */
    mbedtls_mpi_uint *p;    /*!<  pointer to limbs  */
};

enum mbedtls_mpi_gen_prime_flag_t {
    MBEDTLS_MPI_GEN_PRIME_FLAG_DH =      0x0001, /**< (X-1)/2 is prime too */
    MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR = 0x0002, /**< lower error rate from 2<sup>-80</sup> to 2<sup>-128</sup> */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/blowfish.h

enum MBEDTLS_BLOWFISH_ENC_TYPE {
    MBEDTLS_BLOWFISH_ENCRYPT = 1,
    MBEDTLS_BLOWFISH_DECRYPT = 0,
};

enum MBEDTLS_BLOWFISH_MAX_KEY_BITS {
    MBEDTLS_BLOWFISH_MAX_KEY_BITS = 448,
};

enum MBEDTLS_BLOWFISH_MIN_KEY_BITS {
    MBEDTLS_BLOWFISH_MIN_KEY_BITS = 32,
};

enum MBEDTLS_BLOWFISH_ROUNDS {
    MBEDTLS_BLOWFISH_ROUNDS = 16,         /**< Rounds to use. When increasing this value, make sure to extend the initialisation vectors */
};

enum MBEDTLS_BLOWFISH_BLOCKSIZE {
    MBEDTLS_BLOWFISH_BLOCKSIZE = 8,          /* Blowfish uses 64 bit blocks */
};

struct mbedtls_blowfish_context {
    uint32_t P[16 + 2];    /*!<  Blowfish round keys    */
    uint32_t S[4][256];                 /*!<  key dependent S-boxes  */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/camellia.h

enum MBEDTLS_CAMELLIA_ENC_TYPE {
    MBEDTLS_CAMELLIA_ENCRYPT = 1,
    MBEDTLS_CAMELLIA_DECRYPT = 0,
};

struct mbedtls_camellia_context {
    int nr;                     /*!<  number of rounds  */
    uint32_t rk[68];            /*!<  CAMELLIA round keys    */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/cipher.h

enum mbedtls_cipher_id_t {
    MBEDTLS_CIPHER_ID_NONE = 0,  /**< Placeholder to mark the end of cipher ID lists. */
    MBEDTLS_CIPHER_ID_NULL,      /**< The identity cipher, treated as a stream cipher. */
    MBEDTLS_CIPHER_ID_AES,       /**< The AES cipher. */
    MBEDTLS_CIPHER_ID_DES,       /**< The DES cipher. */
    MBEDTLS_CIPHER_ID_3DES,      /**< The Triple DES cipher. */
    MBEDTLS_CIPHER_ID_CAMELLIA,  /**< The Camellia cipher. */
    MBEDTLS_CIPHER_ID_BLOWFISH,  /**< The Blowfish cipher. */
    MBEDTLS_CIPHER_ID_ARC4,      /**< The RC4 cipher. */
    MBEDTLS_CIPHER_ID_ARIA,      /**< The Aria cipher. */
    MBEDTLS_CIPHER_ID_CHACHA20,  /**< The ChaCha20 cipher. */
};

enum mbedtls_cipher_type_t {
    MBEDTLS_CIPHER_NONE = 0,             /**< Placeholder to mark the end of cipher-pair lists. */
    MBEDTLS_CIPHER_NULL,                 /**< The identity stream cipher. */
    MBEDTLS_CIPHER_AES_128_ECB,          /**< AES cipher with 128-bit ECB mode. */
    MBEDTLS_CIPHER_AES_192_ECB,          /**< AES cipher with 192-bit ECB mode. */
    MBEDTLS_CIPHER_AES_256_ECB,          /**< AES cipher with 256-bit ECB mode. */
    MBEDTLS_CIPHER_AES_128_CBC,          /**< AES cipher with 128-bit CBC mode. */
    MBEDTLS_CIPHER_AES_192_CBC,          /**< AES cipher with 192-bit CBC mode. */
    MBEDTLS_CIPHER_AES_256_CBC,          /**< AES cipher with 256-bit CBC mode. */
    MBEDTLS_CIPHER_AES_128_CFB128,       /**< AES cipher with 128-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_192_CFB128,       /**< AES cipher with 192-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_256_CFB128,       /**< AES cipher with 256-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_128_CTR,          /**< AES cipher with 128-bit CTR mode. */
    MBEDTLS_CIPHER_AES_192_CTR,          /**< AES cipher with 192-bit CTR mode. */
    MBEDTLS_CIPHER_AES_256_CTR,          /**< AES cipher with 256-bit CTR mode. */
    MBEDTLS_CIPHER_AES_128_GCM,          /**< AES cipher with 128-bit GCM mode. */
    MBEDTLS_CIPHER_AES_192_GCM,          /**< AES cipher with 192-bit GCM mode. */
    MBEDTLS_CIPHER_AES_256_GCM,          /**< AES cipher with 256-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_ECB,     /**< Camellia cipher with 128-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_ECB,     /**< Camellia cipher with 192-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_ECB,     /**< Camellia cipher with 256-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CBC,     /**< Camellia cipher with 128-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CBC,     /**< Camellia cipher with 192-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CBC,     /**< Camellia cipher with 256-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CFB128,  /**< Camellia cipher with 128-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CFB128,  /**< Camellia cipher with 192-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CFB128,  /**< Camellia cipher with 256-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CTR,     /**< Camellia cipher with 128-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CTR,     /**< Camellia cipher with 192-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CTR,     /**< Camellia cipher with 256-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_GCM,     /**< Camellia cipher with 128-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_GCM,     /**< Camellia cipher with 192-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_GCM,     /**< Camellia cipher with 256-bit GCM mode. */
    MBEDTLS_CIPHER_DES_ECB,              /**< DES cipher with ECB mode. */
    MBEDTLS_CIPHER_DES_CBC,              /**< DES cipher with CBC mode. */
    MBEDTLS_CIPHER_DES_EDE_ECB,          /**< DES cipher with EDE ECB mode. */
    MBEDTLS_CIPHER_DES_EDE_CBC,          /**< DES cipher with EDE CBC mode. */
    MBEDTLS_CIPHER_DES_EDE3_ECB,         /**< DES cipher with EDE3 ECB mode. */
    MBEDTLS_CIPHER_DES_EDE3_CBC,         /**< DES cipher with EDE3 CBC mode. */
    MBEDTLS_CIPHER_BLOWFISH_ECB,         /**< Blowfish cipher with ECB mode. */
    MBEDTLS_CIPHER_BLOWFISH_CBC,         /**< Blowfish cipher with CBC mode. */
    MBEDTLS_CIPHER_BLOWFISH_CFB64,       /**< Blowfish cipher with CFB64 mode. */
    MBEDTLS_CIPHER_BLOWFISH_CTR,         /**< Blowfish cipher with CTR mode. */
    MBEDTLS_CIPHER_ARC4_128,             /**< RC4 cipher with 128-bit mode. */
    MBEDTLS_CIPHER_AES_128_CCM,          /**< AES cipher with 128-bit CCM mode. */
    MBEDTLS_CIPHER_AES_192_CCM,          /**< AES cipher with 192-bit CCM mode. */
    MBEDTLS_CIPHER_AES_256_CCM,          /**< AES cipher with 256-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CCM,     /**< Camellia cipher with 128-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CCM,     /**< Camellia cipher with 192-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CCM,     /**< Camellia cipher with 256-bit CCM mode. */
    MBEDTLS_CIPHER_ARIA_128_ECB,         /**< Aria cipher with 128-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_192_ECB,         /**< Aria cipher with 192-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_256_ECB,         /**< Aria cipher with 256-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_128_CBC,         /**< Aria cipher with 128-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_192_CBC,         /**< Aria cipher with 192-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_256_CBC,         /**< Aria cipher with 256-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_128_CFB128,      /**< Aria cipher with 128-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_192_CFB128,      /**< Aria cipher with 192-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_256_CFB128,      /**< Aria cipher with 256-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_128_CTR,         /**< Aria cipher with 128-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_192_CTR,         /**< Aria cipher with 192-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_256_CTR,         /**< Aria cipher with 256-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_128_GCM,         /**< Aria cipher with 128-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_192_GCM,         /**< Aria cipher with 192-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_256_GCM,         /**< Aria cipher with 256-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_128_CCM,         /**< Aria cipher with 128-bit key and CCM mode. */
    MBEDTLS_CIPHER_ARIA_192_CCM,         /**< Aria cipher with 192-bit key and CCM mode. */
    MBEDTLS_CIPHER_ARIA_256_CCM,         /**< Aria cipher with 256-bit key and CCM mode. */
    MBEDTLS_CIPHER_AES_128_OFB,          /**< AES 128-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_192_OFB,          /**< AES 192-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_256_OFB,          /**< AES 256-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_128_XTS,          /**< AES 128-bit cipher in XTS block mode. */
    MBEDTLS_CIPHER_AES_256_XTS,          /**< AES 256-bit cipher in XTS block mode. */
    MBEDTLS_CIPHER_CHACHA20,             /**< ChaCha20 stream cipher. */
    MBEDTLS_CIPHER_CHACHA20_POLY1305,    /**< ChaCha20-Poly1305 AEAD cipher. */
    MBEDTLS_CIPHER_AES_128_KW,           /**< AES cipher with 128-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_192_KW,           /**< AES cipher with 192-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_256_KW,           /**< AES cipher with 256-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_128_KWP,          /**< AES cipher with 128-bit NIST KWP mode. */
    MBEDTLS_CIPHER_AES_192_KWP,          /**< AES cipher with 192-bit NIST KWP mode. */
    MBEDTLS_CIPHER_AES_256_KWP,          /**< AES cipher with 256-bit NIST KWP mode. */
};

enum mbedtls_cipher_mode_t {
    MBEDTLS_MODE_NONE = 0,               /**< None.                        */
    MBEDTLS_MODE_ECB,                    /**< The ECB cipher mode.         */
    MBEDTLS_MODE_CBC,                    /**< The CBC cipher mode.         */
    MBEDTLS_MODE_CFB,                    /**< The CFB cipher mode.         */
    MBEDTLS_MODE_OFB,                    /**< The OFB cipher mode.         */
    MBEDTLS_MODE_CTR,                    /**< The CTR cipher mode.         */
    MBEDTLS_MODE_GCM,                    /**< The GCM cipher mode.         */
    MBEDTLS_MODE_STREAM,                 /**< The stream cipher mode.      */
    MBEDTLS_MODE_CCM,                    /**< The CCM cipher mode.         */
    MBEDTLS_MODE_XTS,                    /**< The XTS cipher mode.         */
    MBEDTLS_MODE_CHACHAPOLY,             /**< The ChaCha-Poly cipher mode. */
    MBEDTLS_MODE_KW,                     /**< The SP800-38F KW mode */
    MBEDTLS_MODE_KWP,                    /**< The SP800-38F KWP mode */
};

enum mbedtls_cipher_padding_t {
    MBEDTLS_PADDING_PKCS7 = 0,     /**< PKCS7 padding (default).        */
    MBEDTLS_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         */
    MBEDTLS_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             */
    MBEDTLS_PADDING_ZEROS,         /**< Zero padding (not reversible). */
    MBEDTLS_PADDING_NONE,          /**< Never pad (full blocks only).   */
};

enum mbedtls_operation_t {
    MBEDTLS_OPERATION_NONE = -1,
    MBEDTLS_DECRYPT = 0,
    MBEDTLS_ENCRYPT,
};

enum mbedtls_key_length {
    /** Undefined key length. */
    MBEDTLS_KEY_LENGTH_NONE = 0,
    /** Key length, in bits (including parity), for DES keys. */
    MBEDTLS_KEY_LENGTH_DES  = 64,
    /** Key length in bits, including parity, for DES in two-key EDE. */
    MBEDTLS_KEY_LENGTH_DES_EDE = 128,
    /** Key length in bits, including parity, for DES in three-key EDE. */
    MBEDTLS_KEY_LENGTH_DES_EDE3 = 192,
};

struct mbedtls_cipher_info_t {
    /** Full cipher identifier. For example,
     * MBEDTLS_CIPHER_AES_256_CBC.
     */
    enum mbedtls_cipher_type_t type;

    /** The cipher mode. For example, MBEDTLS_MODE_CBC. */
    enum mbedtls_cipher_mode_t mode;

    /** The cipher key length, in bits. This is the
     * default length for variable sized ciphers.
     * Includes parity bits for ciphers like DES.
     */
    unsigned int key_bitlen;

    /** Name of the cipher. */
    const char * name;

    /** IV or nonce size, in Bytes.
     * For ciphers that accept variable IV sizes,
     * this is the recommended size.
     */
    unsigned int iv_size;

    /** Bitflag comprised of MBEDTLS_CIPHER_VARIABLE_IV_LEN and
     *  MBEDTLS_CIPHER_VARIABLE_KEY_LEN indicating whether the
     *  cipher supports variable IV or variable key sizes, respectively.
     */
    int flags;

    /** The block size, in Bytes. */
    unsigned int block_size;

    /** Struct for base cipher information and functions. */
    struct mbedtls_cipher_base_t *base;
};

#define MBEDTLS_MAX_BLOCK_LENGTH   16
#define MBEDTLS_MAX_IV_LENGTH      16

struct mbedtls_cipher_context_t {
    /** Information about the associated cipher. */
    struct mbedtls_cipher_info_t *cipher_info;

    /** Key length to use. */
    int key_bitlen;

    /** Operation that the key of the context has been
     * initialized for.
     */
    enum mbedtls_operation_t operation;

//#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    /** Padding functions to use, if relevant for
     * the specific cipher mode.
     */
    void (*add_padding)( unsigned char *output, size_t olen, size_t data_len );
    int (*get_padding)( unsigned char *input, size_t ilen, size_t *data_len );
//#endif

    /** Buffer for input that has not been processed yet. */
    unsigned char unprocessed_data[MBEDTLS_MAX_BLOCK_LENGTH];

    /** Number of Bytes that have not been processed yet. */
    size_t unprocessed_len;

    /** Current IV or NONCE_COUNTER for CTR-mode, data unit (or sector) number
     * for XTS-mode. */
    unsigned char iv[MBEDTLS_MAX_IV_LENGTH];

    /** IV size in Bytes, for ciphers with variable-length IVs. */
    size_t iv_size;

    /** The cipher-specific context. */
    void *cipher_ctx;

//#if defined(MBEDTLS_CMAC_C)
    /** CMAC-specific context. */
    struct mbedtls_cmac_context_t *cmac_ctx;
//#endif

//#if defined(MBEDTLS_USE_PSA_CRYPTO)
    /** Indicates whether the cipher operations should be performed
     *  by Mbed TLS' own crypto library or an external implementation
     *  of the PSA Crypto API.
     *  This is unset if the cipher context was established through
     *  mbedtls_cipher_setup(), and set if it was established through
     *  mbedtls_cipher_setup_psa().
     */
    unsigned char psa_enabled;
//#endif /* MBEDTLS_USE_PSA_CRYPTO */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/ccm.h

struct mbedtls_ccm_context {
    struct mbedtls_cipher_context_t cipher_ctx;    /*!< The cipher context used. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/chacha20.h

struct mbedtls_chacha20_context
{
    uint32_t state[16];          /*! The state (before round operations). */
    uint8_t  keystream8[64];     /*! Leftover keystream bytes. */
    size_t keystream_bytes_used; /*! Number of keystream bytes already used. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/poly1305.h

struct mbedtls_poly1305_context {
    uint32_t r[4];      /** The value for 'r' (low 128 bits of the key). */
    uint32_t s[4];      /** The value for 's' (high 128 bits of the key). */
    uint32_t acc[5];    /** The accumulator number. */
    uint8_t queue[16];  /** The current partial block of data. */
    size_t queue_len;   /** The number of bytes stored in 'queue'. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/chachapoly.h

enum mbedtls_chachapoly_mode_t {
    MBEDTLS_CHACHAPOLY_ENCRYPT,     /**< The mode value for performing encryption. */
    MBEDTLS_CHACHAPOLY_DECRYPT,     /**< The mode value for performing decryption. */
};

struct mbedtls_chachapoly_context {
    struct mbedtls_chacha20_context chacha20_ctx;  /**< The ChaCha20 context. */
    struct mbedtls_poly1305_context poly1305_ctx;  /**< The Poly1305 context. */
    uint64_t aad_len;                              /**< The length (bytes) of the Additional Authenticated Data. */
    uint64_t ciphertext_len;                       /**< The length (bytes) of the ciphertext. */
    int state;                                     /**< The current state of the context. */
    enum mbedtls_chachapoly_mode_t mode;           /**< Cipher mode (encrypt or decrypt). */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/cmac.h

enum MBEDTLS_BLOCK_SIZE {
    MBEDTLS_AES_BLOCK_SIZE = 16,
    MBEDTLS_DES3_BLOCK_SIZE = 8,
};


#define MBEDTLS_CIPHER_BLKSIZE_MAX      16  /**< The longest block used by CMAC is that of AES. */
//#define MBEDTLS_CIPHER_BLKSIZE_MAX      8   /**< The longest block used by CMAC is that of 3DES. */

struct mbedtls_cmac_context_t {
    /** The internal state of the CMAC algorithm.  */
    unsigned char       state[MBEDTLS_CIPHER_BLKSIZE_MAX];

    /** Unprocessed data - either data that was not block aligned and is still
     *  pending processing, or the final block. */
    unsigned char       unprocessed_block[MBEDTLS_CIPHER_BLKSIZE_MAX];

    /** The length of data pending processing. */
    size_t              unprocessed_len;
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/ctr_drbg.h

struct mbedtls_ctr_drbg_context {
    unsigned char counter[16];                 /*!< The counter (V). */
    int reseed_counter;                        /*!< The reseed counter.
                                                * This is the number of requests that have
                                                * been made since the last (re)seeding,
                                                * minus one.
                                                * Before the initial seeding, this field
                                                * contains the amount of entropy in bytes
                                                * to use as a nonce for the initial seeding,
                                                * or -1 if no nonce length has been explicitly
                                                * set (see mbedtls_ctr_drbg_set_nonce_len()).
                                                */
    int prediction_resistance;                 /*!< This determines whether prediction resistance is enabled, that is whether to systematically reseed before each random generation. */
    size_t entropy_len;                        /*!< The amount of entropy grabbed on each seed or reseed operation, in bytes. */
    int reseed_interval;                       /*!< The reseed interval.
                                                * This is the maximum number of requests
                                                * that can be made between reseedings. */
    struct mbedtls_aes_context aes_ctx;        /*!< The AES context. */
    /*
     * Callbacks (Entropy)
     */
    int (*f_entropy)(void *, unsigned char *, size_t); /*!< The entropy callback function. */
    void *p_entropy;                                   /*!< The context for the entropy function. */
//#if defined(MBEDTLS_THREADING_C)
//     /* Invariant: the mutex is initialized if and only if f_entropy != NULL.
//      * This means that the mutex is initialized during the initial seeding
//      * in mbedtls_ctr_drbg_seed() and freed in mbedtls_ctr_drbg_free().
//      *
//      * Note that this invariant may change without notice. Do not rely on it
//      * and do not access the mutex directly in application code.
//      */
//     struct mbedtls_threading_mutex_t mutex;
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/debug.h

enum mbedtls_debug_ecdh_attr {
    MBEDTLS_DEBUG_ECDH_Q,
    MBEDTLS_DEBUG_ECDH_QP,
    MBEDTLS_DEBUG_ECDH_Z,
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/des.h

enum MBEDTLS_DES_ENC_TYPE {
    MBEDTLS_DES_ENCRYPT = 1,
    MBEDTLS_DES_DECRYPT = 0,
};

enum MBEDTLS_DES_KEY_SIZE {
    MBEDTLS_DES_KEY_SIZE = 8,
};

struct mbedtls_des_context {
    uint32_t sk[32];            /*!<  DES subkeys       */
};

struct mbedtls_des3_context {
    uint32_t sk[96];            /*!<  3DES subkeys      */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/dhm.h

struct mbedtls_dhm_context {
    size_t len;                /*!<  The size of \p P in Bytes. */
    struct mbedtls_mpi P;      /*!<  The prime modulus. */
    struct mbedtls_mpi G;      /*!<  The generator. */
    struct mbedtls_mpi X;      /*!<  Our secret value. */
    struct mbedtls_mpi GX;     /*!<  Our public key = \c G^X mod \c P. */
    struct mbedtls_mpi GY;     /*!<  The public key of the peer = \c G^Y mod \c P. */
    struct mbedtls_mpi K;      /*!<  The shared secret = \c G^(XY) mod \c P. */
    struct mbedtls_mpi RP;     /*!<  The cached value = \c R^2 mod \c P. */
    struct mbedtls_mpi Vi;     /*!<  The blinding value. */
    struct mbedtls_mpi Vf;     /*!<  The unblinding value. */
    struct mbedtls_mpi pX;     /*!<  The previous \c X. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/ecp.h

enum mbedtls_ecp_group_id {
    MBEDTLS_ECP_DP_NONE       = 0,   /*!< Curve not defined. */
    MBEDTLS_ECP_DP_SECP192R1  = 1,   /*!< Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP224R1  = 2,   /*!< Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP256R1  = 3,   /*!< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP384R1  = 4,   /*!< Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_SECP521R1  = 5,   /*!< Domain parameters for the 521-bit curve defined by FIPS 186-4 and SEC1. */
    MBEDTLS_ECP_DP_BP256R1    = 6,   /*!< Domain parameters for 256-bit Brainpool curve. */
    MBEDTLS_ECP_DP_BP384R1    = 7,   /*!< Domain parameters for 384-bit Brainpool curve. */
    MBEDTLS_ECP_DP_BP512R1    = 8,   /*!< Domain parameters for 512-bit Brainpool curve. */
    MBEDTLS_ECP_DP_CURVE25519 = 9,   /*!< Domain parameters for Curve25519. */
    MBEDTLS_ECP_DP_SECP192K1  = 10,  /*!< Domain parameters for 192-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_SECP224K1  = 11,  /*!< Domain parameters for 224-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_SECP256K1  = 12,  /*!< Domain parameters for 256-bit "Koblitz" curve. */
    MBEDTLS_ECP_DP_CURVE448   = 13,  /*!< Domain parameters for Curve448. */
    MBEDTLS_ECP_DP_SM2        = 14,  /*!< Domain parameters for SM2. */
};

enum mbedtls_ecp_curve_type {
    MBEDTLS_ECP_TYPE_NONE              = 0,
    MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS = 1,   /* y^2 = x^3 + a x + b      */
    MBEDTLS_ECP_TYPE_MONTGOMERY        = 2,   /* y^2 = x^3 + a x^2 + x    */
};

struct mbedtls_ecp_curve_info {
    enum mbedtls_ecp_group_id grp_id;    /*!< An internal identifier. */
    uint16_t tls_id;                     /*!< The TLS NamedCurve identifier. */
    uint16_t bit_size;                   /*!< The curve size in bits. */
    const char *name;                    /*!< A human-friendly name. */
};

struct mbedtls_ecp_point {
    struct mbedtls_mpi X;          /*!< The X coordinate of the ECP point. */
    struct mbedtls_mpi Y;          /*!< The Y coordinate of the ECP point. */
    struct mbedtls_mpi Z;          /*!< The Z coordinate of the ECP point. */
};

struct mbedtls_ecp_group {
    enum mbedtls_ecp_group_id id;      /*!< An internal group identifier. */
    struct mbedtls_mpi P;              /*!< The prime modulus of the base field. */
    struct mbedtls_mpi A;              /*!< For Short Weierstrass: \p A in the equation. For Montgomery curves: <code>(A + 2) / 4</code>. */
    struct mbedtls_mpi B;              /*!< For Short Weierstrass: \p B in the equation. For Montgomery curves: unused. */
    struct mbedtls_ecp_point G;        /*!< The generator of the subgroup used. */
    struct mbedtls_mpi N;              /*!< The order of \p G. */
    size_t pbits;                      /*!< The number of bits in \p P. */
    size_t nbits;                      /*!< For Short Weierstrass: The number of bits in \p P. For Montgomery curves: the number of bits in the private keys. */
    unsigned int h;                    /*!< \internal 1 if the constants are static. */
    int (*modp)(struct mbedtls_mpi *); /*!< The function for fast pseudo-reduction mod \p P (see above). */
    int (*t_pre)(struct mbedtls_ecp_point *, void *);  /*!< Unused. */
    int (*t_post)(struct mbedtls_ecp_point *, void *); /*!< Unused. */
    void *t_data;                      /*!< Unused. */
    struct mbedtls_ecp_point *T;       /*!< Pre-computed points for ecp_mul_comb(). */
    size_t T_size;                     /*!< The number of pre-computed points. */
};

struct mbedtls_ecp_restart_ctx {
    unsigned ops_done;                  /*!<  current ops count             */
    unsigned depth;                     /*!<  call depth (0 = top-level)    */
    struct mbedtls_ecp_restart_mul *rsm;   /*!<  ecp_mul_comb() sub-context    */
    struct mbedtls_ecp_restart_muladd *ma; /*!<  ecp_muladd() sub-context      */
};

enum MBEDTLS_ECP_OPS {
    MBEDTLS_ECP_OPS_CHK = 3, /*!< basic ops count for ecp_check_pubkey()  */
    MBEDTLS_ECP_OPS_DBL = 8, /*!< basic ops count for ecp_double_jac()    */
    MBEDTLS_ECP_OPS_ADD = 11, /*!< basic ops count for see ecp_add_mixed() */
    MBEDTLS_ECP_OPS_INV = 120, /*!< empirical equivalent for mpi_mod_inv()  */
};

struct mbedtls_ecp_keypair {
    struct mbedtls_ecp_group grp;      /*!<  Elliptic curve and base point     */
    struct mbedtls_mpi d;              /*!<  our secret value                  */
    struct mbedtls_ecp_point Q;        /*!<  our public value                  */
};

enum MBEDTLS_ECP_PF {
    MBEDTLS_ECP_PF_UNCOMPRESSED = 0,   /**< Uncompressed point format. */
    MBEDTLS_ECP_PF_COMPRESSED   = 1,   /**< Compressed point format. */
};

enum MBEDTLS_ECP_TLS_NAMED_CURVE {
    MBEDTLS_ECP_TLS_NAMED_CURVE = 3,   /**< The named_curve of ECCurveType. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/ecdh.h

enum mbedtls_ecdh_side {
    MBEDTLS_ECDH_OURS,   /**< Our key. */
    MBEDTLS_ECDH_THEIRS, /**< The key of the peer. */
};

enum mbedtls_ecdh_variant {
    MBEDTLS_ECDH_VARIANT_NONE = 0,   /*!< Implementation not defined. */
    MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0,/*!< The default Mbed TLS implementation */
    MBEDTLS_ECDH_VARIANT_EVEREST     /*!< Everest implementation */
};

struct mbedtls_ecdh_context_mbed {
    struct mbedtls_ecp_group grp;   /*!< The elliptic curve used. */
    struct mbedtls_mpi d;           /*!< The private key. */
    struct mbedtls_ecp_point Q;     /*!< The public key. */
    struct mbedtls_ecp_point Qp;    /*!< The value of the public key of the peer. */
    struct mbedtls_mpi z;           /*!< The shared secret. */
//#if defined(MBEDTLS_ECP_RESTARTABLE)
    struct mbedtls_ecp_restart_ctx rs; /*!< The restart context for EC computations. */
//#endif
};

struct mbedtls_ecdh_context {
//#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    struct mbedtls_ecp_group grp;         /*!< The elliptic curve used. */
    struct mbedtls_mpi d;                 /*!< The private key. */
    struct mbedtls_ecp_point Q;           /*!< The public key. */
    struct mbedtls_ecp_point Qp;          /*!< The value of the public key of the peer. */
    struct mbedtls_mpi z;                 /*!< The shared secret. */
    int point_format;                     /*!< The format of point export in TLS messages. */
    struct mbedtls_ecp_point Vi;          /*!< The blinding value. */
    struct mbedtls_ecp_point Vf;          /*!< The unblinding value. */
    struct mbedtls_mpi _d;                /*!< The previous \p d. */
//#if defined(MBEDTLS_ECP_RESTARTABLE)
    int restart_enabled;                  /*!< The flag for restartable mode. */
    struct mbedtls_ecp_restart_ctx rs;    /*!< The restart context for EC computations. */
//#endif /* MBEDTLS_ECP_RESTARTABLE */
//#else
//    uint8_t point_format;                 /*!< The format of point export in TLS messages as defined in RFC 4492. */
//    enum mbedtls_ecp_group_id grp_id;     /*!< The elliptic curve used. */
//    enum mbedtls_ecdh_variant var;        /*!< The ECDH implementation/structure used. */
//    union {
//        struct mbedtls_ecdh_context_mbed   mbed_ecdh;
//#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
//        struct mbedtls_ecdh_context_everest everest_ecdh;
//#endif
//    } ctx;                                /*!< Implementation-specific context. The context in use is specified by the \c var field. */
//#if defined(MBEDTLS_ECP_RESTARTABLE)
//    uint8_t restart_enabled;              /*!< The flag for restartable mode. Functions of an alternative implementation not supporting restartable mode must return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED error if this flag is set. */
//#endif /* MBEDTLS_ECP_RESTARTABLE */
//#endif /* MBEDTLS_ECDH_LEGACY_CONTEXT */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/ecdsa.h

typedef mbedtls_ecp_keypair mbedtls_ecdsa_context;

struct mbedtls_ecdsa_restart_ctx {
    struct mbedtls_ecp_restart_ctx ecp;        /*!<  base context for ECP restart and shared administrative info    */
    struct mbedtls_ecdsa_restart_ver_ctx *ver; /*!<  ecdsa_verify() sub-context    */
    struct mbedtls_ecdsa_restart_sig_ctx *sig; /*!<  ecdsa_sign() sub-context      */
//#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    struct mbedtls_ecdsa_restart_det_ctx *det; /*!<  ecdsa_sign_det() sub-context  */
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/ecjpake.h

enum mbedtls_ecjpake_role {
    MBEDTLS_ECJPAKE_CLIENT = 0,         /**< Client                         */
    MBEDTLS_ECJPAKE_SERVER,             /**< Server                         */
};

struct mbedtls_ecjpake_context {
    struct mbedtls_md_info_t *md_info;  /**< Hash to use                    */
    struct mbedtls_ecp_group grp;       /**< Elliptic curve                 */
    enum mbedtls_ecjpake_role role;     /**< Are we client or server?       */
    int point_format;                   /**< Format for point export        */
    struct mbedtls_ecp_point Xm1;       /**< My public key 1   C: X1, S: X3 */
    struct mbedtls_ecp_point Xm2;       /**< My public key 2   C: X2, S: X4 */
    struct mbedtls_ecp_point Xp1;       /**< Peer public key 1 C: X3, S: X1 */
    struct mbedtls_ecp_point Xp2;       /**< Peer public key 2 C: X4, S: X2 */
    struct mbedtls_ecp_point Xp;        /**< Peer public key   C: Xs, S: Xc */
    struct mbedtls_mpi xm1;             /**< My private key 1  C: x1, S: x3 */
    struct mbedtls_mpi xm2;             /**< My private key 2  C: x2, S: x4 */
    struct mbedtls_mpi s;               /**< Pre-shared secret (passphrase) */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/sha1.h

struct mbedtls_sha1_context {
    uint32_t total[2];          /*!< The number of Bytes processed.  */
    uint32_t state[5];          /*!< The intermediate digest state.  */
    unsigned char buffer[64];   /*!< The data block being processed. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/sha256.h

struct mbedtls_sha256_context {
    uint32_t total[2];          /*!< The number of Bytes processed.  */
    uint32_t state[8];          /*!< The intermediate digest state.  */
    unsigned char buffer[64];   /*!< The data block being processed. */
    int is224;                  /*!< Determines which function to use: 0: Use SHA-256, or 1: Use SHA-224. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/sha512.h

struct mbedtls_sha512_context {
    uint64_t total[2];          /*!< The number of Bytes processed. */
    uint64_t state[8];          /*!< The intermediate digest state. */
    unsigned char buffer[128];  /*!< The data block being processed. */
    int is384;                  /*!< Determines which function to use: 0: Use SHA-512, or 1: Use SHA-384. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/havege.h

#define MBEDTLS_HAVEGE_COLLECT_SIZE 1024

struct mbedtls_havege_state {
    uint32_t PT1, PT2, offset[2];
    uint32_t pool[MBEDTLS_HAVEGE_COLLECT_SIZE];
    uint32_t WALK[8192];
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/entropy.h

typedef int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output, size_t len, size_t *olen);

struct mbedtls_entropy_source_state {
    mbedtls_entropy_f_source_ptr    f_source;   /**< The entropy source callback */
    void *                          p_source;   /**< The callback data pointer */
    size_t                          size;       /**< Amount received in bytes */
    size_t                          threshold;  /**< Minimum bytes required before release */
    int                             strong;     /**< Is the source strong? */
};

#define MBEDTLS_ENTROPY_MAX_SOURCES     20      /**< Maximum number of sources supported */

struct mbedtls_entropy_context {
    int accumulator_started;              /* 0 after init.
                                           * 1 after the first update.
                                           * -1 after free. */
//#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
    mbedtls_sha512_context  accumulator;
//#else
//    mbedtls_sha256_context  accumulator;
//#endif
    int             source_count;         /* Number of entries used in source. */
    struct mbedtls_entropy_source_state    source[MBEDTLS_ENTROPY_MAX_SOURCES];
//#if defined(MBEDTLS_HAVEGE_C)
    struct mbedtls_havege_state    havege_data;
//#endif
//#if defined(MBEDTLS_THREADING_C)
//    mbedtls_threading_mutex_t mutex;    /*!< mutex                  */
//#endif
//#if defined(MBEDTLS_ENTROPY_NV_SEED)
    int initial_entropy_run;
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/gcm.h

enum MBEDTLS_GCM_ENC_TYPE {
    MBEDTLS_GCM_ENCRYPT = 1,
    MBEDTLS_GCM_DECRYPT = 0,
};

struct mbedtls_gcm_context{
    struct mbedtls_cipher_context_t cipher_ctx;  /*!< The cipher context used. */
    uint64_t HL[16];                             /*!< Precalculated HTable low. */
    uint64_t HH[16];                             /*!< Precalculated HTable high. */
    uint64_t len;                                /*!< The total length of the encrypted data. */
    uint64_t add_len;                            /*!< The total length of the additional data. */
    unsigned char base_ectr[16];                 /*!< The first ECTR for tag. */
    unsigned char y[16];                         /*!< The Y working value. */
    unsigned char buf[16];                       /*!< The buf working value. */
    int mode;                                    /*!< The operation to perform: #MBEDTLS_GCM_ENCRYPT or #MBEDTLS_GCM_DECRYPT. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/md.h

enum mbedtls_md_type_t {
    MBEDTLS_MD_NONE=0,    /**< None. */
    MBEDTLS_MD_MD2,       /**< The MD2 message digest. */
    MBEDTLS_MD_MD4,       /**< The MD4 message digest. */
    MBEDTLS_MD_MD5,       /**< The MD5 message digest. */
    MBEDTLS_MD_SHA1,      /**< The SHA-1 message digest. */
    MBEDTLS_MD_SHA224,    /**< The SHA-224 message digest. */
    MBEDTLS_MD_SHA256,    /**< The SHA-256 message digest. */
    MBEDTLS_MD_SHA384,    /**< The SHA-384 message digest. */
    MBEDTLS_MD_SHA512,    /**< The SHA-512 message digest. */
    MBEDTLS_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */
};

//#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_MD_MAX_SIZE         64  /* longest known is SHA512 */
//#else
//#define MBEDTLS_MD_MAX_SIZE         32  /* longest known is SHA256 or less */
//#endif

//#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_MD_MAX_BLOCK_SIZE         128
//#else
//#define MBEDTLS_MD_MAX_BLOCK_SIZE         64
//#endif

struct mbedtls_md_context_t {
    /** Information about the associated message digest. */
    struct mbedtls_md_info_t *md_info;

    /** The digest-specific context. */
    void *md_ctx;

    /** The HMAC part of the context. */
    void *hmac_ctx;
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/hmac_drbg.h

struct mbedtls_hmac_drbg_context {
    /* Working state: the key K is not stored explicitly,
     * but is implied by the HMAC context */
    struct mbedtls_md_context_t md_ctx;                    /*!< HMAC context (inc. K)  */
    unsigned char V[MBEDTLS_MD_MAX_SIZE];  /*!< V in the spec          */
    int reseed_counter;                     /*!< reseed counter         */

    /* Administrative state */
    size_t entropy_len;         /*!< entropy bytes grabbed on each (re)seed */
    int prediction_resistance;  /*!< enable prediction resistance (Automatic
                                     reseed before every random generation) */
    int reseed_interval;        /*!< reseed interval   */

    /* Callbacks */
    int (*f_entropy)(void *, unsigned char *, size_t); /*!< entropy function */
    void *p_entropy;            /*!< context for the entropy function        */

//#if defined(MBEDTLS_THREADING_C)
//    /* Invariant: the mutex is initialized if and only if
//     * md_ctx->md_info != NULL. This means that the mutex is initialized
//     * during the initial seeding in mbedtls_hmac_drbg_seed() or
//     * mbedtls_hmac_drbg_seed_buf() and freed in mbedtls_ctr_drbg_free().
//     *
//     * Note that this invariant may change without notice. Do not rely on it
//     * and do not access the mutex directly in application code.
//     */
//    mbedtls_threading_mutex_t mutex;
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/md2.h

struct mbedtls_md2_context {
    unsigned char cksum[16];    /*!< checksum of the data block */
    unsigned char state[48];    /*!< intermediate digest state  */
    unsigned char buffer[16];   /*!< data block being processed */
    size_t left;                /*!< amount of data in buffer   */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/md4.h

struct mbedtls_md4_context {
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/md5.h

struct mbedtls_md5_context {
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/net_socket.h

struct mbedtls_net_context {
    int fd;             /**< The underlying file descriptor                 */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/nist_kw.h

enum mbedtls_nist_kw_mode_t {
    MBEDTLS_KW_MODE_KW = 0,
    MBEDTLS_KW_MODE_KWP = 1
};

struct mbedtls_nist_kw_context {
    struct mbedtls_cipher_context_t cipher_ctx;    /*!< The cipher context used. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/oid.h

enum MBEDTLS_OID_X509_ID {
    MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER  = (1 << 0),
    MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER    = (1 << 1),
    MBEDTLS_OID_X509_EXT_KEY_USAGE                 = (1 << 2),
    MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES      = (1 << 3),
    MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS           = (1 << 4),
    MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME          = (1 << 5),
    MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME           = (1 << 6),
    MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS   = (1 << 7),
    MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS         = (1 << 8),
    MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS          = (1 << 9),
    MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS        = (1 << 10),
    MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE        = (1 << 11),
    MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS   = (1 << 12),
    MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY        = (1 << 13),
    MBEDTLS_OID_X509_EXT_FRESHEST_CRL              = (1 << 14),
    MBEDTLS_OID_X509_EXT_NS_CERT_TYPE              = (1 << 16),
};

struct mbedtls_oid_descriptor_t {
    const char *asn1;               /*!< OID ASN.1 representation       */
    size_t asn1_len;                /*!< length of asn1                 */
    const char *name;               /*!< official name (e.g. from RFC)  */
    const char *description;        /*!< human friendly description     */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/padlock.h

enum MBEDTLS_PADLOCK_TYPE {
    MBEDTLS_PADLOCK_RNG = 0x000C,
    MBEDTLS_PADLOCK_ACE = 0x00C0,
    MBEDTLS_PADLOCK_PHE = 0x0C00,
    MBEDTLS_PADLOCK_PMM = 0x3000,
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/pem.h

struct mbedtls_pem_context {
    unsigned char *buf;     /*!< buffer for decoded data             */
    size_t buflen;          /*!< length of the buffer                */
    unsigned char *info;    /*!< buffer for extra header information */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/pkcs11.h

struct mbedtls_pkcs11_context {
    struct pkcs11h_certificate_s * pkcs11h_cert;
    int len;
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/pkcs12.h

enum MBEDTLS_PKCS12_DERIVE_TYPE {
    MBEDTLS_PKCS12_DERIVE_KEY     = 1,   /**< encryption/decryption key */
    MBEDTLS_PKCS12_DERIVE_IV      = 2,   /**< initialization vector     */
    MBEDTLS_PKCS12_DERIVE_MAC_KEY = 3,   /**< integrity / MAC key       */
};

enum MBEDTLS_PKCS12_PBE_ENC_TYPE {
    MBEDTLS_PKCS12_PBE_DECRYPT = 0,
    MBEDTLS_PKCS12_PBE_ENCRYPT = 1,
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/pkcs5.h

enum MBEDTLS_PKCS5_ENC_TYPE {
    MBEDTLS_PKCS5_DECRYPT = 0,
    MBEDTLS_PKCS5_ENCRYPT = 1,
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/pk.h

enum mbedtls_pk_type_t {
    MBEDTLS_PK_NONE=0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_RSA_ALT,
    MBEDTLS_PK_RSASSA_PSS,
    MBEDTLS_PK_OPAQUE,
};

struct mbedtls_pk_rsassa_pss_options {
    enum mbedtls_md_type_t mgf1_hash_id;
    int expected_salt_len;
};

enum mbedtls_pk_debug_type {
    MBEDTLS_PK_DEBUG_NONE = 0,
    MBEDTLS_PK_DEBUG_MPI,
    MBEDTLS_PK_DEBUG_ECP,
};

struct mbedtls_pk_debug_item {
    enum mbedtls_pk_debug_type type;
    const char *name;
    void *value;
};

struct mbedtls_pk_context {
    struct mbedtls_pk_info_t *  pk_info; /**< Public key information         */
    void *                      pk_ctx;  /**< Underlying public key context  */
};

struct mbedtls_pk_restart_ctx {
    struct mbedtls_pk_info_t *  pk_info; /**< Public key information         */
    void *                      rs_ctx;  /**< Underlying restart context     */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/ripemd160.h

struct mbedtls_ripemd160_context {
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[5];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/rsa.h

enum BEDTLS_RSA_KEY_TYPE {
    MBEDTLS_RSA_PUBLIC  = 0, /**< Request private key operation. */
    MBEDTLS_RSA_PRIVATE = 1, /**< Request public key operation. */
};

enum MBEDTLS_RSA_PKCS_TYPE {
    MBEDTLS_RSA_PKCS_V15 = 0, /**< Use PKCS#1 v1.5 encoding. */
    MBEDTLS_RSA_PKCS_V21 = 1, /**< Use PKCS#1 v2.1 encoding. */
};

enum MBEDTLS_RSA_USED_TYPE {
    MBEDTLS_RSA_SIGN  = 1, /**< Identifier for RSA signature operations. */
    MBEDTLS_RSA_CRYPT = 2, /**< Identifier for RSA encryption and decryption operations. */
};

enum MBEDTLS_RSA_SALT_LEN_ANY {
    MBEDTLS_RSA_SALT_LEN_ANY = -1,
};

struct mbedtls_rsa_context {
    int ver;                    /*!<  Reserved for internal purposes. Do not set this field in application code. Its meaning might change without notice. */
    size_t len;                 /*!<  The size of \p N in Bytes. */
    struct mbedtls_mpi N;       /*!<  The public modulus. */
    struct mbedtls_mpi E;       /*!<  The public exponent. */
    struct mbedtls_mpi D;       /*!<  The private exponent. */
    struct mbedtls_mpi P;       /*!<  The first prime factor. */
    struct mbedtls_mpi Q;       /*!<  The second prime factor. */
    struct mbedtls_mpi DP;      /*!<  <code>D % (P - 1)</code>. */
    struct mbedtls_mpi DQ;      /*!<  <code>D % (Q - 1)</code>. */
    struct mbedtls_mpi QP;      /*!<  <code>1 / (Q % P)</code>. */
    struct mbedtls_mpi RN;      /*!<  cached <code>R^2 mod N</code>. */
    struct mbedtls_mpi RP;      /*!<  cached <code>R^2 mod P</code>. */
    struct mbedtls_mpi RQ;      /*!<  cached <code>R^2 mod Q</code>. */
    struct mbedtls_mpi Vi;      /*!<  The cached blinding value. */
    struct mbedtls_mpi Vf;      /*!<  The cached un-blinding value. */
    int padding;                /*!< Selects padding mode: #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
    int hash_id;                /*!< Hash identifier of mbedtls_md_type_t type, as specified in md.h for use in the MGF mask generating function used in the EME-OAEP and EMSA-PSS encodings. */
//#if defined(MBEDTLS_THREADING_C)
//    /* Invariant: the mutex is initialized iff ver != 0. */
//    mbedtls_threading_mutex_t mutex;    /*!<  Thread-safety mutex. */
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/ssl_ticket.h

struct mbedtls_ssl_ticket_key {
    unsigned char name[4];                 /*!< random key identifier              */
    uint32_t generation_time;              /*!< key generation timestamp (seconds) */
    struct mbedtls_cipher_context_t ctx;   /*!< context for auth enc/decryption    */
};

struct mbedtls_ssl_ticket_context {
    struct mbedtls_ssl_ticket_key keys[2]; /*!< ticket protection keys             */
    unsigned char active;                  /*!< index of the currently active key  */
    uint32_t ticket_lifetime;              /*!< lifetime of tickets in seconds     */

    /** Callback for getting (pseudo-)random numbers                               */
    int  (*f_rng)(void *, unsigned char *, size_t);
    void *p_rng;                           /*!< context for the RNG function       */

//#if defined(MBEDTLS_THREADING_C)
//    mbedtls_threading_mutex_t mutex;
//#endif
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/timing.h

struct mbedtls_timing_hr_time {
    unsigned char opaque[32];
};

struct mbedtls_timing_delay_context {
    struct mbedtls_timing_hr_time   timer;
    uint32_t                        int_ms;
    uint32_t                        fin_ms;
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/x509.h

#define MBEDTLS_X509_MAX_INTERMEDIATE_CA   8

typedef struct mbedtls_asn1_buf        mbedtls_x509_buf;
typedef struct mbedtls_asn1_bitstring  mbedtls_x509_bitstring;
typedef struct mbedtls_asn1_named_data mbedtls_x509_name;
typedef struct mbedtls_asn1_sequence   mbedtls_x509_sequence;

struct mbedtls_x509_time {
    int year, mon, day;         /**< Date. */
    int hour, min, sec;         /**< Time. */
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/x509_crl.h

struct mbedtls_x509_crl_entry {
    mbedtls_x509_buf raw;
    mbedtls_x509_buf serial;
    mbedtls_x509_time revocation_date;
    mbedtls_x509_buf entry_ext;
    struct mbedtls_x509_crl_entry *next;
};

struct mbedtls_x509_crl {
    mbedtls_x509_buf raw;           /**< The raw certificate data (DER). */
    mbedtls_x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */
    int version;                    /**< CRL version (1=v1, 2=v2) */
    mbedtls_x509_buf sig_oid;       /**< CRL signature type identifier */
    mbedtls_x509_buf issuer_raw;    /**< The raw issuer data (DER). */
    mbedtls_x509_name issuer;       /**< The parsed issuer data (named information object). */
    mbedtls_x509_time this_update;
    mbedtls_x509_time next_update;
    mbedtls_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */
    mbedtls_x509_buf crl_ext;
    mbedtls_x509_buf sig_oid2;
    mbedtls_x509_buf sig;
    enum mbedtls_md_type_t sig_md;  /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    enum mbedtls_pk_type_t sig_pk;  /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *sig_opts;                 /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */
    struct mbedtls_x509_crl *next;
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/x509_crt.h

struct mbedtls_x509_crt {
    int own_buffer;                      /**< Indicates if \c raw is owned by the structure or not.        */
    mbedtls_x509_buf raw;                /**< The raw certificate data (DER). */
    mbedtls_x509_buf tbs;                /**< The raw certificate body (DER). The part that is To Be Signed. */
    int version;                         /**< The X.509 version. (1=v1, 2=v2, 3=v3) */
    mbedtls_x509_buf serial;             /**< Unique id for certificate issued by a specific CA. */
    mbedtls_x509_buf sig_oid;            /**< Signature algorithm, e.g. sha1RSA */
    mbedtls_x509_buf issuer_raw;         /**< The raw issuer data (DER). Used for quick comparison. */
    mbedtls_x509_buf subject_raw;        /**< The raw subject data (DER). Used for quick comparison. */
    mbedtls_x509_name issuer;            /**< The parsed issuer data (named information object). */
    mbedtls_x509_name subject;           /**< The parsed subject data (named information object). */
    mbedtls_x509_time valid_from;        /**< Start time of certificate validity. */
    mbedtls_x509_time valid_to;          /**< End time of certificate validity. */
    mbedtls_x509_buf pk_raw;
    mbedtls_pk_context pk;               /**< Container for the public key context. */
    mbedtls_x509_buf issuer_id;          /**< Optional X.509 v2/v3 issuer unique identifier. */
    mbedtls_x509_buf subject_id;         /**< Optional X.509 v2/v3 subject unique identifier. */
    mbedtls_x509_buf v3_ext;             /**< Optional X.509 v3 extensions.  */
    mbedtls_x509_sequence subject_alt_names;    /**< Optional list of raw entries of Subject Alternative Names extension (currently only dNSName and OtherName are listed). */
    mbedtls_x509_sequence certificate_policies; /**< Optional list of certificate policies (Only anyPolicy is printed and enforced, however the rest of the policies are still listed). */
    int ext_types;                       /**< Bit string containing detected and parsed extensions */
    int ca_istrue;                       /**< Optional Basic Constraint extension value: 1 if this certificate belongs to a CA, 0 otherwise. */
    int max_pathlen;                     /**< Optional Basic Constraint extension value: The maximum path length to the root certificate. Path length is 1 higher than RFC 5280 'meaning', so 1+ */
    unsigned int key_usage;              /**< Optional key usage extension value: See the values in x509.h */
    mbedtls_x509_sequence ext_key_usage; /**< Optional list of extended key usage OIDs. */
    unsigned char ns_cert_type;          /**< Optional Netscape certificate type extension value: See the values in x509.h */
    mbedtls_x509_buf sig;                /**< Signature: hash of the tbs part signed with the private key. */
    enum mbedtls_md_type_t sig_md;       /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    enum mbedtls_pk_type_t sig_pk;       /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *sig_opts;                      /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */
    struct mbedtls_x509_crt *next;       /**< Next certificate in the CA-chain. */
};

struct mbedtls_x509_san_other_name {
    /**
     * The type_id is an OID as deifned in RFC 5280.
     * To check the value of the type id, you should use
     * \p MBEDTLS_OID_CMP with a known OID mbedtls_x509_buf.
     */
    mbedtls_x509_buf type_id;                   /**< The type id. */
    union {
        /**
         * From RFC 4108 section 5:
         * HardwareModuleName ::= SEQUENCE {
         *                         hwType OBJECT IDENTIFIER,
         *                         hwSerialNum OCTET STRING }
         */
        struct {
            mbedtls_x509_buf oid;               /**< The object identifier. */
            mbedtls_x509_buf val;               /**< The named value. */
        } hardware_module_name;
    } value;
};

struct mbedtls_x509_subject_alternative_name {
    int type;                                                 /**< The SAN type, value of MBEDTLS_X509_SAN_XXX. */
    union {
        struct mbedtls_x509_san_other_name other_name;        /**< The otherName supported type. */
        mbedtls_x509_buf                   unstructured_name; /**< The buffer for the un constructed types. Only dnsName currently supported */
    } san;                                                    /**< A union of the supported SAN types */
};

struct mbedtls_x509_crt_profile {
    uint32_t allowed_mds;       /**< MDs for signatures         */
    uint32_t allowed_pks;       /**< PK algs for signatures     */
    uint32_t allowed_curves;    /**< Elliptic curves for ECDSA  */
    uint32_t rsa_min_bitlen;    /**< Minimum size for RSA keys  */
};

#define MBEDTLS_X509_RFC5280_UTC_TIME_LEN   15

struct mbedtls_x509write_cert {
    int version;
    struct mbedtls_mpi serial;
    struct mbedtls_pk_context *subject_key;
    struct mbedtls_pk_context *issuer_key;
    struct mbedtls_asn1_named_data *subject;
    struct mbedtls_asn1_named_data *issuer;
    enum mbedtls_md_type_t md_alg;
    char not_before[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    char not_after[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    struct mbedtls_asn1_named_data *extensions;
};

struct mbedtls_x509_crt_verify_chain_item {
    mbedtls_x509_crt *crt;
    uint32_t flags;
};

#define MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE  ( MBEDTLS_X509_MAX_INTERMEDIATE_CA + 2 )

struct mbedtls_x509_crt_verify_chain {
    struct mbedtls_x509_crt_verify_chain_item items[MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE];
    unsigned len;

//#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    /* This stores the list of potential trusted signers obtained from
     * the CA callback used for the CRT verification, if configured.
     * We must track it somewhere because the callback passes its
     * ownership to the caller. */
    struct mbedtls_x509_crt *trust_ca_cb_result;
//#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
};

struct mbedtls_x509_crt_restart_ctx {
    /* for check_signature() */
    struct mbedtls_pk_restart_ctx pk;

    /* for find_parent_in() */
    struct mbedtls_x509_crt *parent; /* non-null iff parent_in in progress */
    struct mbedtls_x509_crt *fallback_parent;
    int fallback_signature_is_good;

    /* for find_parent() */
    int parent_is_trusted; /* -1 if find_parent is not in progress */

    /* for verify_chain() */
    enum {
        x509_crt_rs_none,
        x509_crt_rs_find_parent,
    } in_progress;  /* none if no operation is in progress */
    int self_cnt;
    struct mbedtls_x509_crt_verify_chain ver_chain;
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/x509_csr.h

struct mbedtls_x509_csr {
    mbedtls_x509_buf raw;           /**< The raw CSR data (DER). */
    mbedtls_x509_buf cri;           /**< The raw CertificateRequestInfo body (DER). */
    int version;                    /**< CSR version (1=v1). */
    mbedtls_x509_buf  subject_raw;  /**< The raw subject data (DER). */
    mbedtls_x509_name subject;      /**< The parsed subject data (named information object). */
    struct mbedtls_pk_context pk;   /**< Container for the public key context. */
    mbedtls_x509_buf sig_oid;
    mbedtls_x509_buf sig;
    enum mbedtls_md_type_t sig_md;  /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    enum mbedtls_pk_type_t sig_pk;  /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *sig_opts;                 /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */
};

struct mbedtls_x509write_csr {
    struct mbedtls_pk_context *key;
    struct mbedtls_asn1_named_data *subject;
    enum mbedtls_md_type_t md_alg;
    struct mbedtls_asn1_named_data *extensions;
};

//---------------------------------------------------------------- optee_os/lib/libmbedtls/mbedtls/include/mbedtls/xtea.h


enum MBEDTLS_XTEA_ENC_TYPE {
    MBEDTLS_XTEA_ENCRYPT = 1,
    MBEDTLS_XTEA_DECRYPT = 0,
};

struct mbedtls_xtea_context {
    uint32_t k[4];       /*!< key */
};
