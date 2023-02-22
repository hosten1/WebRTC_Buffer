//
//  testStun.c
//  testBuffer
//
//  Created by luoyongmeng on 2023/2/22.
//

#include "testStun.h"

#import "byte_order.h"
#import "byte_buffer.h"

#import "bit_buffer.h"


#include "checks.h"

#include "ip_address.h"
#include "socket_address.h"


// RFC5769 Test Vectors
// Software name (request):  "STUN test client" (without quotes)
// Software name (response): "test vector" (without quotes)
// Username:  "evtj:h6vY" (without quotes)
// Password:  "VOkJxbRl1RmTxUk/WvJxBt" (without quotes)
static const unsigned char kRfc5769SampleMsgTransactionId[] = {
  0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae
};
static const char kRfc5769SampleMsgClientSoftware[] = "STUN test client";
static const char kRfc5769SampleMsgServerSoftware[] = "test vector";
static const char kRfc5769SampleMsgUsername[] = "evtj:h6vY";
static const char kRfc5769SampleMsgPassword[] = "VOkJxbRl1RmTxUk/WvJxBt";

static const unsigned char kRfc5769SampleMsgWithAuthTransactionId[] = {
  0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e
};
static const char kRfc5769SampleMsgWithAuthUsername[] =
    "\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9";
static const char kRfc5769SampleMsgWithAuthPassword[] = "TheMatrIX";
static const char kRfc5769SampleMsgWithAuthNonce[] =
    "f//499k954d6OL34oL9FSTvy64sA";
static const char kRfc5769SampleMsgWithAuthRealm[] = "example.org";

// 2.1.  Sample Request
static const unsigned char kRfc5769SampleRequest[] = {
  0x00, 0x01, 0x00, 0x58,   //    Request type and message length
  0x21, 0x12, 0xa4, 0x42,   //    Magic cookie
  0xb7, 0xe7, 0xa7, 0x01,   // }
  0xbc, 0x34, 0xd6, 0x86,   // }  Transaction ID
  0xfa, 0x87, 0xdf, 0xae,   // }
  0x80, 0x22, 0x00, 0x10,   //    SOFTWARE attribute header
  0x53, 0x54, 0x55, 0x4e,   // }
  0x20, 0x74, 0x65, 0x73,   // }  User-agent...
  0x74, 0x20, 0x63, 0x6c,   // }  ...name
  0x69, 0x65, 0x6e, 0x74,   // }
  0x00, 0x24, 0x00, 0x04,   //    PRIORITY attribute header
  0x6e, 0x00, 0x01, 0xff,   //    ICE priority value
  0x80, 0x29, 0x00, 0x08,   //    ICE-CONTROLLED attribute header
  0x93, 0x2f, 0xf9, 0xb1,   // }  Pseudo-random tie breaker...
  0x51, 0x26, 0x3b, 0x36,   // }   ...for ICE control
  0x00, 0x06, 0x00, 0x09,   //    USERNAME attribute header
  0x65, 0x76, 0x74, 0x6a,   // }
  0x3a, 0x68, 0x36, 0x76,   // }  Username (9 bytes) and padding (3 bytes)
  0x59, 0x20, 0x20, 0x20,   // }
  0x00, 0x08, 0x00, 0x14,   //    MESSAGE-INTEGRITY attribute header
  0x9a, 0xea, 0xa7, 0x0c,   // }
  0xbf, 0xd8, 0xcb, 0x56,   // }
  0x78, 0x1e, 0xf2, 0xb5,   // }  HMAC-SHA1 fingerprint
  0xb2, 0xd3, 0xf2, 0x49,   // }
  0xc1, 0xb5, 0x71, 0xa2,   // }
  0x80, 0x28, 0x00, 0x04,   //    FINGERPRINT attribute header
  0xe5, 0x7a, 0x3b, 0xcf    //    CRC32 fingerprint
};
const size_t kStunHeaderSize = 20;
const size_t kStunTransactionIdOffset = 8;
const size_t kStunTransactionIdLength = 12;
const uint32_t kStunMagicCookie = 0x2112A442;
constexpr size_t kStunMagicCookieLength = sizeof(kStunMagicCookie);
// 2.2.  Sample IPv4 Response
static const unsigned char kRfc5769SampleResponse[] = {
  0x01, 0x01, 0x00, 0x3c,  //     Response type and message length
  0x21, 0x12, 0xa4, 0x42,  //     Magic cookie
  0xb7, 0xe7, 0xa7, 0x01,  // }
  0xbc, 0x34, 0xd6, 0x86,  // }  Transaction ID
  0xfa, 0x87, 0xdf, 0xae,  // }
  0x80, 0x22, 0x00, 0x0b,  //    SOFTWARE attribute header
  0x74, 0x65, 0x73, 0x74,  // }
  0x20, 0x76, 0x65, 0x63,  // }  UTF-8 server name
  0x74, 0x6f, 0x72, 0x20,  // }
  0x00, 0x20, 0x00, 0x08,  //    XOR-MAPPED-ADDRESS attribute header
  0x00, 0x01, 0xa1, 0x47,  //    Address family (IPv4) and xor'd mapped port
  0xe1, 0x12, 0xa6, 0x43,  //    Xor'd mapped IPv4 address
  0x00, 0x08, 0x00, 0x14,  //    MESSAGE-INTEGRITY attribute header
  0x2b, 0x91, 0xf5, 0x99,  // }
  0xfd, 0x9e, 0x90, 0xc3,  // }
  0x8c, 0x74, 0x89, 0xf9,  // }  HMAC-SHA1 fingerprint
  0x2a, 0xf9, 0xba, 0x53,  // }
  0xf0, 0x6b, 0xe7, 0xd7,  // }
  0x80, 0x28, 0x00, 0x04,  //    FINGERPRINT attribute header
  0xc0, 0x7d, 0x4c, 0x96   //    CRC32 fingerprint
};

// 2.3.  Sample IPv6 Response
static const unsigned char kRfc5769SampleResponseIPv6[] = {
  0x01, 0x01, 0x00, 0x48,  //    Response type and message length
  0x21, 0x12, 0xa4, 0x42,  //    Magic cookie
  0xb7, 0xe7, 0xa7, 0x01,  // }
  0xbc, 0x34, 0xd6, 0x86,  // }  Transaction ID
  0xfa, 0x87, 0xdf, 0xae,  // }
  0x80, 0x22, 0x00, 0x0b,  //    SOFTWARE attribute header
  0x74, 0x65, 0x73, 0x74,  // }
  0x20, 0x76, 0x65, 0x63,  // }  UTF-8 server name
  0x74, 0x6f, 0x72, 0x20,  // }
  0x00, 0x20, 0x00, 0x14,  //    XOR-MAPPED-ADDRESS attribute header
  0x00, 0x02, 0xa1, 0x47,  //    Address family (IPv6) and xor'd mapped port.
  0x01, 0x13, 0xa9, 0xfa,  // }
  0xa5, 0xd3, 0xf1, 0x79,  // }  Xor'd mapped IPv6 address
  0xbc, 0x25, 0xf4, 0xb5,  // }
  0xbe, 0xd2, 0xb9, 0xd9,  // }
  0x00, 0x08, 0x00, 0x14,  //    MESSAGE-INTEGRITY attribute header
  0xa3, 0x82, 0x95, 0x4e,  // }
  0x4b, 0xe6, 0x7b, 0xf1,  // }
  0x17, 0x84, 0xc9, 0x7c,  // }  HMAC-SHA1 fingerprint
  0x82, 0x92, 0xc2, 0x75,  // }
  0xbf, 0xe3, 0xed, 0x41,  // }
  0x80, 0x28, 0x00, 0x04,  //    FINGERPRINT attribute header
  0xc8, 0xfb, 0x0b, 0x4c   //    CRC32 fingerprint
};

// 2.4.  Sample Request with Long-Term Authentication
static const unsigned char kRfc5769SampleRequestLongTermAuth[] = {
  0x00, 0x01, 0x00, 0x60,  //    Request type and message length
  0x21, 0x12, 0xa4, 0x42,  //    Magic cookie
  0x78, 0xad, 0x34, 0x33,  // }
  0xc6, 0xad, 0x72, 0xc0,  // }  Transaction ID
  0x29, 0xda, 0x41, 0x2e,  // }
  0x00, 0x06, 0x00, 0x12,  //    USERNAME attribute header
  0xe3, 0x83, 0x9e, 0xe3,  // }
  0x83, 0x88, 0xe3, 0x83,  // }
  0xaa, 0xe3, 0x83, 0x83,  // }  Username value (18 bytes) and padding (2 bytes)
  0xe3, 0x82, 0xaf, 0xe3,  // }
  0x82, 0xb9, 0x00, 0x00,  // }
  0x00, 0x15, 0x00, 0x1c,  //    NONCE attribute header
  0x66, 0x2f, 0x2f, 0x34,  // }
  0x39, 0x39, 0x6b, 0x39,  // }
  0x35, 0x34, 0x64, 0x36,  // }
  0x4f, 0x4c, 0x33, 0x34,  // }  Nonce value
  0x6f, 0x4c, 0x39, 0x46,  // }
  0x53, 0x54, 0x76, 0x79,  // }
  0x36, 0x34, 0x73, 0x41,  // }
  0x00, 0x14, 0x00, 0x0b,  //    REALM attribute header
  0x65, 0x78, 0x61, 0x6d,  // }
  0x70, 0x6c, 0x65, 0x2e,  // }  Realm value (11 bytes) and padding (1 byte)
  0x6f, 0x72, 0x67, 0x00,  // }
  0x00, 0x08, 0x00, 0x14,  //    MESSAGE-INTEGRITY attribute header
  0xf6, 0x70, 0x24, 0x65,  // }
  0x6d, 0xd6, 0x4a, 0x3e,  // }
  0x02, 0xb8, 0xe0, 0x71,  // }  HMAC-SHA1 fingerprint
  0x2e, 0x85, 0xc9, 0xa2,  // }
  0x8c, 0xa8, 0x96, 0x66   // }
};

// Length parameter is changed to 0x38 from 0x58.
// AddMessageIntegrity will add MI information and update the length param
// accordingly.
static const unsigned char kRfc5769SampleRequestWithoutMI[] = {
  0x00, 0x01, 0x00, 0x38,  //    Request type and message length
  0x21, 0x12, 0xa4, 0x42,  //    Magic cookie
  0xb7, 0xe7, 0xa7, 0x01,  // }
  0xbc, 0x34, 0xd6, 0x86,  // }  Transaction ID
  0xfa, 0x87, 0xdf, 0xae,  // }
  0x80, 0x22, 0x00, 0x10,  //    SOFTWARE attribute header
  0x53, 0x54, 0x55, 0x4e,  // }
  0x20, 0x74, 0x65, 0x73,  // }  User-agent...
  0x74, 0x20, 0x63, 0x6c,  // }  ...name
  0x69, 0x65, 0x6e, 0x74,  // }
  0x00, 0x24, 0x00, 0x04,  //    PRIORITY attribute header
  0x6e, 0x00, 0x01, 0xff,  //    ICE priority value
  0x80, 0x29, 0x00, 0x08,  //    ICE-CONTROLLED attribute header
  0x93, 0x2f, 0xf9, 0xb1,  // }  Pseudo-random tie breaker...
  0x51, 0x26, 0x3b, 0x36,  // }   ...for ICE control
  0x00, 0x06, 0x00, 0x09,  //    USERNAME attribute header
  0x65, 0x76, 0x74, 0x6a,  // }
  0x3a, 0x68, 0x36, 0x76,  // }  Username (9 bytes) and padding (3 bytes)
  0x59, 0x20, 0x20, 0x20   // }
};

// This HMAC differs from the RFC 5769 SampleRequest message. This differs
// because spec uses 0x20 for the padding where as our implementation uses 0.
static const unsigned char kCalculatedHmac1[] = {
  0x79, 0x07, 0xc2, 0xd2,  // }
  0xed, 0xbf, 0xea, 0x48,  // }
  0x0e, 0x4c, 0x76, 0xd8,  // }  HMAC-SHA1 fingerprint
  0x29, 0x62, 0xd5, 0xc3,  // }
  0x74, 0x2a, 0xf9, 0xe3   // }
};

// Length parameter is changed to 0x1c from 0x3c.
// AddMessageIntegrity will add MI information and update the length param
// accordingly.
static const unsigned char kRfc5769SampleResponseWithoutMI[] = {
  0x01, 0x01, 0x00, 0x1c,  //    Response type and message length
  0x21, 0x12, 0xa4, 0x42,  //    Magic cookie
  0xb7, 0xe7, 0xa7, 0x01,  // }
  0xbc, 0x34, 0xd6, 0x86,  // }  Transaction ID
  0xfa, 0x87, 0xdf, 0xae,  // }
  0x80, 0x22, 0x00, 0x0b,  //    SOFTWARE attribute header
  0x74, 0x65, 0x73, 0x74,  // }
  0x20, 0x76, 0x65, 0x63,  // }  UTF-8 server name
  0x74, 0x6f, 0x72, 0x20,  // }
  0x00, 0x20, 0x00, 0x08,  //    XOR-MAPPED-ADDRESS attribute header
  0x00, 0x01, 0xa1, 0x47,  //    Address family (IPv4) and xor'd mapped port
  0xe1, 0x12, 0xa6, 0x43   //    Xor'd mapped IPv4 address
};

// This HMAC differs from the RFC 5769 SampleResponse message. This differs
// because spec uses 0x20 for the padding where as our implementation uses 0.
static const unsigned char kCalculatedHmac2[] = {
  0x5d, 0x6b, 0x58, 0xbe,  // }
  0xad, 0x94, 0xe0, 0x7e,  // }
  0xef, 0x0d, 0xfc, 0x12,  // }  HMAC-SHA1 fingerprint
  0x82, 0xa2, 0xbd, 0x08,  // }
  0x43, 0x14, 0x10, 0x28   // }
};

// clang-format on

// A transaction ID without the 'magic cookie' portion
// pjnat's test programs use this transaction ID a lot.
const unsigned char kTestTransactionId1[] = {0x029, 0x01f, 0x0cd, 0x07c,
                                             0x0ba, 0x058, 0x0ab, 0x0d7,
                                             0x0f2, 0x041, 0x001, 0x000};

// They use this one sometimes too.
const unsigned char kTestTransactionId2[] = {0x0e3, 0x0a9, 0x046, 0x0e1,
                                             0x07c, 0x000, 0x0c2, 0x062,
                                             0x054, 0x008, 0x001, 0x000};

const in6_addr kIPv6TestAddress1 = {
    {{0x24, 0x01, 0xfa, 0x00, 0x00, 0x04, 0x10, 0x00, 0xbe, 0x30, 0x5b, 0xff,
      0xfe, 0xe5, 0x00, 0xc3}}};
const in6_addr kIPv6TestAddress2 = {
    {{0x24, 0x01, 0xfa, 0x00, 0x00, 0x04, 0x10, 0x12, 0x06, 0x0c, 0xce, 0xff,
      0xfe, 0x1f, 0x61, 0xa4}}};

#ifdef WEBRTC_POSIX
const in_addr kIPv4TestAddress1 = {0xe64417ac};
#elif defined WEBRTC_WIN
// Windows in_addr has a union with a uchar[] array first.
const in_addr kIPv4TestAddress1 = {{{0x0ac, 0x017, 0x044, 0x0e6}}};
#endif
const char kTestUserName1[] = "abcdefgh";
const char kTestUserName2[] = "abc";
const char kTestErrorReason[] = "Unauthorized";
const char kTestOrigin[] = "http://example.com";
const int kTestErrorClass = 4;
const int kTestErrorNumber = 1;
const int kTestErrorCode = 401;

const int kTestMessagePort1 = 59977;
const int kTestMessagePort2 = 47233;
const int kTestMessagePort3 = 56743;
const int kTestMessagePort4 = 40444;



static const uint16_t SIZE_UNDEF = 0;
static const uint16_t SIZE_IP4 = 8;
static const uint16_t SIZE_IP6 = 20;


namespace rtc {
    // These are the types of STUN addresses defined in RFC 5389.
    enum StunAddressFamily {
        // NB: UNDEF is not part of the STUN spec.
        STUN_ADDRESS_UNDEF = 0,
        STUN_ADDRESS_IPV4 = 1,
        STUN_ADDRESS_IPV6 = 2
    };
    // "GTURN"-specific STUN attributes.
    // TODO(?): Rename these attributes to GTURN_ to avoid conflicts.
    enum RelayAttributeType {
        STUN_ATTR_LIFETIME = 0x000d,             // UInt32
        STUN_ATTR_MAGIC_COOKIE = 0x000f,         // ByteString, 4 bytes
        STUN_ATTR_BANDWIDTH = 0x0010,            // UInt32
        STUN_ATTR_DESTINATION_ADDRESS = 0x0011,  // Address
        STUN_ATTR_SOURCE_ADDRESS2 = 0x0012,      // Address
        STUN_ATTR_DATA = 0x0013,                 // ByteString
        STUN_ATTR_OPTIONS = 0x8001,              // UInt32
        STUN_ATTR_XOR_ADDR = 0x0020,              // UInt32
    };
    enum StunAttributeValueType {
        STUN_VALUE_UNKNOWN = 0,
        STUN_VALUE_ADDRESS = 1,
        STUN_VALUE_XOR_ADDRESS = 2,
        STUN_VALUE_UINT32 = 3,
        STUN_VALUE_UINT64 = 4,
        STUN_VALUE_BYTE_STRING = 5,
        STUN_VALUE_ERROR_CODE = 6,
        STUN_VALUE_UINT16_LIST = 7
    };
    StunAttributeValueType GetAttributeValueType(int type)  {
        switch (type) {
            case STUN_ATTR_LIFETIME:
                return STUN_VALUE_UINT32;
            case STUN_ATTR_MAGIC_COOKIE:
                return STUN_VALUE_BYTE_STRING;
            case STUN_ATTR_BANDWIDTH:
                return STUN_VALUE_UINT32;
            case STUN_ATTR_DESTINATION_ADDRESS:
                return STUN_VALUE_ADDRESS;
            case STUN_ATTR_SOURCE_ADDRESS2:
                return STUN_VALUE_ADDRESS;
            case STUN_ATTR_DATA:
                return STUN_VALUE_BYTE_STRING;
            case STUN_ATTR_OPTIONS:
                return STUN_VALUE_UINT32;
            case STUN_ATTR_XOR_ADDR:
                return STUN_VALUE_XOR_ADDRESS;
            default:
                return STUN_VALUE_UNKNOWN;
        }
    }
    bool CreateAttribute(int type, size_t length) /*const*/ {
        StunAttributeValueType value_type = GetAttributeValueType(type);
        if (value_type != STUN_VALUE_UNKNOWN) {
            return true;
        }  else {
            return false;
        }
    }
    uint32_t ReduceTransactionId(const std::string& transaction_id) {
        ByteBufferReader reader(transaction_id.c_str(), transaction_id.length(),
                                rtc::ByteBuffer::ORDER_NETWORK);
        uint32_t result = 0;
        uint32_t next;
        while (reader.ReadUInt32(&next)) {
            result ^= next;
        }
        return result;
    }
    bool StunAddressAttribute_Read(ByteBufferReader* buf,size_t length,std::string reduced_transaction_id) {
        //XOR-MAPPED-ADDRESS和MAPPED-ADDRESS仅在传输地址的编码方面不同。
        uint8_t dummy;
        if (!buf->ReadUInt8(&dummy))
            return false;
        
        uint8_t stun_family;
        if (!buf->ReadUInt8(&stun_family)) {
            return false;
        }
        uint16_t port;
        if (!buf->ReadUInt16(&port)){
            return false;
        }
        port ^= (kStunMagicCookie >> 16);
        if (stun_family == STUN_ADDRESS_IPV4) {
            in_addr v4addr;
            if (length < SIZE_IP4) {
                return false;
            }
            if (!buf->ReadBytes(reinterpret_cast<char*>(&v4addr), sizeof(v4addr))) {
                return false;
            }
            v4addr.s_addr =
            (v4addr.s_addr ^ rtc::HostToNetwork32(kStunMagicCookie));
            IPAddress ipV4Add(v4addr);
            SocketAddress socketAddr(ipV4Add,port);
            printf("ipv4 = %s \n", socketAddr.ToString().c_str());
        } else if (stun_family == STUN_ADDRESS_IPV6) {
            in6_addr v6addr;
            //    if (length != SIZE_IP6) {
            //      return false;
            //    }
            if (!buf->ReadBytes(reinterpret_cast<char*>(&v6addr), sizeof(v6addr))) {
                return false;
            }
            const std::string& transaction_id = reduced_transaction_id;
            if (transaction_id.length() == kStunTransactionIdLength) {
                uint32_t transactionid_as_ints[3];
                memcpy(&transactionid_as_ints[0], transaction_id.c_str(),
                       transaction_id.length());
                uint32_t* ip_as_ints = reinterpret_cast<uint32_t*>(&v6addr.s6_addr);
                // Transaction ID is in network byte order, but magic cookie
                // is stored in host byte order.
                ip_as_ints[0] =
                (ip_as_ints[0] ^ rtc::HostToNetwork32(kStunMagicCookie));
                ip_as_ints[1] = (ip_as_ints[1] ^ transactionid_as_ints[0]);
                ip_as_ints[2] = (ip_as_ints[2] ^ transactionid_as_ints[1]);
                ip_as_ints[3] = (ip_as_ints[3] ^ transactionid_as_ints[2]);
            }
            IPAddress ipV6Add(v6addr);
            SocketAddress socketAddr(ipV6Add,port);
            printf("ipv6 = %s \n", socketAddr.ToString().c_str());
        } else {
            return false;
        }
        return true;
    }
    void ByteBufferTest_TestReadWriteBufferStunMsg() {
        // kRfc5769SampleResponseIPv6 kRfc5769SampleResponse
        rtc::ByteBufferReader buf(reinterpret_cast<const char*>(kRfc5769SampleResponseIPv6), sizeof(kRfc5769SampleResponseIPv6));
        uint16_t type = 0;
        if (!buf.ReadUInt16(&type))
            return;
        int version =  type & 0x8000;
        if (version) {//这里如果不是0就说明不是stun消息
            assert(false);
            return;
        }
        uint16_t length = 0;
        if (!buf.ReadUInt16(&length))
            return ;
        EXPECT_EQ(length, kStunHeaderSize);
        std::string magic_cookie;
        if (!buf.ReadString(&magic_cookie, 4))
            return ;
        //    uint32_t magic_cookie_int;
        //    if (!buf.ReadUInt32(&magic_cookie_int)) {
        //        return;
        //    }
        std::string transaction_id;
        if (!buf.ReadString(&transaction_id, 12))
            return ;
        uint32_t magic_cookie_int;
        static_assert(sizeof(magic_cookie_int) == 4,
                      "Integer size mismatch: magic_cookie_int and kStunMagicCookie");
        std::memcpy(&magic_cookie_int, magic_cookie.data(), sizeof(magic_cookie_int));
        uint32_t magicId = rtc::NetworkToHost32(magic_cookie_int);
        if (magicId != kStunMagicCookie) {
            // If magic cookie is invalid it means that the peer implements
            // RFC3489 instead of RFC5389.
            transaction_id.insert(0, magic_cookie);
        }
        uint32_t reduced_transaction_id_ = ReduceTransactionId(transaction_id);
        printf("===》 magicId: %ul reduced_transaction_id_:%ul version = %d \n",magicId,reduced_transaction_id_,version);
        EXPECT_EQ(length, buf.Length());
        size_t rest = buf.Length() - length;
        while (buf.Length() > rest) {
            uint16_t attr_type, attr_length;
            if (!buf.ReadUInt16(&attr_type))
                return ;
            if (!buf.ReadUInt16(&attr_length))
                return ;
            
            //      std::unique_ptr<StunAttribute> attr(
            //          CreateAttribute(attr_type, attr_length));
            if (!CreateAttribute(attr_type, attr_length)) {
                // Skip any unknown or malformed attributes.
                if ((attr_length % 4) != 0) {
                    attr_length += (4 - (attr_length % 4));
                }
                if(attr_type == 0x8022){
                    //
                    std::string serverName;
                    if (buf.ReadString(&serverName, attr_length)){
                        printf("SOFTWARE attribute header : %s \n",serverName.c_str());
                    }
                    
                }else if(attr_type == 0x0008){//MESSAGE-INTEGRITY attribute header
                    // HMAC-SHA1 fingerprint
                    char HMAC_SHA1[20];
                    
                    if (buf.ReadBytes(HMAC_SHA1, 20)){
                        printf("MESSAGE-INTEGRITY attribute :(HMAC-SHA1 fingerprint attr_length = %d) \n",attr_length);
                    }
                    
                }else if(attr_type == 0x8028){//FINGERPRINT attribute header
                    // CRC32 fingerprint
                    char CRC32_fingerprint[4];
                    if (buf.ReadBytes(CRC32_fingerprint, 4)){
                        printf("MESSAGE-INTEGRITY attribute :(HMAC-SHA1 fingerprint attr_length = %d) \n",attr_length);
                    }
                    
                }else{
                    if (!buf.Consume(attr_length))
                        return ;
                }
                
            } else {
                // 解析xor地址
                if (!StunAddressAttribute_Read(&buf,length,transaction_id))
                    return ;
                //        attrs_.push_back(std::move(attr));
            }
        }
        
    }
}
