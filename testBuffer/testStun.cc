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

#include "stun.h"

void printfX(const char *msg,const char *inData, size_t leng){
    char buf[256] = { 0 };
    memset(buf,0,256);
    int j=0;
    for (int idx = 0; idx < leng; idx++) {
        j += sprintf(buf+j,"%02x",(unsigned char)inData[idx]);
    }
    printf("%s %s\n",msg,buf);
    memset(buf,0,256);
}

namespace cricket {
    
        void CheckStunHeader(const StunMessage& msg,
                             StunMessageType expected_type,
                             size_t expected_length) {
            ASSERT_EQ(expected_type, msg.type());
            ASSERT_EQ(expected_length, msg.length());
        }
        
        void CheckStunTransactionID(const StunMessage& msg,
                                    const unsigned char* expectedID,
                                    size_t length) {
            ASSERT_EQ(length, msg.transaction_id().size());
            ASSERT_EQ(length == kStunTransactionIdLength + 4, msg.IsLegacy());
            ASSERT_EQ(length == kStunTransactionIdLength, !msg.IsLegacy());
            ASSERT_EQ(0, memcmp(msg.transaction_id().c_str(), expectedID, length));
        }
        
        void CheckStunAddressAttribute(const StunAddressAttribute* addr,
                                       StunAddressFamily expected_family,
                                       int expected_port,
                                       rtc::IPAddress expected_address) {
            ASSERT_EQ(expected_family, addr->family());
            ASSERT_EQ(expected_port, addr->port());
            
            if (addr->family() == STUN_ADDRESS_IPV4) {
                in_addr v4_address = expected_address.ipv4_address();
                in_addr stun_address = addr->ipaddr().ipv4_address();
                ASSERT_EQ(0, memcmp(&v4_address, &stun_address, sizeof(stun_address)));
            } else if (addr->family() == STUN_ADDRESS_IPV6) {
                in6_addr v6_address = expected_address.ipv6_address();
                in6_addr stun_address = addr->ipaddr().ipv6_address();
                ASSERT_EQ(0, memcmp(&v6_address, &stun_address, sizeof(stun_address)));
            } else {
                ASSERT_TRUE(addr->family() == STUN_ADDRESS_IPV6 ||
                            addr->family() == STUN_ADDRESS_IPV4);
            }
        }
        
        size_t ReadStunMessageTestCase(StunMessage* msg,
                                       const unsigned char* testcase,
                                       size_t size) {
            const char* input = reinterpret_cast<const char*>(testcase);
            rtc::ByteBufferReader buf(input, size);
            if (msg->Read(&buf)) {
                // Returns the size the stun message should report itself as being
                return (size - 20);
            } else {
                return 0;
            }
        }
}

using namespace cricket;

// Sample STUN packets with various attributes
// Gathered by wiresharking pjproject's pjnath test programs
// pjproject available at www.pjsip.org

// clang-format off
// clang formatting doesn't respect inline comments.

static const unsigned char kStunMessageWithIPv6MappedAddress[] = {
  0x00, 0x01, 0x00, 0x18,  // message header
  0x21, 0x12, 0xa4, 0x42,  // transaction id
  0x29, 0x1f, 0xcd, 0x7c,
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x14,  // Address type (mapped), length
  0x00, 0x02, 0xb8, 0x81,  // family (IPv6), port
  0x24, 0x01, 0xfa, 0x00,  // an IPv6 address
  0x00, 0x04, 0x10, 0x00,
  0xbe, 0x30, 0x5b, 0xff,
  0xfe, 0xe5, 0x00, 0xc3
};

static const unsigned char kStunMessageWithIPv4MappedAddress[] = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x08,  // Mapped, 8 byte length
  0x00, 0x01, 0x9d, 0xfc,  // AF_INET, unxor-ed port
  0xac, 0x17, 0x44, 0xe6   // IPv4 address
};

// Test XOR-mapped IP addresses:
static const unsigned char kStunMessageWithIPv6XorMappedAddress[] = {
  0x01, 0x01, 0x00, 0x18,  // message header (binding response)
  0x21, 0x12, 0xa4, 0x42,  // magic cookie (rfc5389)
  0xe3, 0xa9, 0x46, 0xe1,  // transaction ID
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0x20, 0x00, 0x14,  // Address Type (XOR), length
  0x00, 0x02, 0xcb, 0x5b,  // family, XOR-ed port
  0x05, 0x13, 0x5e, 0x42,  // XOR-ed IPv6 address
  0xe3, 0xad, 0x56, 0xe1,
  0xc2, 0x30, 0x99, 0x9d,
  0xaa, 0xed, 0x01, 0xc3
};

static const unsigned char kStunMessageWithIPv4XorMappedAddress[] = {
  0x01, 0x01, 0x00, 0x0c,  // message header (binding response)
  0x21, 0x12, 0xa4, 0x42,  // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,  // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x20, 0x00, 0x08,  // address type (xor), length
  0x00, 0x01, 0xfc, 0xb5,  // family (AF_INET), XOR-ed port
  0x8d, 0x05, 0xe0, 0xa4   // IPv4 address
};

// ByteString Attribute (username)
static const unsigned char kStunMessageWithByteStringAttribute[] = {
  0x00, 0x01, 0x00, 0x0c,
  0x21, 0x12, 0xa4, 0x42,
  0xe3, 0xa9, 0x46, 0xe1,
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0x06, 0x00, 0x08,  // username attribute (length 8)
  0x61, 0x62, 0x63, 0x64,  // abcdefgh
  0x65, 0x66, 0x67, 0x68
};

// Message with an unknown but comprehensible optional attribute.
// Parsing should succeed despite this unknown attribute.
static const unsigned char kStunMessageWithUnknownAttribute[] = {
  0x00, 0x01, 0x00, 0x14,
  0x21, 0x12, 0xa4, 0x42,
  0xe3, 0xa9, 0x46, 0xe1,
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0xaa, 0x00, 0x07,  // Unknown attribute, length 7 (needs padding!)
  0x61, 0x62, 0x63, 0x64,  // abcdefg + padding
  0x65, 0x66, 0x67, 0x00,
  0x00, 0x06, 0x00, 0x03,  // Followed by a known attribute we can
  0x61, 0x62, 0x63, 0x00   // check for (username of length 3)
};

// ByteString Attribute (username) with padding byte
static const unsigned char kStunMessageWithPaddedByteStringAttribute[] = {
  0x00, 0x01, 0x00, 0x08,
  0x21, 0x12, 0xa4, 0x42,
  0xe3, 0xa9, 0x46, 0xe1,
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0x06, 0x00, 0x03,  // username attribute (length 3)
  0x61, 0x62, 0x63, 0xcc   // abc
};

// Message with an Unknown Attributes (uint16_t list) attribute.
static const unsigned char kStunMessageWithUInt16ListAttribute[] = {
  0x00, 0x01, 0x00, 0x0c,
  0x21, 0x12, 0xa4, 0x42,
  0xe3, 0xa9, 0x46, 0xe1,
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0x0a, 0x00, 0x06,  // username attribute (length 6)
  0x00, 0x01, 0x10, 0x00,  // three attributes plus padding
  0xAB, 0xCU, 0xBE, 0xEF
};

// Error response message (unauthorized)
static const unsigned char kStunMessageWithErrorAttribute[] = {
  0x01, 0x11, 0x00, 0x14,
  0x21, 0x12, 0xa4, 0x42,
  0x29, 0x1f, 0xcd, 0x7c,
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x09, 0x00, 0x10,
  0x00, 0x00, 0x04, 0x01,
  0x55, 0x6e, 0x61, 0x75,
  0x74, 0x68, 0x6f, 0x72,
  0x69, 0x7a, 0x65, 0x64
};

static const unsigned char kStunMessageWithOriginAttribute[] = {
  0x00, 0x01, 0x00, 0x18,  // message header (binding request), length 24
  0x21, 0x12, 0xA4, 0x42,  // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,  // transaction id
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x80, 0x2f, 0x00, 0x12,  // origin attribute (length 18)
  0x68, 0x74, 0x74, 0x70,  // http://example.com
  0x3A, 0x2F, 0x2F, 0x65,
  0x78, 0x61, 0x6d, 0x70,
  0x6c, 0x65, 0x2e, 0x63,
  0x6f, 0x6d, 0x00, 0x00,
};

// Sample messages with an invalid length Field

// The actual length in bytes of the invalid messages (including STUN header)
static const int kRealLengthOfInvalidLengthTestCases = 32;

static const unsigned char kStunMessageWithZeroLength[] = {
  0x00, 0x01, 0x00, 0x00,  // length of 0 (last 2 bytes)
  0x21, 0x12, 0xA4, 0x42,  // magic cookie
  '0', '1', '2', '3',      // transaction id
  '4', '5', '6', '7',
  '8', '9', 'a', 'b',
  0x00, 0x20, 0x00, 0x08,  // xor mapped address
  0x00, 0x01, 0x21, 0x1F,
  0x21, 0x12, 0xA4, 0x53,
};

static const unsigned char kStunMessageWithExcessLength[] = {
  0x00, 0x01, 0x00, 0x55,  // length of 85
  0x21, 0x12, 0xA4, 0x42,  // magic cookie
  '0', '1', '2', '3',      // transaction id
  '4', '5', '6', '7',
  '8', '9', 'a', 'b',
  0x00, 0x20, 0x00, 0x08,  // xor mapped address
  0x00, 0x01, 0x21, 0x1F,
  0x21, 0x12, 0xA4, 0x53,
};

static const unsigned char kStunMessageWithSmallLength[] = {
  0x00, 0x01, 0x00, 0x03,  // length of 3
  0x21, 0x12, 0xA4, 0x42,  // magic cookie
  '0', '1', '2', '3',      // transaction id
  '4', '5', '6', '7',
  '8', '9', 'a', 'b',
  0x00, 0x20, 0x00, 0x08,  // xor mapped address
  0x00, 0x01, 0x21, 0x1F,
  0x21, 0x12, 0xA4, 0x53,
};

static const unsigned char kStunMessageWithBadHmacAtEnd[] = {
  0x00, 0x01, 0x00, 0x14,  // message length exactly 20
  0x21, 0x12, 0xA4, 0x42,  // magic cookie
  '0', '1', '2', '3',      // transaction ID
  '4', '5', '6', '7',
  '8', '9', 'a', 'b',
  0x00, 0x08, 0x00, 0x14,  // type=STUN_ATTR_MESSAGE_INTEGRITY, length=20
  '0', '0', '0', '0',      // We lied, there are only 16 bytes of HMAC.
  '0', '0', '0', '0',
  '0', '0', '0', '0',
  '0', '0', '0', '0',
};

// RTCP packet, for testing we correctly ignore non stun packet types.
// V=2, P=false, RC=0, Type=200, Len=6, Sender-SSRC=85, etc
static const unsigned char kRtcpPacket[] = {
  0x80, 0xc8, 0x00, 0x06, 0x00, 0x00, 0x00, 0x55,
  0xce, 0xa5, 0x18, 0x3a, 0x39, 0xcc, 0x7d, 0x09,
  0x23, 0xed, 0x19, 0x07, 0x00, 0x00, 0x01, 0x56,
  0x00, 0x03, 0x73, 0x50,
};


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
static const rtc::SocketAddress kRfc5769SampleMsgMappedAddress(
    "192.0.2.1", 32853);
static const rtc::SocketAddress kRfc5769SampleMsgIPv6MappedAddress(
    "2001:db8:1234:5678:11:2233:4455:6677", 32853);

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

#define ReadStunMessage(X, Y) ReadStunMessageTestCase(X, Y, sizeof(Y));


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
        port ^= (cricket::kStunMagicCookie >> 16);
        if (stun_family == STUN_ADDRESS_IPV4) {
            in_addr v4addr;
            if (length < SIZE_IP4) {
                return false;
            }
            if (!buf->ReadBytes(reinterpret_cast<char*>(&v4addr), sizeof(v4addr))) {
                return false;
            }
            v4addr.s_addr =
            (v4addr.s_addr ^ rtc::HostToNetwork32(cricket::kStunMagicCookie));
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
            if (transaction_id.length() == cricket::kStunTransactionIdLength) {
                uint32_t transactionid_as_ints[3];
                memcpy(&transactionid_as_ints[0], transaction_id.c_str(),
                       transaction_id.length());
                uint32_t* ip_as_ints = reinterpret_cast<uint32_t*>(&v6addr.s6_addr);
                // Transaction ID is in network byte order, but magic cookie
                // is stored in host byte order.
                ip_as_ints[0] =
                (ip_as_ints[0] ^ rtc::HostToNetwork32(cricket::kStunMagicCookie));
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
//        EXPECT_EQ(length, cricket::kStunHeaderSize);
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
        if (magicId != cricket::kStunMagicCookie) {
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
    
    
    
    
    // Read the RFC5389 fields from the RFC5769 sample STUN request.
  void  StunTest_ReadRfc5769RequestMessage() {
      StunMessage msg;
      size_t size = ReadStunMessage(&msg, kRfc5769SampleRequest);
      CheckStunHeader(msg, STUN_BINDING_REQUEST, size);
      CheckStunTransactionID(msg, kRfc5769SampleMsgTransactionId,
                             kStunTransactionIdLength);

      const StunByteStringAttribute* software =
          msg.GetByteString(STUN_ATTR_SOFTWARE);
      ASSERT_TRUE(software != NULL);
      EXPECT_EQ(kRfc5769SampleMsgClientSoftware, software->GetString());

      const StunByteStringAttribute* username =
          msg.GetByteString(STUN_ATTR_USERNAME);
      ASSERT_TRUE(username != NULL);
      EXPECT_EQ(kRfc5769SampleMsgUsername, username->GetString());

      // Actual M-I value checked in a later test.
      ASSERT_TRUE(msg.GetByteString(STUN_ATTR_MESSAGE_INTEGRITY) != NULL);

      // Fingerprint checked in a later test, but double-check the value here.
      const StunUInt32Attribute* fingerprint = msg.GetUInt32(STUN_ATTR_FINGERPRINT);
      ASSERT_TRUE(fingerprint != NULL);
      EXPECT_EQ(0xe57a3bcf, fingerprint->value());
    }

    // Read the RFC5389 fields from the RFC5769 sample STUN response.
  void  StunTest_ReadRfc5769ResponseMessage() {
      StunMessage msg;
      size_t size = ReadStunMessage(&msg, kRfc5769SampleResponse);
      CheckStunHeader(msg, STUN_BINDING_RESPONSE, size);
      CheckStunTransactionID(msg, kRfc5769SampleMsgTransactionId,
                             kStunTransactionIdLength);

      const StunByteStringAttribute* software =
          msg.GetByteString(STUN_ATTR_SOFTWARE);
      ASSERT_TRUE(software != NULL);
      EXPECT_EQ(kRfc5769SampleMsgServerSoftware, software->GetString());

      const StunAddressAttribute* mapped_address =
          msg.GetAddress(STUN_ATTR_XOR_MAPPED_ADDRESS);
      ASSERT_TRUE(mapped_address != NULL);
      EXPECT_EQ(kRfc5769SampleMsgMappedAddress, mapped_address->GetAddress());

      // Actual M-I and fingerprint checked in later tests.
      ASSERT_TRUE(msg.GetByteString(STUN_ATTR_MESSAGE_INTEGRITY) != NULL);
      ASSERT_TRUE(msg.GetUInt32(STUN_ATTR_FINGERPRINT) != NULL);
    }

    // Read the RFC5389 fields from the RFC5769 sample STUN response for IPv6.
  void  StunTest_ReadRfc5769ResponseMessageIPv6() {
      StunMessage msg;
      size_t size = ReadStunMessage(&msg, kRfc5769SampleResponseIPv6);
      CheckStunHeader(msg, STUN_BINDING_RESPONSE, size);
      CheckStunTransactionID(msg, kRfc5769SampleMsgTransactionId,
                             kStunTransactionIdLength);

      const StunByteStringAttribute* software =
          msg.GetByteString(STUN_ATTR_SOFTWARE);
      ASSERT_TRUE(software != NULL);
      EXPECT_EQ(kRfc5769SampleMsgServerSoftware, software->GetString());

      const StunAddressAttribute* mapped_address =
          msg.GetAddress(STUN_ATTR_XOR_MAPPED_ADDRESS);
      ASSERT_TRUE(mapped_address != NULL);
      EXPECT_EQ(kRfc5769SampleMsgIPv6MappedAddress, mapped_address->GetAddress());

      // Actual M-I and fingerprint checked in later tests.
      ASSERT_TRUE(msg.GetByteString(STUN_ATTR_MESSAGE_INTEGRITY) != NULL);
      ASSERT_TRUE(msg.GetUInt32(STUN_ATTR_FINGERPRINT) != NULL);
    }

    // Read the RFC5389 fields from the RFC5769 sample STUN response with auth.
    void  StunTest_ReadRfc5769RequestMessageLongTermAuth() {
      StunMessage msg;
      size_t size = ReadStunMessage(&msg, kRfc5769SampleRequestLongTermAuth);
      CheckStunHeader(msg, STUN_BINDING_REQUEST, size);
      CheckStunTransactionID(msg, kRfc5769SampleMsgWithAuthTransactionId,
                             kStunTransactionIdLength);

      const StunByteStringAttribute* username =
          msg.GetByteString(STUN_ATTR_USERNAME);
      ASSERT_TRUE(username != NULL);
      EXPECT_EQ(kRfc5769SampleMsgWithAuthUsername, username->GetString());

      const StunByteStringAttribute* nonce = msg.GetByteString(STUN_ATTR_NONCE);
      ASSERT_TRUE(nonce != NULL);
      EXPECT_EQ(kRfc5769SampleMsgWithAuthNonce, nonce->GetString());

      const StunByteStringAttribute* realm = msg.GetByteString(STUN_ATTR_REALM);
      ASSERT_TRUE(realm != NULL);
      EXPECT_EQ(kRfc5769SampleMsgWithAuthRealm, realm->GetString());

      // No fingerprint, actual M-I checked in later tests.
      ASSERT_TRUE(msg.GetByteString(STUN_ATTR_MESSAGE_INTEGRITY) != NULL);
      ASSERT_TRUE(msg.GetUInt32(STUN_ATTR_FINGERPRINT) == NULL);
    }

    // The RFC3489 packet in this test is the same as
    // kStunMessageWithIPv4MappedAddress, but with a different value where the
    // magic cookie was.
    void  StunTest_ReadLegacyMessage() {
      unsigned char rfc3489_packet[sizeof(kStunMessageWithIPv4MappedAddress)];
      memcpy(rfc3489_packet, kStunMessageWithIPv4MappedAddress,
             sizeof(kStunMessageWithIPv4MappedAddress));
      // Overwrite the magic cookie here.
      memcpy(&rfc3489_packet[4], "ABCD", 4);

      StunMessage msg;
      size_t size = ReadStunMessage(&msg, rfc3489_packet);
      CheckStunHeader(msg, STUN_BINDING_RESPONSE, size);
      CheckStunTransactionID(msg, &rfc3489_packet[4], kStunTransactionIdLength + 4);

      const StunAddressAttribute* addr = msg.GetAddress(STUN_ATTR_MAPPED_ADDRESS);
      rtc::IPAddress test_address(kIPv4TestAddress1);
//        CheckStunAddressAttribute(<#const StunAddressAttribute *addr#>, <#StunAddressFamily expected_family#>, <#int expected_port#>, <#rtc::IPAddress expected_address#>)
        cricket::CheckStunAddressAttribute(addr, cricket::STUN_ADDRESS_IPV4, kTestMessagePort4,
                                test_address);
    }
    
    
    
    // Check our STUN message validation code against the RFC5769 test messages.
    void  StunTest_ValidateMessageIntegrity() {
      // Try the messages from RFC 5769.
      EXPECT_TRUE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kRfc5769SampleRequest),
          sizeof(kRfc5769SampleRequest), kRfc5769SampleMsgPassword));
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kRfc5769SampleRequest),
          sizeof(kRfc5769SampleRequest), "InvalidPassword"));

      EXPECT_TRUE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kRfc5769SampleResponse),
          sizeof(kRfc5769SampleResponse), kRfc5769SampleMsgPassword));
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kRfc5769SampleResponse),
          sizeof(kRfc5769SampleResponse), "InvalidPassword"));

      EXPECT_TRUE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kRfc5769SampleResponseIPv6),
          sizeof(kRfc5769SampleResponseIPv6), kRfc5769SampleMsgPassword));
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kRfc5769SampleResponseIPv6),
          sizeof(kRfc5769SampleResponseIPv6), "InvalidPassword"));

      // We first need to compute the key for the long-term authentication HMAC.
      std::string key;
      ComputeStunCredentialHash(kRfc5769SampleMsgWithAuthUsername,
                                kRfc5769SampleMsgWithAuthRealm,
                                kRfc5769SampleMsgWithAuthPassword, &key);
        /*
         MD5加密文本：lym:example.org:123456
         turnKey = 8812c1afb0e203aae88c996e30ac7db6
         unsigned char  data[7] = "123456";
         hmac_sha1加密后数据 = b103f699ef12c04ab6f0cb155ac2f12ef84adf22
         */
        printfX("StunTest_ValidateMessageIntegrity MD5 ",key.c_str(), key.length());
      EXPECT_TRUE(StunMessage::ValidateMessageIntegrity(
               reinterpret_cast<const char*>(kRfc5769SampleRequestLongTermAuth),
                sizeof(kRfc5769SampleRequestLongTermAuth), key));
        
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kRfc5769SampleRequestLongTermAuth),
          sizeof(kRfc5769SampleRequestLongTermAuth), "InvalidPassword"));

      // Try some edge cases.
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kStunMessageWithZeroLength),
          sizeof(kStunMessageWithZeroLength), kRfc5769SampleMsgPassword));
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kStunMessageWithExcessLength),
          sizeof(kStunMessageWithExcessLength), kRfc5769SampleMsgPassword));
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kStunMessageWithSmallLength),
          sizeof(kStunMessageWithSmallLength), kRfc5769SampleMsgPassword));

      // Again, but with the lengths matching what is claimed in the headers.
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kStunMessageWithZeroLength),
          kStunHeaderSize + rtc::GetBE16(&kStunMessageWithZeroLength[2]),
          kRfc5769SampleMsgPassword));
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kStunMessageWithExcessLength),
          kStunHeaderSize + rtc::GetBE16(&kStunMessageWithExcessLength[2]),
          kRfc5769SampleMsgPassword));
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kStunMessageWithSmallLength),
          kStunHeaderSize + rtc::GetBE16(&kStunMessageWithSmallLength[2]),
          kRfc5769SampleMsgPassword));

      // Check that a too-short HMAC doesn't cause buffer overflow.
      EXPECT_FALSE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(kStunMessageWithBadHmacAtEnd),
          sizeof(kStunMessageWithBadHmacAtEnd), kRfc5769SampleMsgPassword));

      // Test that munging a single bit anywhere in the message causes the
      // message-integrity check to fail, unless it is after the M-I attribute.
      char buf[sizeof(kRfc5769SampleRequest)];
      memcpy(buf, kRfc5769SampleRequest, sizeof(kRfc5769SampleRequest));
      for (size_t i = 0; i < sizeof(buf); ++i) {
        buf[i] ^= 0x01;
        if (i > 0)
          buf[i - 1] ^= 0x01;
        EXPECT_EQ(i >= sizeof(buf) - 8,
                  StunMessage::ValidateMessageIntegrity(buf, sizeof(buf),
                                                        kRfc5769SampleMsgPassword));
      }
    }

    // Validate that we generate correct MESSAGE-INTEGRITY attributes.
    // Note the use of IceMessage instead of StunMessage; this is necessary because
    // the RFC5769 test messages used include attributes not found in basic STUN.
    void  StunTest_AddMessageIntegrity() {
//        // We first need to compute the key for the long-term authentication HMAC.
//        std::string key;
//        ComputeStunCredentialHash(kRfc5769SampleMsgWithAuthUsername,
//                                  kRfc5769SampleMsgWithAuthRealm,
//                                  kRfc5769SampleMsgWithAuthPassword, &key);
//          /*
//           MD5加密文本：lym:example.org:123456
//           turnKey = 8812c1afb0e203aae88c996e30ac7db6
//           unsigned char  data[7] = "123456";
//           hmac_sha1加密后数据 = b103f699ef12c04ab6f0cb155ac2f12ef84adf22
//           */
//          unsigned char  data[7] = "123456";
//          printfX(key.c_str(), key.length());
      IceMessage msg;
      rtc::ByteBufferReader buf(
          reinterpret_cast<const char*>(kRfc5769SampleRequestWithoutMI),
          sizeof(kRfc5769SampleRequestWithoutMI));
      EXPECT_TRUE(msg.Read(&buf));
      EXPECT_TRUE(msg.AddMessageIntegrity(kRfc5769SampleMsgPassword));
      const StunByteStringAttribute* mi_attr =
          msg.GetByteString(STUN_ATTR_MESSAGE_INTEGRITY);
        printfX("StunTest_AddMessageIntegrity MD5 ",mi_attr->bytes(), mi_attr->length());
        printfX("StunTest_AddMessageIntegrity MD5 ",(const char *)kCalculatedHmac1, sizeof(kCalculatedHmac1));
      EXPECT_EQ(20U, mi_attr->length());
      EXPECT_EQ(
          0, memcmp(mi_attr->bytes(), kCalculatedHmac1, sizeof(kCalculatedHmac1)));

      rtc::ByteBufferWriter buf1;
      EXPECT_TRUE(msg.Write(&buf1));
      EXPECT_TRUE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(buf1.Data()), buf1.Length(),
          kRfc5769SampleMsgPassword));

      IceMessage msg2;
      rtc::ByteBufferReader buf2(
          reinterpret_cast<const char*>(kRfc5769SampleResponseWithoutMI),
          sizeof(kRfc5769SampleResponseWithoutMI));
      EXPECT_TRUE(msg2.Read(&buf2));
      EXPECT_TRUE(msg2.AddMessageIntegrity(kRfc5769SampleMsgPassword));
      const StunByteStringAttribute* mi_attr2 =
          msg2.GetByteString(STUN_ATTR_MESSAGE_INTEGRITY);
      EXPECT_EQ(20U, mi_attr2->length());
      EXPECT_EQ(
          0, memcmp(mi_attr2->bytes(), kCalculatedHmac2, sizeof(kCalculatedHmac2)));

      rtc::ByteBufferWriter buf3;
      EXPECT_TRUE(msg2.Write(&buf3));
      EXPECT_TRUE(StunMessage::ValidateMessageIntegrity(
          reinterpret_cast<const char*>(buf3.Data()), buf3.Length(),
          kRfc5769SampleMsgPassword));
    }

    // Check our STUN message validation code against the RFC5769 test messages.
    void  StunTest_ValidateFingerprint() {
      EXPECT_TRUE(StunMessage::ValidateFingerprint(
          reinterpret_cast<const char*>(kRfc5769SampleRequest),
          sizeof(kRfc5769SampleRequest)));
      EXPECT_TRUE(StunMessage::ValidateFingerprint(
          reinterpret_cast<const char*>(kRfc5769SampleResponse),
          sizeof(kRfc5769SampleResponse)));
      EXPECT_TRUE(StunMessage::ValidateFingerprint(
          reinterpret_cast<const char*>(kRfc5769SampleResponseIPv6),
          sizeof(kRfc5769SampleResponseIPv6)));

      EXPECT_FALSE(StunMessage::ValidateFingerprint(
          reinterpret_cast<const char*>(kStunMessageWithZeroLength),
          sizeof(kStunMessageWithZeroLength)));
      EXPECT_FALSE(StunMessage::ValidateFingerprint(
          reinterpret_cast<const char*>(kStunMessageWithExcessLength),
          sizeof(kStunMessageWithExcessLength)));
      EXPECT_FALSE(StunMessage::ValidateFingerprint(
          reinterpret_cast<const char*>(kStunMessageWithSmallLength),
          sizeof(kStunMessageWithSmallLength)));

      // Test that munging a single bit anywhere in the message causes the
      // fingerprint check to fail.
      char buf[sizeof(kRfc5769SampleRequest)];
      memcpy(buf, kRfc5769SampleRequest, sizeof(kRfc5769SampleRequest));
      for (size_t i = 0; i < sizeof(buf); ++i) {
        buf[i] ^= 0x01;
        if (i > 0)
          buf[i - 1] ^= 0x01;
        EXPECT_FALSE(StunMessage::ValidateFingerprint(buf, sizeof(buf)));
      }
      // Put them all back to normal and the check should pass again.
      buf[sizeof(buf) - 1] ^= 0x01;
      EXPECT_TRUE(StunMessage::ValidateFingerprint(buf, sizeof(buf)));
    }

    void  StunTest_AddFingerprint( ) {
      IceMessage msg;
      rtc::ByteBufferReader buf(
          reinterpret_cast<const char*>(kRfc5769SampleRequestWithoutMI),
          sizeof(kRfc5769SampleRequestWithoutMI));
      EXPECT_TRUE(msg.Read(&buf));
      EXPECT_TRUE(msg.AddFingerprint());

      rtc::ByteBufferWriter buf1;
      EXPECT_TRUE(msg.Write(&buf1));
      EXPECT_TRUE(StunMessage::ValidateFingerprint(
          reinterpret_cast<const char*>(buf1.Data()), buf1.Length()));
    }
} // namespace end
