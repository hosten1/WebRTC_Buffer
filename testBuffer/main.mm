//
//  main.m
//  testBuffer
//
//  Created by luoyongmeng on 2023/2/17.
//

#import <Foundation/Foundation.h>
#include<stdio.h>
#import "byte_order.h"
#import "byte_buffer.h"

#import "bit_buffer.h"

#include <stddef.h>
#include <limits>

#include <assert.h>


#define  EXPECT_EQ(a,b) \
if (a != b) {\
    printf("");\
   assert( true );\
}

#define  EXPECT_TRUE(a) \
if (!a) {\
    printf("");\
    assert( true ); \
}
#define  EXPECT_FALSE(a) \
if (a) {\
    printf("");\
    assert( true ); \
}


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
// This file defines the arraysize() macro and is derived from Chromium's
// base/macros.h.

// The arraysize(arr) macro returns the # of elements in an array arr.
// The expression is a compile-time constant, and therefore can be
// used in defining new arrays, for example.  If you use arraysize on
// a pointer by mistake, you will get a compile-time error.

// This template function declaration is used in defining arraysize.
// Note that the function doesn't need an implementation, as we only
// use its type.
template <typename T, size_t N>
char (&ArraySizeHelper(T (&array)[N]))[N];

#define arraysize(array) (sizeof(ArraySizeHelper(array)))
using namespace rtc;

void BitBufferTest_ConsumeBits() {
  const uint8_t bytes[64] = {0};
  BitBuffer buffer(bytes, 32);
  uint64_t total_bits = 32 * 8;
  EXPECT_EQ(total_bits, buffer.RemainingBitCount());
  EXPECT_TRUE(buffer.ConsumeBits(3));
  total_bits -= 3;
  EXPECT_EQ(total_bits, buffer.RemainingBitCount());
  EXPECT_TRUE(buffer.ConsumeBits(3));
  total_bits -= 3;
  EXPECT_EQ(total_bits, buffer.RemainingBitCount());
  EXPECT_TRUE(buffer.ConsumeBits(15));
  total_bits -= 15;
  EXPECT_EQ(total_bits, buffer.RemainingBitCount());
  EXPECT_TRUE(buffer.ConsumeBits(37));
  total_bits -= 37;
  EXPECT_EQ(total_bits, buffer.RemainingBitCount());

  EXPECT_FALSE(buffer.ConsumeBits(32 * 8));
  EXPECT_EQ(total_bits, buffer.RemainingBitCount());
}

void BitBufferTest_ReadBytesAligned() {
  const uint8_t bytes[] = {0x0A, 0xBC, 0xDE, 0xF1, 0x23, 0x45, 0x67, 0x89};
  uint8_t val8;
  uint16_t val16;
  uint32_t val32;
  BitBuffer buffer(bytes, 8);
  EXPECT_TRUE(buffer.ReadUInt8(&val8));
  EXPECT_EQ(0x0Au, val8);
  EXPECT_TRUE(buffer.ReadUInt8(&val8));
  EXPECT_EQ(0xBCu, val8);
  EXPECT_TRUE(buffer.ReadUInt16(&val16));
  EXPECT_EQ(0xDEF1u, val16);
  EXPECT_TRUE(buffer.ReadUInt32(&val32));
  EXPECT_EQ(0x23456789u, val32);
}

void BitBufferTest_ReadBytesOffset4() {
  const uint8_t bytes[] = {0x0A, 0xBC, 0xDE, 0xF1, 0x23,
                           0x45, 0x67, 0x89, 0x0A};
  uint8_t val8;
  uint16_t val16;
  uint32_t val32;
  BitBuffer buffer(bytes, 9);
  EXPECT_TRUE(buffer.ConsumeBits(4));

  EXPECT_TRUE(buffer.ReadUInt8(&val8));
  EXPECT_EQ(0xABu, val8);
  EXPECT_TRUE(buffer.ReadUInt8(&val8));
  EXPECT_EQ(0xCDu, val8);
  EXPECT_TRUE(buffer.ReadUInt16(&val16));
  EXPECT_EQ(0xEF12u, val16);
  EXPECT_TRUE(buffer.ReadUInt32(&val32));
  EXPECT_EQ(0x34567890u, val32);
}

void BitBufferTest_ReadBytesOffset3() {
  // The pattern we'll check against is counting down from 0b1111. It looks
  // weird here because it's all offset by 3.
  // Byte pattern is:
  //    56701234
  //  0b00011111,
  //  0b11011011,
  //  0b10010111,
  //  0b01010011,
  //  0b00001110,
  //  0b11001010,
  //  0b10000110,
  //  0b01000010
  //       xxxxx <-- last 5 bits unused.

  // The bytes. It almost looks like counting down by two at a time, except the
  // jump at 5->3->0, since that's when the high bit is turned off.
  const uint8_t bytes[] = {0x1F, 0xDB, 0x97, 0x53, 0x0E, 0xCA, 0x86, 0x42};

  uint8_t val8;
  uint16_t val16;
  uint32_t val32;
  BitBuffer buffer(bytes, 8);
  EXPECT_TRUE(buffer.ConsumeBits(3));
  EXPECT_TRUE(buffer.ReadUInt8(&val8));
  EXPECT_EQ(0xFEu, val8);
  EXPECT_TRUE(buffer.ReadUInt16(&val16));
  EXPECT_EQ(0xDCBAu, val16);
  EXPECT_TRUE(buffer.ReadUInt32(&val32));
  EXPECT_EQ(0x98765432u, val32);
  // 5 bits left unread. Not enough to read a uint8_t.
  EXPECT_EQ(5u, buffer.RemainingBitCount());
  EXPECT_FALSE(buffer.ReadUInt8(&val8));
}

void BitBufferTest_ReadBits() {
  // Bit values are:
  //  0b01001101,
  //  0b00110010
  const uint8_t bytes[] = {0x4D, 0x32};
  uint32_t val;
  BitBuffer buffer(bytes, 2);
  EXPECT_TRUE(buffer.ReadBits(&val, 3));
  // 0b010
  EXPECT_EQ(0x2u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 2));
  // 0b01
  EXPECT_EQ(0x1u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 7));
  // 0b1010011
  EXPECT_EQ(0x53u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 2));
  // 0b00
  EXPECT_EQ(0x0u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 1));
  // 0b1
  EXPECT_EQ(0x1u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 1));
  // 0b0
  EXPECT_EQ(0x0u, val);

  EXPECT_FALSE(buffer.ReadBits(&val, 1));
}

void BitBufferTest_SetOffsetValues() {
  uint8_t bytes[4] = {0};
  BitBufferWriter buffer(bytes, 4);

  size_t byte_offset, bit_offset;
  // Bit offsets are [0,7].
  EXPECT_TRUE(buffer.Seek(0, 0));
  EXPECT_TRUE(buffer.Seek(0, 7));
  buffer.GetCurrentOffset(&byte_offset, &bit_offset);
  EXPECT_EQ(0u, byte_offset);
  EXPECT_EQ(7u, bit_offset);
  EXPECT_FALSE(buffer.Seek(0, 8));
  buffer.GetCurrentOffset(&byte_offset, &bit_offset);
  EXPECT_EQ(0u, byte_offset);
  EXPECT_EQ(7u, bit_offset);
  // Byte offsets are [0,length]. At byte offset length, the bit offset must be
  // 0.
  EXPECT_TRUE(buffer.Seek(0, 0));
  EXPECT_TRUE(buffer.Seek(2, 4));
  buffer.GetCurrentOffset(&byte_offset, &bit_offset);
  EXPECT_EQ(2u, byte_offset);
  EXPECT_EQ(4u, bit_offset);
  EXPECT_TRUE(buffer.Seek(4, 0));
  EXPECT_FALSE(buffer.Seek(5, 0));
  buffer.GetCurrentOffset(&byte_offset, &bit_offset);
  EXPECT_EQ(4u, byte_offset);
  EXPECT_EQ(0u, bit_offset);
  EXPECT_FALSE(buffer.Seek(4, 1));

// Disable death test on Android because it relies on fork() and doesn't play
// nicely.
#if GTEST_HAS_DEATH_TEST
#if !defined(WEBRTC_ANDROID)
  // Passing a null out parameter is death.
  EXPECT_DEATH(buffer.GetCurrentOffset(&byte_offset, nullptr), "");
#endif
#endif
}

uint64_t GolombEncoded(uint32_t val) {
  val++;
  uint32_t bit_counter = val;
  uint64_t bit_count = 0;
  while (bit_counter > 0) {
    bit_count++;
    bit_counter >>= 1;
  }
  return static_cast<uint64_t>(val) << (64 - (bit_count * 2 - 1));
}

void BitBufferTest_GolombUint32Values() {
  ByteBufferWriter byteBuffer;
  byteBuffer.Resize(16);
  BitBuffer buffer(reinterpret_cast<const uint8_t*>(byteBuffer.Data()),
                   byteBuffer.Capacity());
  // Test over the uint32_t range with a large enough step that the test doesn't
  // take forever. Around 20,000 iterations should do.
  const int kStep = std::numeric_limits<uint32_t>::max() / 20000;
  for (uint32_t i = 0; i < std::numeric_limits<uint32_t>::max() - kStep;
       i += kStep) {
    uint64_t encoded_val = GolombEncoded(i);
    byteBuffer.Clear();
    byteBuffer.WriteUInt64(encoded_val);
    uint32_t decoded_val;
    EXPECT_TRUE(buffer.Seek(0, 0));
    EXPECT_TRUE(buffer.ReadExponentialGolomb(&decoded_val));
    EXPECT_EQ(i, decoded_val);
  }
}

void BitBufferTest_SignedGolombValues() {
  uint8_t golomb_bits[] = {
      0x80,  // 1
      0x40,  // 010
      0x60,  // 011
      0x20,  // 00100
      0x38,  // 00111
  };
  int32_t expected[] = {0, 1, -1, 2, -3};
  for (size_t i = 0; i < sizeof(golomb_bits); ++i) {
    BitBuffer buffer(&golomb_bits[i], 1);
    int32_t decoded_val;
//    ASSERT_TRUE(buffer.ReadSignedExponentialGolomb(&decoded_val));
//    EXPECT_EQ(expected[i], decoded_val) << "Mismatch in expected/decoded value for golomb_bits[" << i << "]: " << static_cast<int>(golomb_bits[i]);
  }
}

void BitBufferTest_NoGolombOverread() {
  const uint8_t bytes[] = {0x00, 0xFF, 0xFF};
  // Make sure the bit buffer correctly enforces byte length on golomb reads.
  // If it didn't, the above buffer would be valid at 3 bytes.
  BitBuffer buffer(bytes, 1);
  uint32_t decoded_val;
  EXPECT_FALSE(buffer.ReadExponentialGolomb(&decoded_val));

  BitBuffer longer_buffer(bytes, 2);
  EXPECT_FALSE(longer_buffer.ReadExponentialGolomb(&decoded_val));

  BitBuffer longest_buffer(bytes, 3);
  EXPECT_TRUE(longest_buffer.ReadExponentialGolomb(&decoded_val));
  // Golomb should have read 9 bits, so 0x01FF, and since it is golomb, the
  // result is 0x01FF - 1 = 0x01FE.
  EXPECT_EQ(0x01FEu, decoded_val);
}

void BitBufferTest_SymmetricReadWrite() {
  uint8_t bytes[16] = {0};
  BitBufferWriter buffer(bytes, 4);

  // Write some bit data at various sizes.
  EXPECT_TRUE(buffer.WriteBits(0x2u, 3));
  EXPECT_TRUE(buffer.WriteBits(0x1u, 2));
  EXPECT_TRUE(buffer.WriteBits(0x53u, 7));
  EXPECT_TRUE(buffer.WriteBits(0x0u, 2));
  EXPECT_TRUE(buffer.WriteBits(0x1u, 1));
  EXPECT_TRUE(buffer.WriteBits(0x1ABCDu, 17));
  // That should be all that fits in the buffer.
  EXPECT_FALSE(buffer.WriteBits(1, 1));

  EXPECT_TRUE(buffer.Seek(0, 0));
  uint32_t val;
  EXPECT_TRUE(buffer.ReadBits(&val, 3));
  EXPECT_EQ(0x2u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 2));
  EXPECT_EQ(0x1u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 7));
  EXPECT_EQ(0x53u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 2));
  EXPECT_EQ(0x0u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 1));
  EXPECT_EQ(0x1u, val);
  EXPECT_TRUE(buffer.ReadBits(&val, 17));
  EXPECT_EQ(0x1ABCDu, val);
  // And there should be nothing left.
  EXPECT_FALSE(buffer.ReadBits(&val, 1));
}

void BitBufferTest_SymmetricBytesMisaligned() {
  uint8_t bytes[16] = {0};
  BitBufferWriter buffer(bytes, 16);

  // Offset 3, to get things misaligned.
  EXPECT_TRUE(buffer.ConsumeBits(3));
  EXPECT_TRUE(buffer.WriteUInt8(0x12u));
  EXPECT_TRUE(buffer.WriteUInt16(0x3456u));
  EXPECT_TRUE(buffer.WriteUInt32(0x789ABCDEu));

  buffer.Seek(0, 3);
  uint8_t val8;
  uint16_t val16;
  uint32_t val32;
  EXPECT_TRUE(buffer.ReadUInt8(&val8));
  EXPECT_EQ(0x12u, val8);
  EXPECT_TRUE(buffer.ReadUInt16(&val16));
  EXPECT_EQ(0x3456u, val16);
  EXPECT_TRUE(buffer.ReadUInt32(&val32));
  EXPECT_EQ(0x789ABCDEu, val32);
}

void BitBufferTest_SymmetricGolomb() {
  char test_string[] = "my precious";
  uint8_t bytes[64] = {0};
  BitBufferWriter buffer(bytes, 64);
  for (size_t i = 0; i < arraysize(test_string); ++i) {
    EXPECT_TRUE(buffer.WriteExponentialGolomb(test_string[i]));
  }
  buffer.Seek(0, 0);
  for (size_t i = 0; i < arraysize(test_string); ++i) {
    uint32_t val;
    EXPECT_TRUE(buffer.ReadExponentialGolomb(&val));
//    EXPECT_LE(val, std::numeric_limits<uint8_t>::max());
    EXPECT_EQ(test_string[i], static_cast<char>(val));
  }
}

void BitBufferTest_WriteClearsBits() {
  uint8_t bytes[] = {0xFF, 0xFF};
  BitBufferWriter buffer(bytes, 2);
  EXPECT_TRUE(buffer.ConsumeBits(3));
  EXPECT_TRUE(buffer.WriteBits(0, 1));
  EXPECT_EQ(0xEFu, bytes[0]);
  EXPECT_TRUE(buffer.WriteBits(0, 3));
  EXPECT_EQ(0xE1u, bytes[0]);
  EXPECT_TRUE(buffer.WriteBits(0, 2));
  EXPECT_EQ(0xE0u, bytes[0]);
  EXPECT_EQ(0x7F, bytes[1]);
}

static const uint16_t SIZE_UNDEF = 0;
static const uint16_t SIZE_IP4 = 8;
static const uint16_t SIZE_IP6 = 20;
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
bool StunAddressAttribute_Read(ByteBufferReader* buf,size_t length) {
  uint8_t dummy;
  if (!buf->ReadUInt8(&dummy))
    return false;

  uint8_t stun_family;
  if (!buf->ReadUInt8(&stun_family)) {
    return false;
  }
  uint16_t port;
  if (!buf->ReadUInt16(&port))
    return false;
  if (stun_family == STUN_ADDRESS_IPV4) {
    in_addr v4addr;
    if (length < SIZE_IP4) {
      return false;
    }
    if (!buf->ReadBytes(reinterpret_cast<char*>(&v4addr), sizeof(v4addr))) {
      return false;
    }
    char *z = inet_ntoa(v4addr); /* cast x as a struct in_addr */
        
    printf("ipv4 = %s \n", z);
  } else if (stun_family == STUN_ADDRESS_IPV6) {
    in6_addr v6addr;
    if (length != SIZE_IP6) {
      return false;
    }
    if (!buf->ReadBytes(reinterpret_cast<char*>(&v6addr), sizeof(v6addr))) {
      return false;
    }
//      char *z = inet_ntoa(v6addr); /* cast x as a struct in_addr */
//
//      printf("z = %s\n", z);
  } else {
    return false;
  }
  return true;
}
void ByteBufferTest_TestReadWriteBufferStunMsg() {
    rtc::ByteBufferReader buf(reinterpret_cast<const char*>(kRfc5769SampleResponse), sizeof(kRfc5769SampleResponse));
    uint16_t type = 0;
    if (!buf.ReadUInt16(&type))
      return;
    int version =  type & 0x8000;
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
    printf("===》 magicId: %ul reduced_transaction_id_:%ul \n",magicId,reduced_transaction_id_);
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
        if (!StunAddressAttribute_Read(&buf,length))
          return ;
//        attrs_.push_back(std::move(attr));
      }
    }
    
}

void ByteBufferTest_TestReadWriteBuffer() {
    ByteBufferWriter::ByteOrder orders[2] = {ByteBufferWriter::ORDER_HOST,
        ByteBufferWriter::ORDER_NETWORK};
    for (size_t i = 0; i < arraysize(orders); i++) {
        ByteBufferWriter buffer(orders[i]);
        EXPECT_EQ(orders[i], buffer.Order());
        ByteBufferReader read_buf(nullptr, 0, orders[i]);
        EXPECT_EQ(orders[i], read_buf.Order());
        uint8_t ru8;
        EXPECT_FALSE(read_buf.ReadUInt8(&ru8));
        
        // Write and read uint8_t.
        uint8_t wu8 = 1;
        buffer.WriteUInt8(wu8);
        ByteBufferReader read_buf1(buffer.Data(), buffer.Length(), orders[i]);
        EXPECT_TRUE(read_buf1.ReadUInt8(&ru8));
        EXPECT_EQ(wu8, ru8);
        EXPECT_EQ(0U, read_buf1.Length());
        buffer.Clear();
        
        // Write and read uint16_t.
        uint16_t wu16 = (1 << 8) + 1;
        buffer.WriteUInt16(wu16);
        ByteBufferReader read_buf2(buffer.Data(), buffer.Length(), orders[i]);
        uint16_t ru16;
        EXPECT_TRUE(read_buf2.ReadUInt16(&ru16));
        EXPECT_EQ(wu16, ru16);
        EXPECT_EQ(0U, read_buf2.Length());
        buffer.Clear();

    // Write and read uint24.
    uint32_t wu24 = (3 << 16) + (2 << 8) + 1;
    buffer.WriteUInt24(wu24);
    ByteBufferReader read_buf3(buffer.Data(), buffer.Length(), orders[i]);
    uint32_t ru24;

    EXPECT_TRUE(read_buf3.ReadUInt24(&ru24));
    EXPECT_EQ(wu24, ru24);
    EXPECT_EQ(0U, read_buf3.Length());
    buffer.Clear();

    // Write and read uint32_t.
//    uint32_t wu32 = (4 << 24) + (3 << 16) + (2 << 8) + 1;
      uint32_t wu32 = 64;
    buffer.WriteUInt32(wu32);
    ByteBufferReader read_buf4(buffer.Data(), buffer.Length(), orders[i]);
    uint32_t ru32;

    EXPECT_TRUE(read_buf4.ReadUInt32(&ru32));
    EXPECT_EQ(wu32, ru32);
    EXPECT_EQ(0U, read_buf3.Length());
    buffer.Clear();

    // Write and read uint64_t.
    uint32_t another32 = (8 << 24) + (7 << 16) + (6 << 8) + 5;
    uint64_t wu64 = (static_cast<uint64_t>(another32) << 32) + wu32;
    buffer.WriteUInt64(wu64);
    ByteBufferReader read_buf5(buffer.Data(), buffer.Length(), orders[i]);
    uint64_t ru64;
    EXPECT_TRUE(read_buf5.ReadUInt64(&ru64));
    EXPECT_EQ(wu64, ru64);
    EXPECT_EQ(0U, read_buf5.Length());
    buffer.Clear();

    // Write and read string.
    std::string write_string("hello");
    buffer.WriteString(write_string);
    ByteBufferReader read_buf6(buffer.Data(), buffer.Length(), orders[i]);
    std::string read_string;
    EXPECT_TRUE(read_buf6.ReadString(&read_string, write_string.size()));
    EXPECT_EQ(write_string, read_string);
    EXPECT_EQ(0U, read_buf6.Length());
    buffer.Clear();

    // Write and read bytes
    char write_bytes[] = "foo";
    buffer.WriteBytes(write_bytes, 3);
    ByteBufferReader read_buf7(buffer.Data(), buffer.Length(), orders[i]);
    char read_bytes[3];
    EXPECT_TRUE(read_buf7.ReadBytes(read_bytes, 3));
    for (int i = 0; i < 3; ++i) {
      EXPECT_EQ(write_bytes[i], read_bytes[i]);
    }
    EXPECT_EQ(0U, read_buf7.Length());
    buffer.Clear();

    // Write and read reserved buffer space
    char* write_dst = buffer.ReserveWriteBuffer(3);
    memcpy(write_dst, write_bytes, 3);
    ByteBufferReader read_buf8(buffer.Data(), buffer.Length(), orders[i]);
    memset(read_bytes, 0, 3);
    EXPECT_TRUE(read_buf8.ReadBytes(read_bytes, 3));
    for (int i = 0; i < 3; ++i) {
      EXPECT_EQ(write_bytes[i], read_bytes[i]);
    }
    EXPECT_EQ(0U, read_buf8.Length());
    buffer.Clear();

    // Write and read in order.
    buffer.WriteUInt8(wu8);
    buffer.WriteUInt16(wu16);
    buffer.WriteUInt24(wu24);
    buffer.WriteUInt32(wu32);
    buffer.WriteUInt64(wu64);
    ByteBufferReader read_buf9(buffer.Data(), buffer.Length(), orders[i]);
    EXPECT_TRUE(read_buf9.ReadUInt8(&ru8));
    EXPECT_EQ(wu8, ru8);
    EXPECT_TRUE(read_buf9.ReadUInt16(&ru16));
    EXPECT_EQ(wu16, ru16);
    EXPECT_TRUE(read_buf9.ReadUInt24(&ru24));
    EXPECT_EQ(wu24, ru24);
    EXPECT_TRUE(read_buf9.ReadUInt32(&ru32));
    EXPECT_EQ(wu32, ru32);
    EXPECT_TRUE(read_buf9.ReadUInt64(&ru64));
    EXPECT_EQ(wu64, ru64);
    EXPECT_EQ(0U, read_buf9.Length());
    buffer.Clear();
  }
}
int main(int argc, const char * argv[]) {
    @autoreleasepool {
//        ByteBufferTest_TestReadWriteBuffer();
        ByteBufferTest_TestReadWriteBufferStunMsg();
//        BitBufferTest_ConsumeBits();
//        BitBufferTest_ReadBytesAligned();
//        BitBufferTest_ReadBytesOffset4();
//        BitBufferTest_ReadBytesOffset3();
//        BitBufferTest_ReadBits();
//        BitBufferTest_SetOffsetValues();
        
        NSLog(@"Hello, World!");
    }
    return 0;
}
