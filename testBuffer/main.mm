//
//  main.m
//  testBuffer
//
//  Created by luoyongmeng on 2023/2/17.
//

#import <Foundation/Foundation.h>

#include <stddef.h>
#include <limits>
#include <assert.h>

#import "byte_order.h"
#import "byte_buffer.h"

#import "bit_buffer.h"

#import "testStun.h"

#include "string_builder.h"



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


void StringBuilder_Release() {
  StringBuilder sb;
  std::string str =
      "This string has to be of a moderate length, or we might "
      "run into problems with small object optimizations.";
    if (!(sizeof(str) <= str.size())) {
        printf("========> StringBuilder_Release <=========");
        assert(false);
    }
  sb << str;
  EXPECT_EQ(str, sb.str());
  sb.AppendFormat(" 这是一段中文测试 %d",342);
  const char* original_buffer = sb.str().c_str();
  std::string moved = sb.Release();
  EXPECT_TRUE(sb.str().empty());
  EXPECT_EQ(str, moved);
  EXPECT_EQ(original_buffer, moved.c_str());
}

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
//        StringBuilder_Release();
//        ByteBufferTest_TestReadWriteBuffer();
        rtc::ByteBufferTest_TestReadWriteBufferStunMsg();
        
        
        
        // Read the RFC5389 fields from the RFC5769 sample STUN request.
//        rtc::StunTest_ReadRfc5769RequestMessage() ;
//        // Read the RFC5389 fields from the RFC5769 sample STUN response.
//        rtc::StunTest_ReadRfc5769ResponseMessage();
//        // Read the RFC5389 fields from the RFC5769 sample STUN response for IPv6.
//        rtc::StunTest_ReadRfc5769ResponseMessageIPv6() ;
//
//        // Read the RFC5389 fields from the RFC5769 sample STUN response with auth.
//        rtc::StunTest_ReadRfc5769RequestMessageLongTermAuth();
//
//        // The RFC3489 packet in this test is the same as
//        // kStunMessageWithIPv4MappedAddress, but with a different value where the
//        // magic cookie was.
//        rtc::StunTest_ReadLegacyMessage();
        
        
        rtc::StunTest_ValidateMessageIntegrity();
        rtc::StunTest_AddMessageIntegrity();
        rtc::StunTest_ValidateFingerprint();
        rtc::StunTest_AddFingerprint( ) ;
        
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
