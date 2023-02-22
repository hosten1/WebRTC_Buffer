//
//  testStun.h
//  testBuffer
//
//  Created by luoyongmeng on 2023/2/22.
//

#ifndef testStun_h
#define testStun_h

#include <stdio.h>

#include <stdint.h>

#define  EXPECT_EQ(a,b) \
if (a != b) {\
    printf("EXPECT_EQ 出错了！！！！");\
   assert( a == b );\
}

#define  EXPECT_TRUE(a) \
if (!a) {\
    printf("EXPECT_TRUE 出错了！！！！");\
    assert( a ); \
}
#define  EXPECT_FALSE(a) \
if (a) {\
    printf("EXPECT_FALSE 出错了！！！！");\
    assert( !a ); \
}
#define ASSERT_EQ(a,b) assert( a==b )
#define ASSERT_TRUE(a) assert( a )

static const uint16_t SIZE_UNDEF = 0;
static const uint16_t SIZE_IP4 = 8;
static const uint16_t SIZE_IP6 = 20;

namespace rtc{
    void ByteBufferTest_TestReadWriteBufferStunMsg();
// Read the RFC5389 fields from the RFC5769 sample STUN request.
void  StunTest_ReadRfc5769RequestMessage() ;
// Read the RFC5389 fields from the RFC5769 sample STUN response.
void  StunTest_ReadRfc5769ResponseMessage();
// Read the RFC5389 fields from the RFC5769 sample STUN response for IPv6.
void  StunTest_ReadRfc5769ResponseMessageIPv6() ;

// Read the RFC5389 fields from the RFC5769 sample STUN response with auth.
void  StunTest_ReadRfc5769RequestMessageLongTermAuth();

// The RFC3489 packet in this test is the same as
// kStunMessageWithIPv4MappedAddress, but with a different value where the
// magic cookie was.
void  StunTest_ReadLegacyMessage();

void  StunTest_ValidateMessageIntegrity();
void  StunTest_AddMessageIntegrity();
void  StunTest_ValidateFingerprint();
void  StunTest_AddFingerprint( ) ;
void test_sendBindMsg();
}

#endif /* testStun_h */
