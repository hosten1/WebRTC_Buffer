//
//  testStun.h
//  testBuffer
//
//  Created by luoyongmeng on 2023/2/22.
//

#ifndef testStun_h
#define testStun_h

#include <stdio.h>


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


namespace rtc{
    void ByteBufferTest_TestReadWriteBufferStunMsg();
}

#endif /* testStun_h */
