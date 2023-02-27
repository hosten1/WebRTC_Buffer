//
//  arch.h
//  RTCEngine
//
//  Created by luoyongmeng on 2023/2/23.
//  Copyright © 2023 ymluo. All rights reserved.
//

#ifndef arch_h
#define arch_h
#if defined(__arm64__) || defined(__aarch64__)
    #define TARGET_CPU_ARM64 1
    #define WEBRTC_HAS_NEON
#elif defined(__arm__)
    #define TARGET_CPU_ARM 1
    #define WEBRTC_HAS_NEON
#elif defined(__x86_64__) || defined(__i386__)
    #define TARGET_CPU_X86 1
#endif


#endif /* arch_h */
