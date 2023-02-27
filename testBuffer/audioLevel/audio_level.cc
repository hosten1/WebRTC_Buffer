/*
 *  Copyright (c) 2012 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include "audio_level.h"

//#include "api/audio/audio_frame.h"

#include "arch.h"

#define WEBRTC_SPL_WORD16_MAX 32767
#define WEBRTC_SPL_WORD16_MIN -32768

#if defined(WEBRTC_HAS_NEON)
#include <arm_neon.h>
#include <stdlib.h>
// Maximum absolute value of word16 vector. C version for generic platforms.
int16_t WebRtcSpl_MaxAbsValueW16Neon(const int16_t* vector, size_t length) {
  int absolute = 0, maximum = 0;

//  RTC_DCHECK_GT(length, 0);

  const int16_t* p_start = vector;
  size_t rest = length & 7;
  const int16_t* p_end = vector + length - rest;

  int16x8_t v;
  uint16x8_t max_qv;
  max_qv = vdupq_n_u16(0);

  while (p_start < p_end) {
    v = vld1q_s16(p_start);
    // Note vabs doesn't change the value of -32768.
    v = vabsq_s16(v);
    // Use u16 so we don't lose the value -32768.
    max_qv = vmaxq_u16(max_qv, vreinterpretq_u16_s16(v));
    p_start += 8;
  }

#ifdef WEBRTC_ARCH_ARM64
  maximum = (int)vmaxvq_u16(max_qv);
#else
  uint16x4_t max_dv;
  max_dv = vmax_u16(vget_low_u16(max_qv), vget_high_u16(max_qv));
  max_dv = vpmax_u16(max_dv, max_dv);
  max_dv = vpmax_u16(max_dv, max_dv);

  maximum = (int)vget_lane_u16(max_dv, 0);
#endif

  p_end = vector + length;
  while (p_start < p_end) {
    absolute = abs((int)(*p_start));

    if (absolute > maximum) {
      maximum = absolute;
    }
    p_start++;
  }

  // Guard the case for abs(-32768).
  if (maximum > WEBRTC_SPL_WORD16_MAX) {
    maximum = WEBRTC_SPL_WORD16_MAX;
  }

  return (int16_t)maximum;
}
#else
int16_t WebRtcSpl_MaxAbsValueW16C(const int16_t* vector, size_t length) {
  size_t i = 0;
  int absolute = 0, maximum = 0;

  for (i = 0; i < length; i++) {
    absolute = abs((int)vector[i]);

    if (absolute > maximum) {
      maximum = absolute;
    }
  }

  // Guard the case for abs(-32768).
  if (maximum > WEBRTC_SPL_WORD16_MAX) {
    maximum = WEBRTC_SPL_WORD16_MAX;
  }

  return (int16_t)maximum;
}
#endif
namespace webrtc {
namespace voe {



AudioLevel::AudioLevel()
    : abs_max_(0), count_(0), current_level_full_range_(0) {
//  WebRtcSpl_Init();
}

AudioLevel::~AudioLevel() {}

int16_t AudioLevel::LevelFullRange() const {
  return current_level_full_range_;
}

void AudioLevel::Clear() {
  abs_max_ = 0;
  count_ = 0;
  current_level_full_range_ = 0;
}

double AudioLevel::TotalEnergy() const {
  return total_energy_;
}

double AudioLevel::TotalDuration() const {
  return total_duration_;
}

void AudioLevel::ComputeLevel(const int16_t *audio_data, size_t count, double duration) {
  // Check speech level (works for 2 channels as well)
#if defined(WEBRTC_HAS_NEON)
    int16_t abs_value = WebRtcSpl_MaxAbsValueW16Neon(audio_data, count);
#else
    int16_t abs_value = WebRtcSpl_MaxAbsValueW16C(audio_data, count);
#endif

  // Protect member access using a lock since this method is called on a
  // dedicated audio thread in the RecordedDataIsAvailable() callback.
//  rtc::CritScope cs(&crit_sect_);

  if (abs_value > abs_max_)
    abs_max_ = abs_value;

  // Update level approximately 10 times per second
  if (count_++ == kUpdateFrequency) {
    current_level_full_range_ = abs_max_;

    count_ = 0;

    // Decay the absolute maximum (divide by 4)
    abs_max_ >>= 2;
  }

  // See the description for "totalAudioEnergy" in the WebRTC stats spec
  // (https://w3c.github.io/webrtc-stats/#dom-rtcmediastreamtrackstats-totalaudioenergy)
  // for an explanation of these formulas. In short, we need a value that can
  // be used to compute RMS audio levels over different time intervals, by
  // taking the difference between the results from two getStats calls. To do
  // this, the value needs to be of units "squared sample value * time".
  double additional_energy =
      static_cast<double>(current_level_full_range_) / INT16_MAX;
  additional_energy *= additional_energy;
  total_energy_ += additional_energy * duration;
  total_duration_ += duration;
}

}  // namespace voe
}  // namespace webrtc
