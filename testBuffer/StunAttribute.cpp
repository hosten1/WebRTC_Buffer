//
//  StunAttribute.cpp
//  testBuffer
//
//  Created by luoyongmeng on 2023/2/17.
//

#include "StunAttribute.hpp"
// StunAttribute
using rtc::ByteBufferReader;
using rtc::ByteBufferWriter;

StunAttribute::StunAttribute(uint16_t type, uint16_t length)
    : type_(type), length_(length) {}

void StunAttribute::ConsumePadding(ByteBufferReader* buf) const {
  int remainder = length_ % 4;
  if (remainder > 0) {
    buf->Consume(4 - remainder);
  }
}

void StunAttribute::WritePadding(ByteBufferWriter* buf) const {
  int remainder = length_ % 4;
  if (remainder > 0) {
    char zeroes[4] = {0};
    buf->WriteBytes(zeroes, 4 - remainder);
  }
}

StunAttribute* StunAttribute::Create(StunAttributeValueType value_type,
                                     uint16_t type,
                                     uint16_t length,
                                     StunMessage* owner) {
  switch (value_type) {
    case STUN_VALUE_ADDRESS:
      return new StunAddressAttribute(type, length);
    case STUN_VALUE_XOR_ADDRESS:
      return new StunXorAddressAttribute(type, length, owner);
    case STUN_VALUE_UINT32:
      return new StunUInt32Attribute(type);
    case STUN_VALUE_UINT64:
      return new StunUInt64Attribute(type);
    case STUN_VALUE_BYTE_STRING:
      return new StunByteStringAttribute(type, length);
    case STUN_VALUE_ERROR_CODE:
      return new StunErrorCodeAttribute(type, length);
    case STUN_VALUE_UINT16_LIST:
      return new StunUInt16ListAttribute(type, length);
    default:
      return NULL;
  }
}

std::unique_ptr<StunAddressAttribute> StunAttribute::CreateAddress(
    uint16_t type) {
  return absl::make_unique<StunAddressAttribute>(type, 0);
}

std::unique_ptr<StunXorAddressAttribute> StunAttribute::CreateXorAddress(
    uint16_t type) {
  return absl::make_unique<StunXorAddressAttribute>(type, 0, nullptr);
}

std::unique_ptr<StunUInt64Attribute> StunAttribute::CreateUInt64(
    uint16_t type) {
  return absl::make_unique<StunUInt64Attribute>(type);
}

std::unique_ptr<StunUInt32Attribute> StunAttribute::CreateUInt32(
    uint16_t type) {
  return absl::make_unique<StunUInt32Attribute>(type);
}

std::unique_ptr<StunByteStringAttribute> StunAttribute::CreateByteString(
    uint16_t type) {
  return absl::make_unique<StunByteStringAttribute>(type, 0);
}

std::unique_ptr<StunErrorCodeAttribute> StunAttribute::CreateErrorCode() {
  return absl::make_unique<StunErrorCodeAttribute>(
      STUN_ATTR_ERROR_CODE, StunErrorCodeAttribute::MIN_SIZE);
}

std::unique_ptr<StunUInt16ListAttribute>
StunAttribute::CreateUnknownAttributes() {
  return absl::make_unique<StunUInt16ListAttribute>(
      STUN_ATTR_UNKNOWN_ATTRIBUTES, 0);
}
