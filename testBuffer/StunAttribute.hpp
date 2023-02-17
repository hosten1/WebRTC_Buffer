//
//  StunAttribute.hpp
//  testBuffer
//
//  Created by luoyongmeng on 2023/2/17.
//

#ifndef StunAttribute_hpp
#define StunAttribute_hpp

#include <stdio.h>

#import "byte_order.h"
#import "byte_buffer.h"
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
// Base class for all STUN/TURN attributes.
class StunAttribute {
 public:
  virtual ~StunAttribute() {}

  int type() const { return type_; }
  size_t length() const { return length_; }

  // Return the type of this attribute.
  virtual StunAttributeValueType value_type() const = 0;

  // Only XorAddressAttribute needs this so far.
  virtual void SetOwner(StunMessage* owner) {}

  // Reads the body (not the type or length) for this type of attribute from
  // the given buffer.  Return value is true if successful.
  virtual bool Read(rtc::ByteBufferReader* buf) = 0;

  // Writes the body (not the type or length) to the given buffer.  Return
  // value is true if successful.
  virtual bool Write(rtc::ByteBufferWriter* buf) const = 0;

  // Creates an attribute object with the given type and smallest length.
  static StunAttribute* Create(StunAttributeValueType value_type,
                               uint16_t type,
                               uint16_t length,
                               StunMessage* owner);
  // TODO(?): Allow these create functions to take parameters, to reduce
  // the amount of work callers need to do to initialize attributes.
  static std::unique_ptr<StunAddressAttribute> CreateAddress(uint16_t type);
  static std::unique_ptr<StunXorAddressAttribute> CreateXorAddress(
      uint16_t type);
  static std::unique_ptr<StunUInt32Attribute> CreateUInt32(uint16_t type);
  static std::unique_ptr<StunUInt64Attribute> CreateUInt64(uint16_t type);
  static std::unique_ptr<StunByteStringAttribute> CreateByteString(
      uint16_t type);
  static std::unique_ptr<StunErrorCodeAttribute> CreateErrorCode();
  static std::unique_ptr<StunUInt16ListAttribute> CreateUnknownAttributes();

 protected:
  StunAttribute(uint16_t type, uint16_t length);
  void SetLength(uint16_t length) { length_ = length; }
  void WritePadding(rtc::ByteBufferWriter* buf) const;
  void ConsumePadding(rtc::ByteBufferReader* buf) const;

 private:
  uint16_t type_;
  uint16_t length_;
};
#endif /* StunAttribute_hpp */
