# WebRTC_Buffer
webrtc bitBuffer ByteBuffer
# 按照以下方式可以构建一个stun的bind消息
```c++
    StunMessage request;
    request.SetType(STUN_BINDING_REQUEST);
    std::string str =   reinterpret_cast<const char*>(kRfc5769SampleMsgTransactionId);
    request.SetTransactionID(str);
    /*
  //           MD5加密文本：lym:example.org:123456
  //           turnKey = 8812c1afb0e203aae88c996e30ac7db6
  //           unsigned char  data[7] = "123456";
  //           hmac_sha1加密后数据 = b103f699ef12c04ab6f0cb155ac2f12ef84adf22
  //           */
    std::string key;
    ComputeStunCredentialHash("lym","example.org","123456", &key);
    request.AddMessageIntegrity(key);
    const StunByteStringAttribute* mi_attr =
    request.GetByteString(STUN_ATTR_MESSAGE_INTEGRITY);
      printfX("StunTest_AddMessageIntegrity MD5 ",mi_attr->bytes(), mi_attr->length());
    
    request.AddAttribute(std::make_unique<StunByteStringAttribute>(STUN_ATTR_USERNAME, "username"));
    request.AddAttribute(std::make_unique<StunUInt32Attribute>(STUN_ATTR_RETRANSMIT_COUNT, 1));
    request.AddAttribute(std::make_unique<StunByteStringAttribute>(STUN_ATTR_SOFTWARE, "{\"name\":\"lym\",\"age\":10,\"body\":\"haha\"}"));
    rtc::ByteBufferWriter writer;
    request.Write(&writer);
```
获取数据的使用`writer.Data()`就能获取到二进制数据；
# 按照以下方式可以解析一个stun的消息
```c++
  StunMessage msg;
    rtc::ByteBufferReader buf(writer.Data() , writer.Length());
    msg.Read(&buf);
    const StunByteStringAttribute *soft_attr = msg.GetByteString(STUN_ATTR_SOFTWARE);
    std::string soft_attrStr = mi_attr->GetString();
    printf("test_sendBindMsg soft_attr %s %zu",soft_attrStr.c_str(), mi_attr->length());
```
