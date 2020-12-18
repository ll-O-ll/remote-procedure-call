// -*- c++ -*-
#ifndef RPCXX_SAMPLE_H
#define RPCXX_SAMPLE_H

#include <cstdlib>
#include "rpc.h"

#include <iostream>
#include <cassert>

namespace rpc {

// Protocol is used for encode and decode a type to/from the network.
//
// You may use network byte order, but it's optional. We won't test your code
// on two different architectures.

// TASK1: add more specializations to Protocol template class to support more
// types.
template<typename T>
struct Protocol {
  static constexpr size_t TYPE_SIZE = sizeof(T);

  static bool Encode(uint8_t *out_bytes, uint32_t *out_len, const T &x) {
    // Ensure that the allocated buffer is large enough to hold the data contained in type T
    if (*out_len < TYPE_SIZE) return false;

    // Copy the data (byte-by-byte) from the object to the buffer
    memcpy(out_bytes, &x, TYPE_SIZE);

    // The length of data placed in the buffer is equal to the size of T
    // Note: this value needs to be set because the allocated buffer may have been larger than what was required to hold
    // type T, but we only wrote to the number of bytes needed to hold T, and ignored the extras
    *out_len = TYPE_SIZE;

    return true;
  }
  static bool Decode(uint8_t *in_bytes, uint32_t *in_len, bool *ok, T &x) {
    // Ensure that at least the number of bytes needed to hold T have been read in
    if (*in_len < TYPE_SIZE) return false;

    // Copy the data (byte-by-byte) from the buffer to the object
    memcpy(&x, in_bytes, TYPE_SIZE);

    // The length of data read in the buffer is equal to the size of T
    // Note: this value needs to be set because the read-in data in the buffer may not have all been used. We only read
    // the number of bytes needed to hold T, and ignored any extra bytes
    *in_len = TYPE_SIZE;

    *ok = true;
    return true;
  }
};

template<>
struct Protocol<std::string> {
  // We encode strings as Pascal strings with the length as a prefix
  // [string size][0 or more bytes for the actual string]
  // Hence, the number of bytes required to encode this string is the length of the string itself, plus the additional
  // bytes at the beginning that specify the size

  static bool Encode(uint8_t *out_bytes, uint32_t *out_len, const std::string &x) {
    // Ensure that the allocated buffer is large enough to store the required number of bytes (as explained above)
    size_t x_len = x.length();
    if (*out_len < sizeof(size_t) + x_len) return false;

    // Write the string size at the beginning of the output buffer
    memcpy(out_bytes, &x_len, sizeof(size_t));

    // Copy the characters (byte-by-byte) from the string object to the buffer (these characters are placed after the
    // length prefix)
    const char *x_bytes = x.c_str();
    memcpy(out_bytes + sizeof(size_t), x_bytes, x_len);

    // The length of data placed in the buffer is equal to the size of T
    // Note: this value needs to be set because the allocated buffer may have been larger than what was required to hold
    // type T, but we only wrote to the number of bytes needed to hold T, and ignored the extras
    *out_len = sizeof(size_t) + x_len;

    return true;
  }
  static bool Decode(uint8_t *in_bytes, uint32_t *in_len, bool *ok, std::string &x) {
    // Ensure that at least the length prefix of the string has been read in
    if (*in_len < sizeof(size_t)) return false;

    // Read the length prefix and determine the actual size of the string being read in
    size_t in_str_len;
    memcpy(&in_str_len, in_bytes, sizeof(size_t));

    // Now we can actually determine if enough bytes have been read in to contain the actual string
    if (*in_len < sizeof(size_t) + in_str_len) return false;

    // Construct a std::string object using the characters in the input buffer (the std::string constructor will copy
    // the characters byte-by-byte automatically)
    x = std::string(reinterpret_cast<const char *>(in_bytes + sizeof(size_t)), in_str_len);

    // The length of data read in the buffer is equal to the size of T
    // Note: this value needs to be set because the read-in data in the buffer may not have all been used. We only read
    // the number of bytes needed to hold T, and ignored any extra bytes
    *in_len = sizeof(size_t) + in_str_len;

    *ok = true;
    return true;
  }
};

// TASK2: Client-side
template<typename... Params>
class ParamList : public BaseParams {
 public:
  ParamList() {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    *out_len = 0;
    return true;
  }
};

template<typename Param, typename... OtherParams>
class ParamList<Param, OtherParams...> : public ParamList<OtherParams...> {
  Param param;

 public:
  ParamList(Param param, OtherParams... other_params) : ParamList<OtherParams...>(other_params...), param(param) {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    uint32_t used_len = 0;
    uint32_t remaining_len = *out_len;
    if (!Protocol<Param>::Encode(out_bytes, &remaining_len, param)) {
      return false;
    }
    used_len += remaining_len; // Encode() returns the number of used bytes through the remaining_len parameter

    out_bytes += remaining_len;
    remaining_len = *out_len - used_len;
    if (!this->ParamList<OtherParams...>::Encode(out_bytes, &remaining_len)) {
      return false;
    }
    used_len += remaining_len; // Encode() returns the number of used bytes through the remaining_len parameter

    // Return the final number of used bytes via the out_len parameter
    *out_len = used_len;
    return true;
  }
};

// TASK2: Client-side
template<typename ResultType>
class Result : public BaseResult {
  ResultType r;
 public:
  bool HandleResponse(uint8_t *in_bytes, uint32_t *in_len, bool *ok) override final {
    return Protocol<ResultType>::Decode(in_bytes, in_len, ok, r);
  }
  ResultType &data() { return r; }
};

template<>
class Result<void> : public BaseResult {
 public:
  bool HandleResponse(uint8_t *in_bytes, uint32_t *in_len, bool *ok) final {
    *in_len = 0;
    return true;
  }
};

// TASK2: Client-side
class Client : public BaseClient {
 public:
  template<typename Svc, typename Return, typename... Params>
  Result<Return> *Call(Svc *svc, Return (Svc::*func)(Params...), Params... params) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    auto result = new Result<Return>();

    if (!Send(instance_id, func_id, new ParamList<Params...>(params...), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }
};

// ---------------------------------------------------------------------------------------

// TASK2: Server-side

// cases:
// specialize template when RT is void
// 2) T func(Args... ) -> use progressive approach

template<typename Svc, typename ReturnType, typename... Args>
class Args_TProcedure;

template<typename Svc, typename ReturnType>
class Args_TProcedure<Svc, ReturnType> : public BaseProcedure {
 public:
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override {
    ReturnType result = DecodeAndExecuteRecursive(in_bytes, in_len, ok);
    if (!Protocol<ReturnType>::Encode(out_bytes, out_len, result)) {
      *ok = false;
      return false;
    }

    return true;
  }

  template<typename... Args>
  ReturnType DecodeAndExecuteRecursive(uint8_t *in_bytes, uint32_t *in_len,
                                       Args... args,
                                       bool *ok) {
    *in_len = 0;

    using FunctionPointerType = ReturnType (Svc::*)(Args...);
    auto p = func_ptr.To<FunctionPointerType>();
    ReturnType result = (((Svc *) instance)->*p)(args...);
    return result;
  }
};

// Sample function
// in the progressive approach - handling one argument of type Arg
template<typename Svc, typename ReturnType, typename Arg, typename... Args>
class Args_TProcedure<Svc, ReturnType, Arg, Args...> : public Args_TProcedure<Svc, ReturnType, Args...> { // inherit from base template above
 public:
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override {

    ReturnType result = DecodeAndExecuteRecursive(in_bytes, in_len, ok);
    if (!Protocol<ReturnType>::Encode(out_bytes, out_len, result)) {
      *ok = false;
      return false;
    }

    return true;
  }

  template<typename... CurrArgs>
  ReturnType DecodeAndExecuteRecursive(uint8_t *in_bytes, uint32_t *in_len,
                                       CurrArgs... curr_args,
                                       bool *ok) {

    uint32_t used_in_len = 0;
    uint32_t remaining_in_len = *in_len;

    Arg arg;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<Arg>::Decode(in_bytes, &remaining_in_len, ok, arg) || !*ok) {
      return (ReturnType) 0;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;
    remaining_in_len = *in_len - used_in_len;

    ReturnType result =
        Args_TProcedure<Svc, ReturnType, Args...>::template DecodeAndExecuteRecursive<CurrArgs..., Arg>(in_bytes,
                                                                                                        &remaining_in_len,
                                                                                                        curr_args...,
                                                                                                        arg,
                                                                                                        ok);
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter

    *in_len = used_in_len;
    return result;
  }
};


// handle the case where result type is void (cannot assign to void type to a variable in Cpp)
template<typename Svc>
class Args_TProcedure<Svc, void> : public BaseProcedure {
 public:
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override {
    DecodeAndExecuteRecursive(in_bytes, in_len, ok);
    *out_len = 0;
    return true;
  }

  template<typename... CurrArgs>
  void DecodeAndExecuteRecursive(uint8_t *in_bytes, uint32_t *in_len,
                                 CurrArgs... curr_args,
                                 bool *ok) {
    *in_len = 0;

    using FunctionPointerType = void (Svc::*)(CurrArgs...);
    auto p = func_ptr.To<FunctionPointerType>();
    (((Svc *) instance)->*p)(curr_args...);
  }
};

// progressive approach for void return type
template<typename Svc, typename Arg, typename... Args>
class Args_TProcedure<Svc, void, Arg, Args...> : public Args_TProcedure<Svc, void, Args...> {
 public:
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override {
    DecodeAndExecuteRecursive(in_bytes, in_len, ok);
    *out_len = 0;
    return true;
  }

  template<typename... CurrArgs>
  void DecodeAndExecuteRecursive(uint8_t *in_bytes, uint32_t *in_len,
                                 CurrArgs... curr_args,
                                 bool *ok) {
    uint32_t used_in_len = 0;
    uint32_t remaining_in_len = *in_len;

    Arg arg;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<Arg>::Decode(in_bytes, &remaining_in_len, ok, arg) || !*ok) {
      return;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;
    remaining_in_len = *in_len - used_in_len;

    Args_TProcedure<Svc, void, Args...>::template DecodeAndExecuteRecursive<CurrArgs..., Arg>(in_bytes,
                                                                                              &remaining_in_len,
                                                                                              curr_args...,
                                                                                              arg,
                                                                                              ok);
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter

    *in_len = used_in_len;
  }
};

// TASK2: Server-side
template<typename Svc>
class Service : public BaseService {
 protected:
  template<typename ReturnType, typename ... Args>
  // << That's why template belongs here
  void Export(ReturnType (Svc::*func)(Args...)) {
    ExportRaw(MemberFunctionPtr::From(func), new Args_TProcedure<Svc, ReturnType, Args...>());
  }
};

}

#endif /* RPCXX_SAMPLE_H */
