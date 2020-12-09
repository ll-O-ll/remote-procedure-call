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
class IntParam : public BaseParams {
  int p;
 public:
  IntParam(int p) : p(p) {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    return Protocol<int>::Encode(out_bytes, out_len, p);
  }
};

class VoidParam : public BaseParams {
 public:
  VoidParam() {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    *out_len = 0;
    return true;
  }
};

class UintParam : public BaseParams {
  unsigned int p;
 public:
  UintParam(unsigned int p) : p(p) {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    return Protocol<unsigned int>::Encode(out_bytes, out_len, p);
  }
};

class StrParam : public BaseParams {
  std::string p;
 public:
  StrParam(std::string p) : p(p) {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    return Protocol<std::string>::Encode(out_bytes, out_len, p);
  }
};

class StrIntParam : public BaseParams {
  std::string p1;
  int p2;
 public:
  StrIntParam(std::string p1, int p2) : p1(p1), p2(p2) {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    uint32_t used_len = 0;

    uint32_t remaining_len = *out_len;
    if (!Protocol<std::string>::Encode(out_bytes, &remaining_len, p1)) {
      return false;
    }
    used_len += remaining_len; // Encode() returns the number of used bytes through the remaining_len parameter
    out_bytes += remaining_len;

    remaining_len = *out_len - used_len;
    if (!Protocol<int>::Encode(out_bytes, &remaining_len, p2)) {
      return false;
    }
    used_len += remaining_len; // Encode() returns the number of used bytes through the remaining_len parameter
    out_bytes += remaining_len;

    // Return the final number of used bytes via the out_len parameter
    *out_len = used_len;

    return true;
  }
};

class IntUintParam : public BaseParams {
  int p1;
  unsigned int p2;
 public:
  IntUintParam(int p1, unsigned int p2) : p1(p1), p2(p2) {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    uint32_t used_len = 0;

    uint32_t remaining_len = *out_len;
    if (!Protocol<int>::Encode(out_bytes, &remaining_len, p1)) {
      return false;
    }
    used_len += remaining_len; // Encode() returns the number of used bytes through the remaining_len parameter
    out_bytes += remaining_len;

    remaining_len = *out_len - used_len;
    if (!Protocol<unsigned int>::Encode(out_bytes, &remaining_len, p2)) {
      return false;
    }
    used_len += remaining_len; // Encode() returns the number of used bytes through the remaining_len parameter
    out_bytes += remaining_len;

    // Return the final number of used bytes via the out_len parameter
    *out_len = used_len;

    return true;
  }
};

class StrStrParam : public BaseParams {
  std::string p1;
  std::string p2;
 public:
  StrStrParam(std::string p1, std::string p2) : p1(p1), p2(p2) {}

  bool Encode(uint8_t *out_bytes, uint32_t *out_len) const override {
    uint32_t used_len = 0;

    uint32_t remaining_len = *out_len;
    if (!Protocol<std::string>::Encode(out_bytes, &remaining_len, p1)) {
      return false;
    }
    used_len += remaining_len; // Encode() returns the number of used bytes through the remaining_len parameter
    out_bytes += remaining_len;

    remaining_len = *out_len - used_len;
    if (!Protocol<std::string>::Encode(out_bytes, &remaining_len, p2)) {
      return false;
    }
    used_len += remaining_len; // Encode() returns the number of used bytes through the remaining_len parameter
    out_bytes += remaining_len;

    // Return the final number of used bytes via the out_len parameter
    *out_len = used_len;

    return true;
  }
};

// TASK2: Server-side
// Sample function
template<typename Svc>
class Int_IntProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    int x;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<int>::Decode(in_bytes, in_len, ok, x) || !*ok) {
      return false;
    }
    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = int (Svc::*)(int);
    auto p = func_ptr.To<FunctionPointerType>();
    int result = (((Svc *) instance)->*p)(x);
    if (!Protocol<int>::Encode(out_bytes, out_len, result)) {
      // out_len should always be large enough so this branch shouldn't be
      // taken. However just in case, we return an fatal error by setting *ok
      // to false.
      *ok = false;
      return false;
    }
    return true;
  }
};

// Function 1

template<typename Svc>
class Void_VoidProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    *in_len = 0;

    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = void (Svc::*)();
    auto p = func_ptr.To<FunctionPointerType>();
    (((Svc *) instance)->*p)();
    *out_len = 0;
    return true;
  }
};

// Function 2

template<typename Svc>
class Void_BoolProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    *in_len = 0;

    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = bool (Svc::*)();
    auto p = func_ptr.To<FunctionPointerType>();
    bool result = (((Svc *) instance)->*p)();
    if (!Protocol<bool>::Encode(out_bytes, out_len, result)) {
      // out_len should always be large enough so this branch shouldn't be
      // taken. However just in case, we return an fatal error by setting *ok
      // to false.
      *ok = false;
      return false;
    }
    return true;
  }
};

// Function 3

template<typename Svc>
class Uint_StrProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    unsigned int x;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<unsigned int>::Decode(in_bytes, in_len, ok, x) || !*ok) {
      return false;
    }
    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = std::string (Svc::*)(unsigned int);
    auto p = func_ptr.To<FunctionPointerType>();
    std::string result = (((Svc *) instance)->*p)(x);
    if (!Protocol<std::string>::Encode(out_bytes, out_len, result)) {
      // out_len should always be large enough so this branch shouldn't be
      // taken. However just in case, we return an fatal error by setting *ok
      // to false.
      *ok = false;
      return false;
    }
    return true;
  }
};

// Function 4 (according to lab doc)
// ------------------------------------------------------------------------------

template<typename Svc>
class Str_StrProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    std::string x;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<std::string>::Decode(in_bytes, in_len, ok, x) || !*ok) {
      return false;
    }
    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = std::string (Svc::*)(std::string);
    auto p = func_ptr.To<FunctionPointerType>();
    std::string result = (((Svc *) instance)->*p)(x);
    if (!Protocol<std::string>::Encode(out_bytes, out_len, result)) {
      // out_len should always be large enough so this branch shouldn't be
      // taken. However just in case, we return an fatal error by setting *ok
      // to false.
      *ok = false;
      return false;
    }
    return true;
  }
};

// ------------------------------------------------------------------------------------------
// Function 4 (according to test-complex.cc)
// ------------------------------------------------------------------------------------------
// see Function 5's server-side implementation
// ------------------------------------------------------------------------------------------

// Function 5

template<typename Svc>
class StrInt_StrProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    std::string arg1;
    int arg2;

    uint32_t used_in_len = 0;
    uint32_t remaining_in_len = *in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<std::string>::Decode(in_bytes, &remaining_in_len, ok, arg1) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    remaining_in_len = *in_len - used_in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<int>::Decode(in_bytes, &remaining_in_len, ok, arg2) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    *in_len = used_in_len;

    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = std::string (Svc::*)(std::string, int);
    auto p = func_ptr.To<FunctionPointerType>();
    std::string result = (((Svc *) instance)->*p)(arg1, arg2);
    if (!Protocol<std::string>::Encode(out_bytes, out_len, result)) {
      // out_len should always be large enough so this branch shouldn't be
      // taken. However just in case, we return an fatal error by setting *ok
      // to false.
      *ok = false;
      return false;
    }
    return true;
  }
};

// Functions 6-7 (according to lab doc)
// ------------------------------------------------------------------------------------------
template<typename Svc>
class StrInt_UintProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    std::string arg1;
    int arg2;

    uint32_t used_in_len = 0;
    uint32_t remaining_in_len = *in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<std::string>::Decode(in_bytes, &remaining_in_len, ok, arg1) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    remaining_in_len = *in_len - used_in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<int>::Decode(in_bytes, &remaining_in_len, ok, arg2) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    *in_len = used_in_len;

    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = unsigned int (Svc::*)(std::string, int);
    auto p = func_ptr.To<FunctionPointerType>();
    unsigned int result = (((Svc *) instance)->*p)(arg1, arg2);
    if (!Protocol<unsigned int>::Encode(out_bytes, out_len, result)) {
      // out_len should always be large enough so this branch shouldn't be
      // taken. However just in case, we return an fatal error by setting *ok
      // to false.
      *ok = false;
      return false;
    }
    return true;
  }
};

template<typename Svc>
class StrInt_VoidProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    std::string arg1;
    int arg2;

    uint32_t used_in_len = 0;
    uint32_t remaining_in_len = *in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<std::string>::Decode(in_bytes, &remaining_in_len, ok, arg1) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    remaining_in_len = *in_len - used_in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<int>::Decode(in_bytes, &remaining_in_len, ok, arg2) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    *in_len = used_in_len;

    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = void (Svc::*)(std::string, int);
    auto p = func_ptr.To<FunctionPointerType>();
    (((Svc *) instance)->*p)(arg1, arg2);
    *out_len = 0;
    return true;
  }
};

// Functions 6-7 (according to test-complex.cc)
// ------------------------------------------------------------------------------------------
template<typename Svc>
class IntUint_UlongProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    int arg1;
    unsigned int arg2;

    uint32_t used_in_len = 0;
    uint32_t remaining_in_len = *in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<int>::Decode(in_bytes, &remaining_in_len, ok, arg1) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    remaining_in_len = *in_len - used_in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<unsigned int>::Decode(in_bytes, &remaining_in_len, ok, arg2) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    *in_len = used_in_len;

    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = unsigned long (Svc::*)(int, unsigned int);
    auto p = func_ptr.To<FunctionPointerType>();
    unsigned long result = (((Svc *) instance)->*p)(arg1, arg2);
    if (!Protocol<unsigned long>::Encode(out_bytes, out_len, result)) {
      // out_len should always be large enough so this branch shouldn't be
      // taken. However just in case, we return an fatal error by setting *ok
      // to false.
      *ok = false;
      return false;
    }

    return true;
  }
};

template<typename Svc>
class StrStr_VoidProcedure : public BaseProcedure {
  bool DecodeAndExecute(uint8_t *in_bytes, uint32_t *in_len,
                        uint8_t *out_bytes, uint32_t *out_len,
                        bool *ok) override final {
    std::string arg1;
    std::string arg2;

    uint32_t used_in_len = 0;
    uint32_t remaining_in_len = *in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<std::string>::Decode(in_bytes, &remaining_in_len, ok, arg1) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    remaining_in_len = *in_len - used_in_len;
    // This function is similar to Decode. We need to return false if buffer
    // isn't large enough, or fatal error happens during parsing.
    if (!Protocol<std::string>::Decode(in_bytes, &remaining_in_len, ok, arg2) || !*ok) {
      return false;
    }
    used_in_len += remaining_in_len; // Decode() returns the number of bytes used through the remaining_in_len parameter
    in_bytes += remaining_in_len;

    *in_len = used_in_len;

    // Now we cast the function pointer func_ptr to its original type.
    //
    // This incomplete solution only works for this type of member functions.
    using FunctionPointerType = void (Svc::*)(std::string, std::string);
    auto p = func_ptr.To<FunctionPointerType>();
    (((Svc *) instance)->*p)(arg1, arg2);
    *out_len = 0;
    return true;
  }
};
// ------------------------------------------------------------------------------------------

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
  // Sample function
  template<typename Svc>
  Result<int> *Call(Svc *svc, int (Svc::*func)(int), int x) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an integer.
    auto result = new Result<int>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    if (!Send(instance_id, func_id, new IntParam(x), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }

  // Function 1
  template<typename Svc>
  Result<void> *Call(Svc *svc, void (Svc::*func)()) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    auto result = new Result<void>();
    Send(instance_id, func_id, new VoidParam(), result);
    return nullptr;
  }

  // Function 2

  template<typename Svc>
  Result<bool> *Call(Svc *svc, bool (Svc::*func)()) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an boolean.
    auto result = new Result<bool>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.

    if (!Send(instance_id, func_id, new VoidParam(), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }

  // Function 3

  template<typename Svc>
  Result<std::string> *Call(Svc *svc, std::string (Svc::*func)(unsigned int), unsigned int x) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an integer.
    auto result = new Result<std::string>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    if (!Send(instance_id, func_id, new UintParam(x), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }

  // Function 4 (according to lab doc)
  // ------------------------------------------------------------------------------------------
  template<typename Svc>
  Result<std::string> *Call(Svc *svc, std::string (Svc::*func)(std::string), std::string x) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an integer.
    auto result = new Result<std::string>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    if (!Send(instance_id, func_id, new StrParam(x), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }

  // ------------------------------------------------------------------------------------------
  // Function 4 (according to text-complex.cc)
  // see Function 5's client-side implementation
  // ------------------------------------------------------------------------------------------

  // Function 5
  template<typename Svc>
  Result<std::string> *Call(Svc *svc, std::string (Svc::*func)(std::string, int), std::string arg1, int arg2) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an integer.
    auto result = new Result<std::string>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    if (!Send(instance_id, func_id, new StrIntParam(arg1, arg2), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }

  // Functions 6-7 (according to lab doc)
  // ------------------------------------------------------------------------------------------
  template<typename Svc>
  Result<unsigned int> *Call(Svc *svc, unsigned int (Svc::*func)(std::string, int), std::string arg1, int arg2) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an integer.
    auto result = new Result<unsigned int>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    if (!Send(instance_id, func_id, new StrIntParam(arg1, arg2), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }

  template<typename Svc>
  Result<void> *Call(Svc *svc, void (Svc::*func)(std::string, int), std::string arg1, int arg2) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an integer.
    auto result = new Result<void>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    if (!Send(instance_id, func_id, new StrIntParam(arg1, arg2), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }

  // Functions 6-7 (according to test-complex.cc)
  // ------------------------------------------------------------------------------------------
  template<typename Svc>
  Result<unsigned long> *Call(Svc *svc, unsigned long (Svc::*func)(int, unsigned int), int arg1, unsigned int arg2) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an integer.
    auto result = new Result<unsigned long>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    if (!Send(instance_id, func_id, new IntUintParam(arg1, arg2), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }

  template<typename Svc>
  Result<void> *Call(Svc *svc, void (Svc::*func)(std::string, std::string), std::string arg1, std::string arg2) {
    // Lookup instance and function IDs.
    int instance_id = svc->instance_id();
    int func_id = svc->LookupExportFunction(MemberFunctionPtr::From(func));

    // This incomplete solution only works for this type of member functions.
    // So the result must be an integer.
    auto result = new Result<void>();

    // We also send the parameters of the functions. For this incomplete
    // solution, it must be one integer.
    if (!Send(instance_id, func_id, new StrStrParam(arg1, arg2), result)) {
      // Fail to send, then delete the result and return nullptr.
      delete result;
      return nullptr;
    }
    return result;
  }
  // ------------------------------------------------------------------------------------------
};

// TASK2: Server-side
template<typename Svc>
class Service : public BaseService {
 protected:
  // Sample function
  void Export(int (Svc::*func)(int)) {
    ExportRaw(MemberFunctionPtr::From(func), new Int_IntProcedure<Svc>());
  }

  // Function 1
  void Export(void (Svc::*func)()) {
    ExportRaw(MemberFunctionPtr::From(func), new Void_VoidProcedure<Svc>());
  }

  // Function 2
  void Export(bool (Svc::*func)()) {
    ExportRaw(MemberFunctionPtr::From(func), new Void_BoolProcedure<Svc>());
  }

  // Function 3
  void Export(std::string (Svc::*func)(unsigned int)) {
    ExportRaw(MemberFunctionPtr::From(func), new Uint_StrProcedure<Svc>());
  }

  // Function 4 (according to lab doc)
  // ------------------------------------------------------------------------------------------
  void Export(std::string (Svc::*func)(std::string)) {
    ExportRaw(MemberFunctionPtr::From(func), new Str_StrProcedure<Svc>());
  }

  // ------------------------------------------------------------------------------------------
  // Function 4 (according to test-complex.cc)
  // ------------------------------------------------------------------------------------------
  // see Function 5
  // ------------------------------------------------------------------------------------------

  // Function 5
  void Export(std::string (Svc::*func)(std::string, int)) {
    ExportRaw(MemberFunctionPtr::From(func), new StrInt_StrProcedure<Svc>());
  }

  // Functions 6-7 (according to lab doc)
  // ------------------------------------------------------------------------------------------
  void Export(unsigned int (Svc::*func)(std::string, int)) {
    ExportRaw(MemberFunctionPtr::From(func), new StrInt_UintProcedure<Svc>());
  }

  void Export(void (Svc::*func)(std::string, int)) {
    ExportRaw(MemberFunctionPtr::From(func), new StrInt_VoidProcedure<Svc>());
  }

  // Functions 6-7 (according to test-complex.cc)
  // ------------------------------------------------------------------------------------------
  void Export(unsigned long (Svc::*func)(int, unsigned int)) {
    ExportRaw(MemberFunctionPtr::From(func), new IntUint_UlongProcedure<Svc>());
  }

  void Export(void (Svc::*func)(std::string, std::string)) {
    ExportRaw(MemberFunctionPtr::From(func), new StrStr_VoidProcedure<Svc>());
  }
  // ------------------------------------------------------------------------------------------
};
}

#endif /* RPCXX_SAMPLE_H */
