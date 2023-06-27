/*
 * Copyright (C) 2019-2022 Alibaba Group Holding Limited
 */

// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: simple_meta.proto

#include "simple_meta.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace cx {
namespace proto {
constexpr SimpleMeta::SimpleMeta(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : value_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string){}
struct SimpleMetaDefaultTypeInternal {
  constexpr SimpleMetaDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~SimpleMetaDefaultTypeInternal() {}
  union {
    SimpleMeta _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT SimpleMetaDefaultTypeInternal _SimpleMeta_default_instance_;
}  // namespace proto
}  // namespace cx
namespace cx {
namespace proto {

// ===================================================================

class SimpleMeta::_Internal {
 public:
};

SimpleMeta::SimpleMeta(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:cx.proto.SimpleMeta)
}
SimpleMeta::SimpleMeta(const SimpleMeta& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite() {
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  value_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_value().empty()) {
    value_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_value(), 
      GetArenaForAllocation());
  }
  // @@protoc_insertion_point(copy_constructor:cx.proto.SimpleMeta)
}

inline void SimpleMeta::SharedCtor() {
value_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

SimpleMeta::~SimpleMeta() {
  // @@protoc_insertion_point(destructor:cx.proto.SimpleMeta)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<std::string>();
}

inline void SimpleMeta::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  value_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void SimpleMeta::ArenaDtor(void* object) {
  SimpleMeta* _this = reinterpret_cast< SimpleMeta* >(object);
  (void)_this;
}
void SimpleMeta::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void SimpleMeta::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void SimpleMeta::Clear() {
// @@protoc_insertion_point(message_clear_start:cx.proto.SimpleMeta)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  value_.ClearToEmpty();
  _internal_metadata_.Clear<std::string>();
}

const char* SimpleMeta::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // string value = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_value();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, nullptr));
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<std::string>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* SimpleMeta::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:cx.proto.SimpleMeta)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // string value = 1;
  if (!this->_internal_value().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_value().data(), static_cast<int>(this->_internal_value().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "cx.proto.SimpleMeta.value");
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_value(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:cx.proto.SimpleMeta)
  return target;
}

size_t SimpleMeta::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:cx.proto.SimpleMeta)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string value = 1;
  if (!this->_internal_value().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_value());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void SimpleMeta::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::PROTOBUF_NAMESPACE_ID::internal::DownCast<const SimpleMeta*>(
      &from));
}

void SimpleMeta::MergeFrom(const SimpleMeta& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:cx.proto.SimpleMeta)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_value().empty()) {
    _internal_set_value(from._internal_value());
  }
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void SimpleMeta::CopyFrom(const SimpleMeta& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:cx.proto.SimpleMeta)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool SimpleMeta::IsInitialized() const {
  return true;
}

void SimpleMeta::InternalSwap(SimpleMeta* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &value_, GetArenaForAllocation(),
      &other->value_, other->GetArenaForAllocation()
  );
}

std::string SimpleMeta::GetTypeName() const {
  return "cx.proto.SimpleMeta";
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace cx
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::cx::proto::SimpleMeta* Arena::CreateMaybeMessage< ::cx::proto::SimpleMeta >(Arena* arena) {
  return Arena::CreateMessageInternal< ::cx::proto::SimpleMeta >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
