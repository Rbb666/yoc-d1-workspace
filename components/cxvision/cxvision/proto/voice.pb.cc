/*
 * Copyright (C) 2019-2022 Alibaba Group Holding Limited
 */

// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: voice.proto

#include "voice.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace thead {
namespace voice {
namespace proto {
constexpr SessionMsg::SessionMsg(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : kws_word_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , cmd_id_(0)

  , kws_id_(0)
  , kws_score_(0){}
struct SessionMsgDefaultTypeInternal {
  constexpr SessionMsgDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~SessionMsgDefaultTypeInternal() {}
  union {
    SessionMsg _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT SessionMsgDefaultTypeInternal _SessionMsg_default_instance_;
constexpr RecordMsg::RecordMsg(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : cmd_(0)
{}
struct RecordMsgDefaultTypeInternal {
  constexpr RecordMsgDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~RecordMsgDefaultTypeInternal() {}
  union {
    RecordMsg _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT RecordMsgDefaultTypeInternal _RecordMsg_default_instance_;
}  // namespace proto
}  // namespace voice
}  // namespace thead
namespace thead {
namespace voice {
namespace proto {
bool SessionCmd_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
    case 2:
      return true;
    default:
      return false;
  }
}

static ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<std::string> SessionCmd_strings[3] = {};

static const char SessionCmd_names[] =
  "BEGIN"
  "END"
  "TIMEOUT";

static const ::PROTOBUF_NAMESPACE_ID::internal::EnumEntry SessionCmd_entries[] = {
  { {SessionCmd_names + 0, 5}, 0 },
  { {SessionCmd_names + 5, 3}, 1 },
  { {SessionCmd_names + 8, 7}, 2 },
};

static const int SessionCmd_entries_by_number[] = {
  0, // 0 -> BEGIN
  1, // 1 -> END
  2, // 2 -> TIMEOUT
};

const std::string& SessionCmd_Name(
    SessionCmd value) {
  static const bool dummy =
      ::PROTOBUF_NAMESPACE_ID::internal::InitializeEnumStrings(
          SessionCmd_entries,
          SessionCmd_entries_by_number,
          3, SessionCmd_strings);
  (void) dummy;
  int idx = ::PROTOBUF_NAMESPACE_ID::internal::LookUpEnumName(
      SessionCmd_entries,
      SessionCmd_entries_by_number,
      3, value);
  return idx == -1 ? ::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString() :
                     SessionCmd_strings[idx].get();
}
bool SessionCmd_Parse(
    ::PROTOBUF_NAMESPACE_ID::ConstStringParam name, SessionCmd* value) {
  int int_value;
  bool success = ::PROTOBUF_NAMESPACE_ID::internal::LookUpEnumValue(
      SessionCmd_entries, 3, name, &int_value);
  if (success) {
    *value = static_cast<SessionCmd>(int_value);
  }
  return success;
}
bool RecordCmd_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
      return true;
    default:
      return false;
  }
}

static ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<std::string> RecordCmd_strings[2] = {};

static const char RecordCmd_names[] =
  "START"
  "STOP";

static const ::PROTOBUF_NAMESPACE_ID::internal::EnumEntry RecordCmd_entries[] = {
  { {RecordCmd_names + 0, 5}, 0 },
  { {RecordCmd_names + 5, 4}, 1 },
};

static const int RecordCmd_entries_by_number[] = {
  0, // 0 -> START
  1, // 1 -> STOP
};

const std::string& RecordCmd_Name(
    RecordCmd value) {
  static const bool dummy =
      ::PROTOBUF_NAMESPACE_ID::internal::InitializeEnumStrings(
          RecordCmd_entries,
          RecordCmd_entries_by_number,
          2, RecordCmd_strings);
  (void) dummy;
  int idx = ::PROTOBUF_NAMESPACE_ID::internal::LookUpEnumName(
      RecordCmd_entries,
      RecordCmd_entries_by_number,
      2, value);
  return idx == -1 ? ::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString() :
                     RecordCmd_strings[idx].get();
}
bool RecordCmd_Parse(
    ::PROTOBUF_NAMESPACE_ID::ConstStringParam name, RecordCmd* value) {
  int int_value;
  bool success = ::PROTOBUF_NAMESPACE_ID::internal::LookUpEnumValue(
      RecordCmd_entries, 2, name, &int_value);
  if (success) {
    *value = static_cast<RecordCmd>(int_value);
  }
  return success;
}

// ===================================================================

class SessionMsg::_Internal {
 public:
};

SessionMsg::SessionMsg(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:thead.voice.proto.SessionMsg)
}
SessionMsg::SessionMsg(const SessionMsg& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite() {
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  kws_word_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_kws_word().empty()) {
    kws_word_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_kws_word(), 
      GetArenaForAllocation());
  }
  ::memcpy(&cmd_id_, &from.cmd_id_,
    static_cast<size_t>(reinterpret_cast<char*>(&kws_score_) -
    reinterpret_cast<char*>(&cmd_id_)) + sizeof(kws_score_));
  // @@protoc_insertion_point(copy_constructor:thead.voice.proto.SessionMsg)
}

inline void SessionMsg::SharedCtor() {
kws_word_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
::memset(reinterpret_cast<char*>(this) + static_cast<size_t>(
    reinterpret_cast<char*>(&cmd_id_) - reinterpret_cast<char*>(this)),
    0, static_cast<size_t>(reinterpret_cast<char*>(&kws_score_) -
    reinterpret_cast<char*>(&cmd_id_)) + sizeof(kws_score_));
}

SessionMsg::~SessionMsg() {
  // @@protoc_insertion_point(destructor:thead.voice.proto.SessionMsg)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<std::string>();
}

inline void SessionMsg::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  kws_word_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void SessionMsg::ArenaDtor(void* object) {
  SessionMsg* _this = reinterpret_cast< SessionMsg* >(object);
  (void)_this;
}
void SessionMsg::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void SessionMsg::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void SessionMsg::Clear() {
// @@protoc_insertion_point(message_clear_start:thead.voice.proto.SessionMsg)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  kws_word_.ClearToEmpty();
  ::memset(&cmd_id_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&kws_score_) -
      reinterpret_cast<char*>(&cmd_id_)) + sizeof(kws_score_));
  _internal_metadata_.Clear<std::string>();
}

const char* SessionMsg::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // .thead.voice.proto.SessionCmd cmd_id = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 8)) {
          ::PROTOBUF_NAMESPACE_ID::uint64 val = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
          _internal_set_cmd_id(static_cast<::thead::voice::proto::SessionCmd>(val));
        } else goto handle_unusual;
        continue;
      // int32 kws_id = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 16)) {
          kws_id_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // string kws_word = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 26)) {
          auto str = _internal_mutable_kws_word();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, nullptr));
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // int32 kws_score = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 32)) {
          kws_score_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
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

::PROTOBUF_NAMESPACE_ID::uint8* SessionMsg::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:thead.voice.proto.SessionMsg)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .thead.voice.proto.SessionCmd cmd_id = 1;
  if (this->_internal_cmd_id() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteEnumToArray(
      1, this->_internal_cmd_id(), target);
  }

  // int32 kws_id = 2;
  if (this->_internal_kws_id() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(2, this->_internal_kws_id(), target);
  }

  // string kws_word = 3;
  if (!this->_internal_kws_word().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_kws_word().data(), static_cast<int>(this->_internal_kws_word().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "thead.voice.proto.SessionMsg.kws_word");
    target = stream->WriteStringMaybeAliased(
        3, this->_internal_kws_word(), target);
  }

  // int32 kws_score = 4;
  if (this->_internal_kws_score() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(4, this->_internal_kws_score(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:thead.voice.proto.SessionMsg)
  return target;
}

size_t SessionMsg::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:thead.voice.proto.SessionMsg)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string kws_word = 3;
  if (!this->_internal_kws_word().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_kws_word());
  }

  // .thead.voice.proto.SessionCmd cmd_id = 1;
  if (this->_internal_cmd_id() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::EnumSize(this->_internal_cmd_id());
  }

  // int32 kws_id = 2;
  if (this->_internal_kws_id() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
        this->_internal_kws_id());
  }

  // int32 kws_score = 4;
  if (this->_internal_kws_score() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
        this->_internal_kws_score());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void SessionMsg::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::PROTOBUF_NAMESPACE_ID::internal::DownCast<const SessionMsg*>(
      &from));
}

void SessionMsg::MergeFrom(const SessionMsg& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:thead.voice.proto.SessionMsg)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_kws_word().empty()) {
    _internal_set_kws_word(from._internal_kws_word());
  }
  if (from._internal_cmd_id() != 0) {
    _internal_set_cmd_id(from._internal_cmd_id());
  }
  if (from._internal_kws_id() != 0) {
    _internal_set_kws_id(from._internal_kws_id());
  }
  if (from._internal_kws_score() != 0) {
    _internal_set_kws_score(from._internal_kws_score());
  }
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void SessionMsg::CopyFrom(const SessionMsg& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:thead.voice.proto.SessionMsg)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool SessionMsg::IsInitialized() const {
  return true;
}

void SessionMsg::InternalSwap(SessionMsg* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &kws_word_, GetArenaForAllocation(),
      &other->kws_word_, other->GetArenaForAllocation()
  );
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(SessionMsg, kws_score_)
      + sizeof(SessionMsg::kws_score_)
      - PROTOBUF_FIELD_OFFSET(SessionMsg, cmd_id_)>(
          reinterpret_cast<char*>(&cmd_id_),
          reinterpret_cast<char*>(&other->cmd_id_));
}

std::string SessionMsg::GetTypeName() const {
  return "thead.voice.proto.SessionMsg";
}


// ===================================================================

class RecordMsg::_Internal {
 public:
};

RecordMsg::RecordMsg(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:thead.voice.proto.RecordMsg)
}
RecordMsg::RecordMsg(const RecordMsg& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite() {
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  cmd_ = from.cmd_;
  // @@protoc_insertion_point(copy_constructor:thead.voice.proto.RecordMsg)
}

inline void RecordMsg::SharedCtor() {
cmd_ = 0;
}

RecordMsg::~RecordMsg() {
  // @@protoc_insertion_point(destructor:thead.voice.proto.RecordMsg)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<std::string>();
}

inline void RecordMsg::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
}

void RecordMsg::ArenaDtor(void* object) {
  RecordMsg* _this = reinterpret_cast< RecordMsg* >(object);
  (void)_this;
}
void RecordMsg::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void RecordMsg::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void RecordMsg::Clear() {
// @@protoc_insertion_point(message_clear_start:thead.voice.proto.RecordMsg)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cmd_ = 0;
  _internal_metadata_.Clear<std::string>();
}

const char* RecordMsg::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // .thead.voice.proto.RecordCmd cmd = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 8)) {
          ::PROTOBUF_NAMESPACE_ID::uint64 val = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
          _internal_set_cmd(static_cast<::thead::voice::proto::RecordCmd>(val));
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

::PROTOBUF_NAMESPACE_ID::uint8* RecordMsg::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:thead.voice.proto.RecordMsg)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .thead.voice.proto.RecordCmd cmd = 1;
  if (this->_internal_cmd() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteEnumToArray(
      1, this->_internal_cmd(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:thead.voice.proto.RecordMsg)
  return target;
}

size_t RecordMsg::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:thead.voice.proto.RecordMsg)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // .thead.voice.proto.RecordCmd cmd = 1;
  if (this->_internal_cmd() != 0) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::EnumSize(this->_internal_cmd());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void RecordMsg::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::PROTOBUF_NAMESPACE_ID::internal::DownCast<const RecordMsg*>(
      &from));
}

void RecordMsg::MergeFrom(const RecordMsg& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:thead.voice.proto.RecordMsg)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from._internal_cmd() != 0) {
    _internal_set_cmd(from._internal_cmd());
  }
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void RecordMsg::CopyFrom(const RecordMsg& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:thead.voice.proto.RecordMsg)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool RecordMsg::IsInitialized() const {
  return true;
}

void RecordMsg::InternalSwap(RecordMsg* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(cmd_, other->cmd_);
}

std::string RecordMsg::GetTypeName() const {
  return "thead.voice.proto.RecordMsg";
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace voice
}  // namespace thead
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::thead::voice::proto::SessionMsg* Arena::CreateMaybeMessage< ::thead::voice::proto::SessionMsg >(Arena* arena) {
  return Arena::CreateMessageInternal< ::thead::voice::proto::SessionMsg >(arena);
}
template<> PROTOBUF_NOINLINE ::thead::voice::proto::RecordMsg* Arena::CreateMaybeMessage< ::thead::voice::proto::RecordMsg >(Arena* arena) {
  return Arena::CreateMessageInternal< ::thead::voice::proto::RecordMsg >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
