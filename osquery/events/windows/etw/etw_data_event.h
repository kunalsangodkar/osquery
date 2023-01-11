/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <variant>

#include <osquery/events/windows/etw/etw_krabs.h>

namespace osquery {

/**
 * @brief File delete event payload
 */
struct EtwDeletePathData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  // Path of File Deleted
  std::string FilePath;

  /// Time
  FILETIME EventTime{0};

  /// Flag to indicate that user data has been gathered
  bool UserDataReady{false};
};

using EtwDeletePathDataRef = std::shared_ptr<EtwDeletePathData>;

/**
 * @brief File delete event payload
 */
struct EtwNameDeleteData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  // Path of File created
  std::string FileName;

  /// Time
  FILETIME EventTime{0};

  /// Flag to indicate that user data has been gathered
  bool UserDataReady{false};
};

using EtwNameDeleteDataRef = std::shared_ptr<EtwNameDeleteData>;


/**
 * @brief Create New File event payload
 */
struct EtwCreateNewFileData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  // Path of File created
  std::string FileName;

  /// Time
  FILETIME EventTime{0};

  /// Flag to indicate that user data has been gathered
  bool UserDataReady{false};
};

using EtwCreateNewFileDataRef = std::shared_ptr<EtwCreateNewFileData>;

/**
 * @brief Create File event payload
 */
struct EtwCreateData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  // Path of File created
  std::string FileName;

  /// Time
  FILETIME EventTime{0};

  /// File object
  uint64_t FileObj;

  /// Flag to indicate that user data has been gathered
  bool UserDataReady{false};
};

using EtwCreateDataRef = std::shared_ptr<EtwCreateData>;

/**
 * @brief Rename File event payload
 */
struct EtwRenamePathData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  // Old file path
  std::string OldFilePath;

  // Path of File Renamed
  std::string RenamedFilePath;

  /// Time
  FILETIME EventTime{0};

  /// File object
  uint64_t FileObj;

  /// Flag to indicate that user data has been gathered
  bool UserDataReady{false};
};

using EtwRenamePathDataRef = std::shared_ptr<EtwRenamePathData>;
/**
 * @brief Process start event payload
 */
struct EtwProcessStartData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  /// Parent Process ID
  std::uint32_t ParentProcessId{0};

  /// Process Creation Time
  FILETIME CreateTime{0};

  /// Session ID
  std::uint32_t SessionId{0};

  /// Process Flags
  std::uint32_t Flags{0};

  /// Process Name
  std::string ImageName;

  /// Command Line
  std::string Cmdline;

  /// Mandatory Label SID
  std::string MandatoryLabelSid;

  /// User SID
  std::string UserSid;

  /// User Name
  std::string UserName;

  /// Token Elevation Type
  std::uint32_t TokenElevationType{0};

  /// Token Elevation Type Description
  std::string TokenElevationTypeInfo;

  /// Token IsElevated
  std::uint32_t TokenIsElevated{0};

  /// Process Sequence Number
  std::uint64_t ProcessSequenceNumber{0};

  /// Parent Process Sequence Number
  std::uint64_t ParentProcessSequenceNumber{0};

  /// Flag to indicate that kernel data has been gathered
  bool KernelDataReady{false};

  /// Flag to indicate that user data has been gathered
  bool UserDataReady{false};
};

using EtwProcStartDataRef = std::shared_ptr<EtwProcessStartData>;

/**
 * @brief Process stop event payload
 */
struct EtwProcessStopData final {
  /// Process ID
  std::uint32_t ProcessId{0};

  /// Parent Process ID
  std::uint32_t ParentProcessId{0};

  /// Exit Code
  std::int32_t ExitCode{0};

  /// Process Flags
  std::uint32_t Flags{0};

  /// Process Name
  std::string ImageName;

  /// Session ID
  std::uint32_t SessionId{0};

  /// Command Line
  std::string Cmdline;

  /// User SID
  std::string UserSid;

  /// User Name
  std::string UserName;
};

using EtwProcStopDataRef = std::shared_ptr<EtwProcessStopData>;

/**
 * @brief ETW Event Payload
 */
using EtwPayloadVariant = std::variant<std::monostate,
                                       EtwProcStartDataRef,
                                       EtwProcStopDataRef,
                                       EtwCreateNewFileDataRef,
                                       EtwNameDeleteDataRef,
                                       EtwCreateDataRef,
                                       EtwRenamePathDataRef,
                                       EtwDeletePathDataRef >;

/**
 * @brief Event types
 * The event type is used to tag an ETW event to an specific data type that will
 * be used to dispatch events to different provider post processors
 */
enum class EtwEventType { 
    Invalid, 
    ProcessStart, 
    ProcessStop, 
    CreateNewFile, 
    NameDelete,
    Create,
    RenamePath,
    DeletePath
};

/**
 * @brief Event Type string representation
 */
const auto kEtwEventTypeStrings = std::unordered_map<EtwEventType, std::string>{
    {EtwEventType::Invalid, "Invalid"},
    {EtwEventType::ProcessStart, "ProcessStart"},
    {EtwEventType::ProcessStop, "ProcessStop"},
    {EtwEventType::CreateNewFile, "CreateNewFile"},
    {EtwEventType::NameDelete, "NameDelete"},
    {EtwEventType::Create, "Create"},
    {EtwEventType::RenamePath, "RenamePath"},
    {EtwEventType::DeletePath, "DeletePath"}};

/**
 * @brief ETW Event Header
 */
struct EtwHeaderData final {
  /// ETW event header
  EVENT_HEADER RawHeader;

  // Event Type
  EtwEventType Type{EtwEventType::Invalid};

  // Event Type Info
  std::string TypeInfo;

  /// Process creation windows timestamp
  ULONGLONG WinTimestamp{0};

  /// Process creation unix timestamp
  LONGLONG UnixTimestamp{0};
};

/**
 * @brief ETW Event Data structure
 */
struct EtwEventData {
  EtwHeaderData Header;
  EtwPayloadVariant Payload;
};

using EtwEventDataRef = std::shared_ptr<EtwEventData>;
using EtwEventTypes = std::vector<EtwEventType>;

} // namespace osquery
