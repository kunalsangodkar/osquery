/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <variant>

#include <osquery/core/flags.h>
#include <osquery/events/events.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/events/windows/etw_qh_file_events.h>

namespace osquery {

REGISTER_ETW_SUBSCRIBER(EtwQhFileEventSubscriber, "etw_qh_file_events");
DECLARE_bool(enable_etw_qh_file_events);

Status EtwQhFileEventSubscriber::init() {
  if (!FLAGS_enable_etw_qh_file_events) {
    return Status::failure("subscriber disabled via configuration.");
  }
  auto subscription_context = createSubscriptionContext();
  subscribe(&EtwQhFileEventSubscriber::eventCallback, subscription_context);

  return Status::success();
}

Status EtwQhFileEventSubscriber::eventCallback(
    const ECRef& event_context, const SCRef& event_subscription) {
  if ((!event_context) || (!event_context->data)) {
    return Status::failure("Invalid event context");
  }

  // New event row to capture the incoming ETW event data
  Row newRow;

  // Sugar syntax to facilitate the access to the event header
  const auto& eventHeader = event_context->data->Header;

  // For now, capture only system process events.
  if (SYSTEM_PID != eventHeader.RawHeader.ProcessId) {
    return Status::success();
  }
  // Common fields
  newRow["type"] = SQL_TEXT(eventHeader.TypeInfo);
  newRow["datetime"] = BIGINT(eventHeader.UnixTimestamp);
  newRow["time_windows"] = BIGINT(eventHeader.WinTimestamp);
  newRow["pid"] = BIGINT(eventHeader.RawHeader.ProcessId);

  if (eventHeader.Type == EtwEventType::CreateNewFile) {
    // events handling

    if (!std::holds_alternative<EtwCreateNewFileDataRef>(
            event_context->data->Payload)) {
      return Status::failure("Invalid event payload");
    }

    // Sugar syntax to facilitate the access to the event payload
    const auto& eventPayload =
        std::get<EtwCreateNewFileDataRef>(event_context->data->Payload);

    if (!eventPayload) {
      return Status::failure("Event payload was null");
    }

    newRow["path"] = SQL_TEXT(eventPayload->FileName);

    std::vector<Row> rowList;
    rowList.push_back(std::move(newRow));
    addBatch(rowList, eventHeader.UnixTimestamp);

  } 
  else if (eventHeader.Type == EtwEventType::NameDelete) {
    // File delete events handling

    if (!std::holds_alternative<EtwNameDeleteDataRef>(
            event_context->data->Payload)) {
      return Status::failure("Invalid event payload");
    }

    // Sugar syntax to facilitate the access to the event payload
    const auto& eventPayload =
        std::get<EtwNameDeleteDataRef>(event_context->data->Payload);

    if (!eventPayload) {
      return Status::failure("Event payload was null");
    }

    newRow["path"] = SQL_TEXT(eventPayload->FileName);

    std::vector<Row> rowList;
    rowList.push_back(std::move(newRow));
    addBatch(rowList, eventHeader.UnixTimestamp);
  } 
  else if (eventHeader.Type == EtwEventType::RenamePath){
    if (!std::holds_alternative<EtwRenamePathDataRef>(
            event_context->data->Payload)) {
      return Status::failure("Invalid event payload");
    }

    // Sugar syntax to facilitate the access to the event payload
    const auto& eventPayload =
        std::get<EtwRenamePathDataRef>(event_context->data->Payload);

    if (!eventPayload) {
      return Status::failure("Event payload was null");
    }

    newRow["new_path"] = SQL_TEXT(eventPayload->RenamedFilePath);
    newRow["path"] = SQL_TEXT(eventPayload->OldFilePath);

    std::vector<Row> rowList;
    rowList.push_back(std::move(newRow));
    addBatch(rowList, eventHeader.UnixTimestamp);
  } 
  else if (eventHeader.Type == EtwEventType::DeletePath) {
    // File delete events handling

    if (!std::holds_alternative<EtwDeletePathDataRef>(
            event_context->data->Payload)) {
      return Status::failure("Invalid event payload");
    }

    // Sugar syntax to facilitate the access to the event payload
    const auto& eventPayload =
        std::get<EtwDeletePathDataRef>(event_context->data->Payload);

    if (!eventPayload) {
      return Status::failure("Event payload was null");
    }

    newRow["path"] = SQL_TEXT(eventPayload->FilePath);

    std::vector<Row> rowList;
    rowList.push_back(std::move(newRow));
    addBatch(rowList, eventHeader.UnixTimestamp);
  }
  return Status::success();
}

} // namespace osquery
