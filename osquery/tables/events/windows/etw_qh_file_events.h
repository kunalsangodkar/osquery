/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/eventsubscriber.h>
#include <osquery/events/windows/etw/etw_qh_publisher_files.h>

#define SYSTEM_PID      4

namespace osquery {

class EtwQhFileEventSubscriber final
    : public EventSubscriber<EtwQhPublisherFiles> {
 public:
  virtual ~EtwQhFileEventSubscriber() override = default;
  virtual Status init() override;

  Status eventCallback(const ECRef& event_context,
                       const SCRef& subscription_context);
};

} // namespace osquery
