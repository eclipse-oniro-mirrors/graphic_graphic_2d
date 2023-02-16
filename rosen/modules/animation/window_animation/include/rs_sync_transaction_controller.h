/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WINDOW_ANIMATION_RS_SYNC_TRANSACTION_CONTROLLER_H
#define WINDOW_ANIMATION_RS_SYNC_TRANSACTION_CONTROLLER_H

#include <vector>
#include <refbase.h>
#include <mutex>

#include "event_handler.h"

namespace OHOS {
namespace Rosen {
class RSProcessTransactionController;

class RSSyncTransactionController : public RefBase {
public:
    explicit RSSyncTransactionController();
    virtual ~RSSyncTransactionController() = default;

    void CreateTransactionFinished();

    void StartTransactionSyncForProcess();

    void OpenSyncTransaction();

    void AddProcessTransactionController(const sptr<RSProcessTransactionController>& controller);

    uint64_t GetSyncId() const
    {
        return syncId_;
    }

    void AddReleaseCallback(const std::function<void()>& callback)
    {
        releaseCallbacks_.emplace_back(callback);
    }

protected:
    void CloseSyncTransaction();

private:
    uint64_t GenerateSyncId();
    void CallReleaseCallbacks();

    int32_t processCount_ { 0 };
    int32_t syncTransactionCount_ { 0 };
    uint64_t syncId_ { 0 };
    std::vector<std::function<void()>> releaseCallbacks_;
    std::vector<sptr<RSProcessTransactionController>> controllers_;
    std::mutex mutex_;
    bool needCloseSync_ { false };
    std::shared_ptr<AppExecFwk::EventRunner> runner_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
};
} // namespace Rosen
} // namespace OHOS

#endif // WINDOW_ANIMATION_RS_SYNC_TRANSACTION_CONTROLLER_H
