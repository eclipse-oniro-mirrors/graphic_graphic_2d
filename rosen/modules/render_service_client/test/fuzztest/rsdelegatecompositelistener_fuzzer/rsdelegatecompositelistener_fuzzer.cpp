/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "rsdelegatecompositelistener_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <queue>
#include <thread>
#include <unistd.h>

#include "rs_delegate_composite_listener.h"

#include "command/rs_command.h"
#include "ipc_callbacks/rs_transaction_callback.h"
#include "transaction/rs_interfaces.h"

namespace OHOS {
using namespace Rosen;
namespace {
constexpr uint8_t LISTENER_COUNT = 2;
constexpr uint8_t MAX_COMMAND_REPEAT = 8;
} // namespace

sptr<IRemoteObject> GetConnectToRenderToken()
{
    static ScreenId screenId = RSInterfaces::GetInstance().GetDefaultScreenId();
    static sptr<IRemoteObject> connectToRender = RSInterfaces::GetInstance().GetConnectToRenderToken(screenId);
    return connectToRender;
}

SurfaceTransactionListener::OnCompleteCallback GetOnCompleteCallback()
{
    return [](uint64_t timestamp, uint64_t srcId, std::queue<uint64_t> seqNums) {
        (void)timestamp;
        (void)srcId;
        while (!seqNums.empty()) {
            seqNums.pop();
        }
    };
}

SurfaceNodeBufferReleaseListener::OnBufferCompleteCallback GetOnBufferCompleteCallback()
{
    return [](std::queue<OnCompletedRet> queue) {
        while (!queue.empty()) {
            queue.pop();
        }
    };
}

void TransactionListenerFuzzTest(FuzzedDataProvider& fdp)
{
    bool useNullToken = fdp.ConsumeBool();
    sptr<IRemoteObject> token = useNullToken ? nullptr : GetConnectToRenderToken();
    sptr<SurfaceTransactionListener> listener = new SurfaceTransactionListener(token);
    uint64_t uniqueId = listener->GetUniqueId();
    (void)uniqueId;
    uint64_t cmdSeqNum = 0;
    std::unique_ptr<RSCommand> command = listener->GetCommand(cmdSeqNum);
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % MAX_COMMAND_REPEAT;
    for (uint8_t i = 0; i < count; i++) {
        command = listener->GetCommand(cmdSeqNum);
    }
    // GetCommand on a foreign thread hits the workTid guard and returns nullptr.
    std::thread worker([&listener]() {
        uint64_t otherSeq = 0;
        std::unique_ptr<RSCommand> otherCmd = listener->GetCommand(otherSeq);
    });
    worker.join();
    listener->UnRegisterCommandCompleteCallBack();
    bool useNullCallback = fdp.ConsumeBool();
    SurfaceTransactionListener::OnCompleteCallback callback = useNullCallback ? nullptr : GetOnCompleteCallback();
    listener->RegisterCommandCompleteCallBack(callback);
    // The second register hits the repeat-register guard.
    listener->RegisterCommandCompleteCallBack(GetOnCompleteCallback());
    listener->UnRegisterCommandCompleteCallBack();
    // The second unregister hits the invalid-params guard.
    listener->UnRegisterCommandCompleteCallBack();
    // The listener destructs here, running UnRegisterCommandCompleteCallBack again.
}

void BufferReleaseListenerFuzzTest(FuzzedDataProvider& fdp)
{
    SurfaceNodeBufferReleaseListener& instance = SurfaceNodeBufferReleaseListener::GetInstance();
    bool useNullToken = fdp.ConsumeBool();
    sptr<IRemoteObject> token = useNullToken ? nullptr : GetConnectToRenderToken();
    instance.SetConnectToRender(token);
    // The singleton keeps its token across inputs, so a second set hits the already-set guard.
    instance.SetConnectToRender(token);
    instance.UnRegisterReleaseBufferCallBack();
    bool useNullCallback = fdp.ConsumeBool();
    SurfaceNodeBufferReleaseListener::OnBufferCompleteCallback callback =
        useNullCallback ? nullptr : GetOnBufferCompleteCallback();
    instance.RegisterReleaseBufferCallBack(callback);
    // The second register hits the repeat-register guard.
    instance.RegisterReleaseBufferCallBack(GetOnBufferCompleteCallback());
    instance.UnRegisterReleaseBufferCallBack();
    // The second unregister hits the invalid-params guard.
    instance.UnRegisterReleaseBufferCallBack();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    uint8_t tarPos = fdp.ConsumeIntegral<uint8_t>() % OHOS::LISTENER_COUNT;
    if (tarPos == 0) {
        OHOS::TransactionListenerFuzzTest(fdp);
    } else {
        OHOS::BufferReleaseListenerFuzzTest(fdp);
    }
    return 0;
}