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

#include "rsdelegatecompositebuffermanager_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>

#include "rs_delegate_composite_buffer_manager.h"
#include "surface.h"
#include "surface_buffer.h"
#include "sync_fence.h"

#include "transaction/rs_interfaces.h"
#include "ui/rs_ui_context_manager.h"

namespace OHOS {
using namespace Rosen;
namespace {
constexpr size_t STR_LEN = 16;
constexpr uint32_t MAX_DAMAGE_RECTS = 16;
constexpr uint32_t SET_BUFFER_REPEAT = 4;
constexpr uint8_t MANAGER_COUNT = 2;
} // namespace

// The manager hands the released fence fd to the callback, which takes its ownership.
RSDelegateCompositeBufferManager::BufferReleaseCallback GetReleaseCallback()
{
    return [](int fd) {
        if (fd >= 0) {
            close(fd);
        }
    };
}

void SetBufferFuzzTest(const sptr<RSDelegateCompositeBufferManager>& manager)
{
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    RSDelegateCompositeBufferManager::BufferReleaseCallback callback = GetReleaseCallback();
    manager->SetBuffer(nullptr, UniqueFd(INVALID_FD), callback);
    manager->SetBuffer(buffer, UniqueFd(INVALID_FD), nullptr);
    manager->SetBuffer(buffer, UniqueFd(INVALID_FD), callback);
    int pipeFds[2] = { INVALID_FD, INVALID_FD };
    if (pipe(pipeFds) == 0) {
        manager->SetBuffer(buffer, UniqueFd(pipeFds[0]), callback);
        sptr<SyncFence> fence = new SyncFence(pipeFds[1]);
        manager->ReleaseBuffer(buffer->GetSeqNum(), fence);
    }
    // Repeated set/release cycles exercise the queued/released cache states and callback map.
    for (uint32_t i = 0; i < SET_BUFFER_REPEAT; i++) {
        manager->SetBuffer(buffer, UniqueFd(INVALID_FD), callback);
        manager->ReleaseBuffer(buffer->GetSeqNum(), SyncFence::InvalidFence());
    }
}

void ReleaseBufferFuzzTest(FuzzedDataProvider& fdp, const sptr<RSDelegateCompositeBufferManager>& manager)
{
    uint32_t sequence = fdp.ConsumeIntegral<uint32_t>();
    manager->ReleaseBuffer(sequence, nullptr);
    manager->ReleaseBuffer(sequence, SyncFence::InvalidFence());
    // The second call with the same sequence hits the path where the callback was already erased.
    manager->ReleaseBuffer(sequence, SyncFence::InvalidFence());
}

void CleanBufferFuzzTest(FuzzedDataProvider& fdp, const sptr<RSDelegateCompositeBufferManager>& manager)
{
    manager->CleanBuffer(fdp.ConsumeBool());
    manager->CleanBuffer(true);
    manager->CleanBuffer(false);
}

void PropertySetterFuzzTest(FuzzedDataProvider& fdp, const sptr<RSDelegateCompositeBufferManager>& manager)
{
    manager->SetDesiredPresentTime(fdp.ConsumeIntegral<int64_t>());
    // uint8_t keeps a sane hit rate on valid enum values while retaining out-of-range coverage.
    manager->SetBufferTransform(static_cast<GraphicTransformType>(fdp.ConsumeIntegral<uint8_t>()));
    manager->SetDelegateDstRect(fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>(),
        fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>());
    manager->SetDelegateSrcRect(fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>(),
        fdp.ConsumeFloatingPoint<float>(), fdp.ConsumeFloatingPoint<float>());
    manager->SetDelegateMode(fdp.ConsumeBool());
}

void DamageRegionFuzzTest(FuzzedDataProvider& fdp, const sptr<RSDelegateCompositeBufferManager>& manager)
{
    uint32_t count = fdp.ConsumeIntegralInRange<uint32_t>(0, MAX_DAMAGE_RECTS);
    std::vector<Rect> rects;
    for (uint32_t i = 0; i < count; i++) {
        Rect rect { fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(),
            fdp.ConsumeIntegral<int32_t>() };
        rects.push_back(rect);
    }
    manager->SetDamageRegion(rects);
    // SetBuffer consumes the damage region and flips the rects against the buffer height.
    manager->SetBuffer(SurfaceBuffer::Create(), UniqueFd(INVALID_FD), GetReleaseCallback());
    manager->SetDamageRegion({});
    // Empty damage region falls back to the whole buffer size.
    manager->SetBuffer(SurfaceBuffer::Create(), UniqueFd(INVALID_FD), GetReleaseCallback());
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider& fdp, uint8_t tarPos)
{
    static ScreenId screenId = RSInterfaces::GetInstance().GetDefaultScreenId();
    static sptr<IRemoteObject> connectToRender = RSInterfaces::GetInstance().GetConnectToRenderToken(screenId);
    static std::shared_ptr<RSUIContext> rsUIContext =
        RSUIContextManager::MutableInstance().CreateRSUIContext(connectToRender);
    static sptr<Surface> surface = Surface::CreateSurfaceAsConsumer("rsdelegatecomposite_fuzz");
    NodeId nodeId = fdp.ConsumeIntegral<NodeId>();
    std::string name = fdp.ConsumeRandomLengthString(STR_LEN);
    // The bare manager exercises the null context/surface guards, the full one the transaction paths.
    sptr<RSDelegateCompositeBufferManager> managers[MANAGER_COUNT] = {
        new RSDelegateCompositeBufferManager(nullptr, nullptr, nodeId, name),
        new RSDelegateCompositeBufferManager(rsUIContext, surface, nodeId, name),
    };
    const sptr<RSDelegateCompositeBufferManager>& manager = managers[tarPos];
    DamageRegionFuzzTest(fdp, manager);
    PropertySetterFuzzTest(fdp, manager);
    SetBufferFuzzTest(manager);
    ReleaseBufferFuzzTest(fdp, manager);
    CleanBufferFuzzTest(fdp, manager);
    // The selected manager destructs here, invoking the remaining release callbacks with an invalid fd.
    // Drain the commands queued on the static context, otherwise the transaction
    // data (holding the buffers) grows across iterations and exhausts memory.
    if (rsUIContext) {
        rsUIContext->GetRSTransaction()->FlushImplicitTransaction();
    }
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    uint8_t tarPos = fdp.ConsumeIntegral<uint8_t>() % OHOS::MANAGER_COUNT;
    OHOS::DoSomethingInterestingWithMyAPI(fdp, tarPos);
    return 0;
}