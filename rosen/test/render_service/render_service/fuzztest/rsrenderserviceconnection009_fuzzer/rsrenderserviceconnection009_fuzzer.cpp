/*
* Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "rsrenderserviceconnection009_fuzzer.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>
#include <unistd.h>
#include <unordered_map>

#include "message_parcel.h"
#include "securec.h"

#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/main_thread/rs_render_service_connection.h"
#include "platform/ohos/rs_irender_service.h"
#include "transaction/rs_render_service_connection_stub.h"
#include "transaction/rs_transaction_proxy.h"

namespace OHOS {
namespace Rosen {
DECLARE_INTERFACE_DESCRIPTOR(u"ohos.rosen.RenderServiceConnection");
auto g_pid = getpid();
auto screenManagerPtr_ = impl::RSScreenManager::GetInstance();
auto mainThread_ = RSMainThread::Instance();
sptr<RSIConnectionToken> token_ = new IRemoteStub<RSIConnectionToken>();

DVSyncFeatureParam dvsyncParam;
auto generator = CreateVSyncGenerator();
auto appVSyncController = new VSyncController(generator, 0);
sptr<VSyncDistributor> appVSyncDistributor_ = new VSyncDistributor(appVSyncController, "app", dvsyncParam);
sptr<RSRenderServiceConnectionStub> connectionStub_ = new RSRenderServiceConnection(
    g_pid, nullptr, mainThread_, screenManagerPtr_, token_->AsObject(), appVSyncDistributor_);
namespace {
const uint8_t DO_SHOW_WATERMARK = 0;
const uint8_t DO_SET_WATERMARK = 1;
const uint8_t DO_REGISTER_TRANSACTION_DATA_CALLBACK = 2;
const uint8_t TARGET_SIZE = 3;

sptr<RSIRenderServiceConnection> CONN = nullptr;
sptr<RSRenderServiceConnectionStub> rsConnStub_ = nullptr;
const uint8_t* DATA = nullptr;
size_t g_size = 0;
size_t g_pos;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (DATA == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

template<>
std::string GetData()
{
    size_t objectSize = GetData<uint8_t>();
    std::string object(objectSize, '\0');
    if (DATA == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    object.assign(reinterpret_cast<const char*>(DATA + g_pos), objectSize);
    g_pos += objectSize;
    return object;
}

bool Init(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    DATA = data;
    g_size = size;
    g_pos = 0;
    return true;
}
} // namespace

namespace Mock {
void CreateVirtualScreenStubbing(ScreenId screenId)
{
    uint32_t width = GetData<uint32_t>();
    uint32_t height = GetData<uint32_t>();
    int32_t flags = GetData<int32_t>();
    std::string name = GetData<std::string>();
    // Random name of IBufferProducer is not necessary
    sptr<IBufferProducer> bp = IConsumerSurface::Create("DisplayNode")->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);

    CONN->CreateVirtualScreen(name, width, height, pSurface, screenId, flags);
}
} // namespace Mock

void DoShowWatermark()
{
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SHOW_WATERMARK);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    MessageOption option;

    bool isShow = GetData<bool>();
    dataParcel.WriteInterfaceToken(GetDescriptor());
    dataParcel.WriteBool(isShow);
    connectionStub_->OnRemoteRequest(code, dataParcel, replyParcel, option);
}

void DoSetWatermark()
{
    std::string name = "name";
    MessageParcel dataP;
    MessageParcel reply;
    MessageOption option;
    if (!dataP.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    option.SetFlags(MessageOption::TF_SYNC);
    dataP.WriteString(name);
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceConnectionInterfaceCode::SET_WATERMARK);
    if (connectionStub_ == nullptr) {
        return;
    }
    connectionStub_->OnRemoteRequest(code, dataP, reply, option);
}

void DoRegisterTransactionDataCallback()
{
    MessageParcel dataP;
    MessageParcel reply;
    MessageOption option;
    if (!dataP.WriteInterfaceToken(RSIRenderServiceConnection::GetDescriptor())) {
        return;
    }
    auto pid = GetData<int32_t>();
    auto timeStamp = GetData<uint64_t>();
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    dataP.WriteInt32(pid);
    dataP.WriteUint64(timeStamp);
    dataP.WriteRemoteObject(remoteObject);
    uint32_t code = static_cast<uint32_t>(
        RSIRenderServiceConnectionInterfaceCode::REGISTER_TRANSACTION_DATA_CALLBACK);
    if (rsConnStub_ == nullptr) {
        return;
    }
    rsConnStub_->OnRemoteRequest(code, dataP, reply, option);
}

} // namespace Rosen
} // namespace OHOS

/* Fuzzer envirement */
extern "C" int LLVMFuzzerInitialize(const uint8_t* data, size_t size)
{
    auto newPid = getpid();
    auto mainThread = OHOS::Rosen::RSMainThread::Instance();
    auto screenManagerPtr = OHOS::Rosen::impl::RSScreenManager::GetInstance();
    OHOS::Rosen::CONN = new OHOS::Rosen::RSRenderServiceConnection(
        newPid,
        nullptr,
        mainThread,
        screenManagerPtr,
        nullptr,
        nullptr
    );
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!OHOS::Rosen::Init(data, size)) {
        return -1;
    }
    /* Run your code on data */
    uint8_t tarPos = OHOS::Rosen::GetData<uint8_t>() % OHOS::Rosen::TARGET_SIZE;
    switch (tarPos) {
        case OHOS::Rosen::DO_SHOW_WATERMARK:
            OHOS::Rosen::DoShowWatermark();
            break;
        case OHOS::Rosen::DO_REGISTER_TRANSACTION_DATA_CALLBACK:
            OHOS::Rosen::DoRegisterTransactionDataCallback();
            break;
        case OHOS::Rosen::DO_SET_WATERMARK:
            OHOS::Rosen::DoSetWatermark();
            break;
        default:
            return -1;
    }
    return 0;
}