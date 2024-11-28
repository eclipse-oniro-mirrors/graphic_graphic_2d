/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "rsrenderserviceconnection_fuzzer.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <unordered_map>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "ipc_object_proxy.h"
#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "securec.h"

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
#include "ipc_callbacks/pointer_render/pointer_luminance_callback_stub.h"
#endif
#include "ipc_callbacks/rs_occlusion_change_callback_stub.h"
#include "pipeline/rs_render_service.h"
#include "pipeline/rs_render_service_connection.h"
#include "platform/ohos/rs_render_service_connect_hub.cpp"
#include "screen_manager/rs_screen_manager.h"
#include "transaction/rs_render_service_client.h"
#include "transaction/rs_render_service_connection_stub.h"
#include "transaction/rs_transaction_proxy.h"

namespace OHOS {
namespace Rosen {
constexpr size_t SCREEN_WIDTH = 100;
constexpr size_t SCREEN_HEIGHT = 100;
sptr<RSIRenderServiceConnection> rsConn_ = nullptr;
namespace {
const uint8_t* g_data = nullptr;
size_t g_size = 0;
size_t g_pos;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_data == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_data + g_pos, objectSize);
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
    if (g_data == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    object.assign(reinterpret_cast<const char*>(g_data + g_pos), objectSize);
    g_pos += objectSize;
    return object;
}
} // namespace

bool Init(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    g_data = data;
    g_size = size;
    g_pos = 0;
    
    rsConn_ = RSRenderServiceConnectHub::GetRenderService();
    if (rsConn_ == nullptr) {
        return false;
    }
    return true;
}

bool DoRegisterApplicationAgent()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    uint32_t pid = GetData<uint32_t>();
    MessageParcel message;
    auto remoteObject = message.ReadRemoteObject();
    sptr<IApplicationAgent> app = iface_cast<IApplicationAgent>(remoteObject);
    rsConn_->RegisterApplicationAgent(pid, app);
    return true;
}

bool DoCommitTransaction()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    auto transactionData = std::make_unique<RSTransactionData>();
    rsConn_->CommitTransaction(transactionData);
    return true;
}

class DerivedSyncTask : public RSSyncTask {
public:
    using RSSyncTask::RSSyncTask;
    bool CheckHeader(Parcel& parcel) const override
    {
        return true;
    }
    bool ReadFromParcel(Parcel& parcel) override
    {
        return true;
    }
    bool Marshalling(Parcel& parcel) const override
    {
        return true;
    }
    void Process(RSContext& context) override {}
};
bool DoExecuteSynchronousTask()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    uint64_t timeoutNS = GetData<uint64_t>();
    auto task = std::make_shared<DerivedSyncTask>(timeoutNS);
    rsConn_->ExecuteSynchronousTask(task);
    return true;
}

bool DoGetMemoryGraphic()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    int pid = GetData<int>();
    rsConn_->GetMemoryGraphic(pid);
    return true;
}

bool DoGetMemoryGraphics()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    rsConn_->GetMemoryGraphics();
    return true;
}

bool DoCreateNodeAndSurface()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    RSSurfaceRenderNodeConfig config = { .id = 0, .name = "test" };
    rsConn_->CreateNode(config);
    rsConn_->CreateNodeAndSurface(config);
    return true;
}

bool DoGetScreenBacklight()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    uint32_t level = GetData<uint32_t>();
    rsConn_->SetScreenBacklight(id, level);
    rsConn_->GetScreenBacklight(id);
    return true;
}

bool DoGetScreenType()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    uint32_t level = GetData<uint32_t>();
    RSScreenType type = (RSScreenType)level;
    rsConn_->GetScreenType(id, type);
    return true;
}

bool DoRegisterBufferAvailableListener()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    bool isFromRenderThread = GetData<bool>();
    sptr<RSIBufferAvailableCallback> cb = nullptr;
    rsConn_->RegisterBufferAvailableListener(id, cb, isFromRenderThread);
    return true;
}

bool DoSetScreenSkipFrameInterval()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    uint32_t skipFrameInterval = GetData<uint32_t>();
    rsConn_->SetScreenSkipFrameInterval(id, skipFrameInterval);
    return true;
}

bool DoSetVirtualScreenResolution()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    rsConn_->SetVirtualScreenResolution(id, SCREEN_WIDTH, SCREEN_HEIGHT);
    rsConn_->GetVirtualScreenResolution(id);
    return true;
}

bool DoGetScreenSupportedColorGamuts()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    std::vector<ScreenColorGamut> mode;
    ScreenId id = GetData<uint64_t>();
    uint32_t screenCol = GetData<uint32_t>();
    mode.push_back((ScreenColorGamut)screenCol);
    rsConn_->GetScreenSupportedColorGamuts(id, mode);
    std::vector<ScreenHDRMetadataKey> keys;
    keys.push_back((ScreenHDRMetadataKey)screenCol);
    rsConn_->GetScreenSupportedMetaDataKeys(id, keys);
    return true;
}

bool DoGetScreenSupportedModes()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    rsConn_->GetScreenSupportedModes(id);
    return true;
}

bool DoGetScreenColorGamut()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    int32_t modeIdx = GetData<int32_t>();
    rsConn_->SetScreenColorGamut(id, modeIdx);
    uint32_t mod = GetData<uint32_t>();
    ScreenColorGamut mode = (ScreenColorGamut)mod;
    rsConn_->GetScreenColorGamut(id, mode);
    return true;
}

bool DoSetScreenPowerStatus()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    uint32_t status = GetData<uint32_t>();
    rsConn_->SetScreenPowerStatus(id, static_cast<ScreenPowerStatus>(status));
    rsConn_->GetScreenPowerStatus(id);
    return true;
}

bool DoSetScreenGamutMap()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    uint32_t mapMode = GetData<uint32_t>();
    ScreenGamutMap mode = (ScreenGamutMap)mapMode;
    rsConn_->SetScreenGamutMap(id, mode);
    rsConn_->GetScreenGamutMap(id, mode);
    return true;
}

bool DoSetAppWindowNum()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint32_t num = GetData<uint32_t>();
    rsConn_->SetAppWindowNum(num);
    return true;
}

bool DoCreateVirtualScreen()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    int32_t flags = GetData<int32_t>();
    sptr<IConsumerSurface> cSurface = IConsumerSurface::Create("DisplayNode");
    sptr<IBufferProducer> bp = cSurface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(bp);
    rsConn_->CreateVirtualScreen("name", SCREEN_WIDTH, SCREEN_HEIGHT, pSurface, id, flags);
    rsConn_->SetVirtualScreenSurface(id, pSurface);
    rsConn_->RemoveVirtualScreen(id);
    return true;
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
bool DoSetPointerColorInversionConfig()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    float darkBuffer = GetData<float>();
    float brightBuffer = GetData<float>();
    int64_t interval = GetData<int64_t>();
    int32_t rangeSize = GetData<int32_t>();
    rsConn_->SetPointerColorInversionConfig(darkBuffer, brightBuffer, interval, rangeSize);
    return true;
}

bool DoSetPointerColorInversionEnabled()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    bool enable = GetData<bool>();
    rsConn_->SetPointerColorInversionEnabled(enable);
    return true;
}

class CustomPointerLuminanceChangeCallback : public RSPointerLuminanceChangeCallbackStub {
public:
    explicit CustomPointerLuminanceChangeCallback(const PointerLuminanceChangeCallback &callback) : cb_(callback) {}
    ~CustomPointerLuminanceChangeCallback() override {};
 
    void OnPointerLuminanceChanged(int32_t brightness) override
    {
        if (cb_ != nullptr) {
            cb_(brightness);
        }
    }

private:
    PointerLuminanceChangeCallback cb_;
};

bool DoRegisterPointerLuminanceChangeCallback()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    PointerLuminanceChangeCallback callback = [](int32_t brightness) {};
    sptr<CustomPointerLuminanceChangeCallback> cb = new CustomPointerLuminanceChangeCallback(callback);
    rsConn_->RegisterPointerLuminanceChangeCallback(cb);
    return true;
}

bool DoUnRegisterPointerLuminanceChangeCallback()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    rsConn_->UnRegisterPointerLuminanceChangeCallback();
    return true;
}
#endif

bool DoSetScreenActiveMode()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    uint32_t modeId = GetData<uint32_t>();
    rsConn_->SetScreenActiveMode(id, modeId);
    rsConn_->GetScreenActiveMode(id);
    return true;
}

bool DoSetScreenActiveRect()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    int32_t x = GetData<int32_t>();
    int32_t y = GetData<int32_t>();
    int32_t w = GetData<int32_t>();
    int32_t h = GetData<int32_t>();
    Rect activeRect {
        .x = x,
        .y = y,
        .w = w,
        .h = h
    };
    rsConn_->SetScreenActiveRect(id, activeRect);
    return true;
}

bool DoSetRefreshRateMode()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    int32_t refreshRateMode = GetData<int32_t>();
    rsConn_->SetRefreshRateMode(refreshRateMode);
    return true;
}

bool DoCreateVSyncConnection()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    sptr<VSyncIConnectionToken> token = new IRemoteStub<VSyncIConnectionToken>();
    rsConn_->CreateVSyncConnection("test", token, id);
    return true;
}

bool DoSetScreenRefreshRate()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    int32_t sceneId = GetData<int32_t>();
    int32_t rate = GetData<int32_t>();
    bool enable = GetData<bool>();
    rsConn_->SetScreenRefreshRate(id, sceneId, rate);
    rsConn_->GetScreenCurrentRefreshRate(id);
    rsConn_->GetScreenSupportedRefreshRates(id);
    rsConn_->GetCurrentRefreshRateMode();
    rsConn_->GetShowRefreshRateEnabled();
    rsConn_->SetShowRefreshRateEnabled(enable);
    return true;
}

bool DoGetBitmap()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    Drawing::Bitmap bm;
    NodeId id = GetData<uint64_t>();
    rsConn_->GetBitmap(id, bm);
    return true;
}

bool DoGetScreenCapability()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    rsConn_->GetScreenCapability(id);
    return true;
}

bool DoGetScreenData()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    rsConn_->GetScreenData(id);
    return true;
}

bool DoGetScreenHDRCapability()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    ScreenId id = GetData<uint64_t>();
    RSScreenHDRCapability screenHDRCapability;
    rsConn_->GetScreenHDRCapability(id, screenHDRCapability);
    return true;
}

class CustomOcclusionChangeCallback : public RSOcclusionChangeCallbackStub {
public:
    explicit CustomOcclusionChangeCallback(const OcclusionChangeCallback& callback) : cb_(callback) {}
    ~CustomOcclusionChangeCallback() override {};

    void OnOcclusionVisibleChanged(std::shared_ptr<RSOcclusionData> occlusionData) override
    {
        if (cb_ != nullptr) {
            cb_(occlusionData);
        }
    }

private:
    OcclusionChangeCallback cb_;
};

bool DoRegisterOcclusionChangeCallback()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    OcclusionChangeCallback callback = [](std::shared_ptr<RSOcclusionData> data) {};
    sptr<CustomOcclusionChangeCallback> cb = new CustomOcclusionChangeCallback(callback);
    rsConn_->RegisterOcclusionChangeCallback(cb);
    return true;
}

bool DoShowWatermark()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    const char *perms[1];
    perms[0] = "ohos.permission.UPDATE_CONFIGURATION";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "DoShowWatermark",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    bool isShow = GetData<bool>();
    std::shared_ptr<Media::PixelMap> pixelMap1;
    rsConn_->ShowWatermark(pixelMap1, isShow);
    return true;
}

bool DoTakeSurfaceCapture()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t nodeId = GetData<uint64_t>();
    sptr<RSISurfaceCaptureCallback> callback = nullptr;
    RSSurfaceCaptureConfig captureConfig;
    captureConfig.scaleX = GetData<float>();
    captureConfig.scaleY = GetData<float>();
    captureConfig.useDma = GetData<bool>();
    captureConfig.useCurWindow = GetData<bool>();
    uint8_t type = GetData<uint8_t>();
    captureConfig.captureType = (SurfaceCaptureType)type;
    captureConfig.isSync = GetData<bool>();
    rsConn_->TakeSurfaceCapture(nodeId, callback, captureConfig);
    return true;
}

bool DoSetHwcNodeBounds()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t nodeId = GetData<uint64_t>();
    float positionX = GetData<float>();
    float positionY = GetData<float>();
    float positionZ = GetData<float>();
    float positionW = GetData<float>();
    rsConn_->SetHwcNodeBounds(nodeId, positionX, positionY, positionZ, positionW);
    return true;
}

bool DoSetScreenChangeCallback()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    sptr<RSIScreenChangeCallback> callback = nullptr;
    rsConn_->SetScreenChangeCallback(callback);
    return true;
}

bool DoSetFocusAppInfo()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    int32_t pid = GetData<int32_t>();
    int32_t uid = GetData<int32_t>();
    std::string bundleName = GetData<std::string>();
    std::string abilityName = GetData<std::string>();
    uint64_t focusNodeId = GetData<uint64_t>();
    rsConn_->SetFocusAppInfo(pid, uid, bundleName, abilityName, focusNodeId);
    return true;
}

bool DoSetAncoForceDoDirect()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    bool direct = GetData<bool>();
    rsConn_->SetAncoForceDoDirect(direct);
    return true;
}

bool DoGetActiveDirtyRegionInfo()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    rsConn_->GetActiveDirtyRegionInfo();
    return true;
}

bool DoGetGlobalDirtyRegionInfo()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    rsConn_->GetGlobalDirtyRegionInfo();
    return true;
}

bool DoGetLayerComposeInfo()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    rsConn_->GetLayerComposeInfo();
    return true;
}

bool DoGetHwcDisabledReasonInfo()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    rsConn_->GetHwcDisabledReasonInfo();
    return true;
}

bool DoGetUniRenderEnabled()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    rsConn_->GetUniRenderEnabled();
    return true;
}

bool DoCreateNode1()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    RSDisplayNodeConfig displayNodeConfig;
    displayNodeConfig.screenId = GetData<uint64_t>();
    displayNodeConfig.isMirrored = GetData<bool>();
    displayNodeConfig.mirrorNodeId = GetData<uint64_t>();
    displayNodeConfig.isSync = GetData<bool>();
    uint64_t nodeId = GetData<uint64_t>();
    rsConn_->CreateNode(displayNodeConfig, nodeId);
    return true;
}

bool DoCreateNode2()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    RSSurfaceRenderNodeConfig config;
    config.id = GetData<uint64_t>();
    config.name = GetData<std::string>();
    rsConn_->CreateNode(config);
    return true;
}

bool DoGetDefaultScreenId()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    rsConn_->GetDefaultScreenId();
    return true;
}

bool DoGetActiveScreenId()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    rsConn_->GetActiveScreenId();
    return true;
}

bool DoGetAllScreenIds()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    rsConn_->GetAllScreenIds();
    return true;
}

bool DoGetTotalAppMemSize()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    float cpuMemSize = GetData<float>();
    float gpuMemSize = GetData<float>();
    rsConn_->GetTotalAppMemSize(cpuMemSize, gpuMemSize);
    return true;
}

bool DoSetVirtualScreenBlackList()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint64_t nodeId = GetData<uint64_t>();
    std::vector<uint64_t> blackListVector;
    blackListVector.push_back(nodeId);
    rsConn_->SetVirtualScreenBlackList(id, blackListVector);
    return true;
}

bool DoSetVirtualScreenSecurityExemptionList()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint64_t nodeId = GetData<uint64_t>();
    std::vector<uint64_t> securityExemptionList;
    securityExemptionList.push_back(nodeId);
    rsConn_->SetVirtualScreenSecurityExemptionList(id, securityExemptionList);
    return true;
}

bool DoSetCastScreenEnableSkipWindow()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    bool enable = GetData<bool>();
    rsConn_->SetCastScreenEnableSkipWindow(id, enable);
    return true;
}

bool DoSyncFrameRateRange()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    FrameRateRange range;
    int32_t animatorExpectedFrameRate = GetData<int32_t>();
    rsConn_->SyncFrameRateRange(id, range, animatorExpectedFrameRate);
    return true;
}

bool DoUnregisterFrameRateLinker()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    rsConn_->UnregisterFrameRateLinker(id);
    return true;
}

bool DoMarkPowerOffNeedProcessOneFrame()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    rsConn_->MarkPowerOffNeedProcessOneFrame();
    return true;
}

bool DoDisablePowerOffRenderControl()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    rsConn_->DisablePowerOffRenderControl(id);
    return true;
}

bool DoSetScreenCorrection()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint32_t screenRotation = GetData<uint32_t>();
    rsConn_->SetScreenCorrection(id, static_cast<ScreenRotation>(screenRotation));
    return true;
}

bool DoSetVirtualMirrorScreenCanvasRotation()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    bool canvasRotation = GetData<bool>();
    rsConn_->SetVirtualMirrorScreenCanvasRotation(id, canvasRotation);
    return true;
}

bool DoSetVirtualMirrorScreenScaleMode()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint32_t scaleMode = GetData<uint32_t>();
    rsConn_->SetVirtualMirrorScreenScaleMode(id, static_cast<ScreenScaleMode>(scaleMode));
    return true;
}

bool DoSetGlobalDarkColorMode()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    bool isDark = GetData<bool>();
    rsConn_->SetGlobalDarkColorMode(isDark);
    return true;
}

bool DoSetPixelFormat()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint32_t pixelFormat = GetData<uint32_t>();
    rsConn_->SetPixelFormat(id, static_cast<GraphicPixelFormat>(pixelFormat));
    GraphicPixelFormat pixelFormat1;
    rsConn_->GetPixelFormat(id, pixelFormat1);
    return true;
}

bool DOGetScreenSupportedHDRFormats()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    int32_t modeIdx = GetData<int32_t>();
    rsConn_->SetScreenHDRFormat(id, modeIdx);
    ScreenHDRFormat hdrFormat;
    rsConn_->GetScreenHDRFormat(id, hdrFormat);
    std::vector<ScreenHDRFormat> hdrFormats;
    rsConn_->GetScreenSupportedHDRFormats(id, hdrFormats);
    return true;
}

bool DOGetScreenSupportedColorSpaces()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint32_t colorSpace = GetData<uint32_t>();
    rsConn_->SetScreenColorSpace(id, static_cast<GraphicCM_ColorSpaceType>(colorSpace));
    std::vector<GraphicCM_ColorSpaceType> colorSpaces;
    rsConn_->GetScreenSupportedColorSpaces(id, colorSpaces);
    return true;
}

bool DOSetVirtualScreenRefreshRate()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint32_t maxRefreshRate = GetData<uint32_t>();
    uint32_t actualRefreshRate = GetData<uint32_t>();
    rsConn_->SetVirtualScreenRefreshRate(id, maxRefreshRate, actualRefreshRate);
    return true;
}

bool DOSetSystemAnimatedScenes()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint32_t systemAnimatedScenes = GetData<uint32_t>();
    rsConn_->SetSystemAnimatedScenes(static_cast<SystemAnimatedScenes>(systemAnimatedScenes));
    return true;
}

bool DOResizeVirtualScreen()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint32_t width = GetData<uint32_t>();
    uint32_t height = GetData<uint32_t>();
    rsConn_->ResizeVirtualScreen(id, width, height);
    return true;
}

bool DOReportJankStats()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    rsConn_->ReportJankStats();
    return true;
}

bool DOReportEventResponse()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    DataBaseRs info;
    info.appPid = GetData<int32_t>();
    info.eventType = GetData<int32_t>();
    info.versionCode = GetData<int32_t>();
    info.uniqueId = GetData<int64_t>();
    info.inputTime = GetData<int64_t>();
    info.beginVsyncTime = GetData<int64_t>();
    info.endVsyncTime = GetData<int64_t>();
    info.isDisplayAnimator = GetData<bool>();
    info.sceneId = GetData<std::string>();
    info.versionName = GetData<std::string>();
    info.bundleName = GetData<std::string>();
    info.processName = GetData<std::string>();
    info.abilityName = GetData<std::string>();
    info.pageUrl = GetData<std::string>();
    info.sourceType = GetData<std::string>();
    info.note = GetData<std::string>();
    rsConn_->ReportEventJankFrame(info);
    rsConn_->ReportEventResponse(info);
    return true;
}

bool DOReportEventComplete()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    DataBaseRs info;
    info.appPid = GetData<int32_t>();
    info.eventType = GetData<int32_t>();
    info.versionCode = GetData<int32_t>();
    info.uniqueId = GetData<int64_t>();
    info.inputTime = GetData<int64_t>();
    info.beginVsyncTime = GetData<int64_t>();
    info.endVsyncTime = GetData<int64_t>();
    info.isDisplayAnimator = GetData<bool>();
    info.sceneId = GetData<std::string>();
    info.versionName = GetData<std::string>();
    info.bundleName = GetData<std::string>();
    info.processName = GetData<std::string>();
    info.abilityName = GetData<std::string>();
    info.pageUrl = GetData<std::string>();
    info.sourceType = GetData<std::string>();
    info.note = GetData<std::string>();
    rsConn_->ReportEventJankFrame(info);
    rsConn_->ReportEventComplete(info);
    return true;
}

bool DOReportEventJankFrame()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    DataBaseRs info;
    info.appPid = GetData<int32_t>();
    info.eventType = GetData<int32_t>();
    info.versionCode = GetData<int32_t>();
    info.uniqueId = GetData<int64_t>();
    info.inputTime = GetData<int64_t>();
    info.beginVsyncTime = GetData<int64_t>();
    info.endVsyncTime = GetData<int64_t>();
    info.isDisplayAnimator = GetData<bool>();
    info.sceneId = GetData<std::string>();
    info.versionName = GetData<std::string>();
    info.bundleName = GetData<std::string>();
    info.processName = GetData<std::string>();
    info.abilityName = GetData<std::string>();
    info.pageUrl = GetData<std::string>();
    info.sourceType = GetData<std::string>();
    info.note = GetData<std::string>();
    rsConn_->ReportEventJankFrame(info);
    return true;
}

bool DOReportGameStateData()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    GameStateData info;
    info.pid = GetData<int32_t>();
    info.uid = GetData<int32_t>();
    info.state = GetData<int32_t>();
    info.renderTid = GetData<int32_t>();
    info.bundleName = GetData<std::string>();
    rsConn_->ReportGameStateData(info);
    return true;
}

bool DOSetHidePrivacyContent()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint32_t id = GetData<uint32_t>();
    bool needHidePrivacyContent = GetData<bool>();
    rsConn_->SetHidePrivacyContent(id, needHidePrivacyContent);
    return true;
}

bool DONotifyLightFactorStatus()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    bool isSafe = GetData<bool>();
    rsConn_->NotifyLightFactorStatus(isSafe);
    return true;
}

bool DONotifyPackageEvent()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint32_t listSize = GetData<uint32_t>();
    std::string package = GetData<std::string>();
    std::vector<std::string> packageList;
    packageList.push_back(package);
    rsConn_->NotifyPackageEvent(listSize, packageList);
    return true;
}

bool DONotifyRefreshRateEvent()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    EventInfo eventInfo;
    eventInfo.eventName = GetData<std::string>();
    eventInfo.eventStatus = GetData<bool>();
    eventInfo.minRefreshRate = GetData<uint32_t>();
    eventInfo.maxRefreshRate = GetData<uint32_t>();
    eventInfo.description = GetData<std::string>();
    rsConn_->NotifyRefreshRateEvent(eventInfo);
    return true;
}

bool DONotifyTouchEvent()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    int32_t touchStatus = GetData<int32_t>();
    int32_t touchCnt = GetData<int32_t>();
    rsConn_->NotifyTouchEvent(touchStatus, touchCnt);
    return true;
}

bool DONotifyDynamicModeEvent()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    bool enableDynamicMode = GetData<bool>();
    rsConn_->NotifyDynamicModeEvent(enableDynamicMode);
    return true;
}

bool DOSetCacheEnabledForRotation()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    bool isEnabled = GetData<bool>();
    rsConn_->SetCacheEnabledForRotation(isEnabled);
    return true;
}

bool DOSetDefaultDeviceRotationOffset()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint32_t offset = GetData<uint32_t>();
    rsConn_->SetDefaultDeviceRotationOffset(offset);
    return true;
}

bool DOSetOnRemoteDiedCallback()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    OnRemoteDiedCallback callback;
    rsConn_->SetOnRemoteDiedCallback(callback);
    return true;
}

bool DOSetVmaCacheStatus()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    bool flag = GetData<bool>();
    rsConn_->SetVmaCacheStatus(flag);
    return true;
}

#ifdef TP_FEATURE_ENABLE
bool DOSetTpFeatureConfig()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    int32_t feature = GetData<int32_t>();
    char config = GetData<char>();
    auto tpFeatureConfigType = static_cast<TpFeatureConfigType>(GetData<uint8_t>());
    rsConn_->SetTpFeatureConfig(feature, &config, tpFeatureConfigType);
    return true;
}
#endif

bool DOSetVirtualScreenUsingStatus()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    bool isVirtualScreenUsingStatus = GetData<bool>();
    rsConn_->SetVirtualScreenUsingStatus(isVirtualScreenUsingStatus);
    return true;
}

bool DOSetCurtainScreenUsingStatus()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    bool isCurtainScreenOn = GetData<bool>();
    rsConn_->SetCurtainScreenUsingStatus(isCurtainScreenOn);
    return true;
}

bool DOSetVirtualScreenStatus()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    uint64_t id = GetData<uint64_t>();
    uint64_t screenStatus = GetData<uint64_t>();
    rsConn_->SetVirtualScreenStatus(id, static_cast<VirtualScreenStatus>(screenStatus));
    return true;
}

bool DOSetLayerTop()
{
    if (rsConn_ == nullptr) {
        return false;
    }
    std::string nodeIdStr = GetData<std::string>();
    bool isTop = GetData<bool>();
    rsConn_->SetLayerTop(nodeIdStr, isTop);
    return true;
}

bool DOSetFreeMultiWindowStatus()
{
    if (rsConn_ == nullptr) {
        return false;
    }

    bool enable = GetData<bool>();
    rsConn_->SetFreeMultiWindowStatus(enable);
    return true;
}

void DoFuzzerTest1()
{
    DoRegisterApplicationAgent();
    DoCommitTransaction();
    DoExecuteSynchronousTask();
    DoGetMemoryGraphic();
    DoCreateNodeAndSurface();
    DoGetScreenBacklight();
    DoGetScreenType();
    DoRegisterBufferAvailableListener();
    DoSetScreenSkipFrameInterval();
    DoSetVirtualScreenResolution();
    DoGetScreenSupportedColorGamuts();
    DoGetScreenSupportedModes();
    DoGetScreenColorGamut();
    DoSetScreenPowerStatus();
    DoSetScreenGamutMap();
    DoSetAppWindowNum();
    DoCreateVirtualScreen();
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    DoSetPointerColorInversionConfig();
    DoSetPointerColorInversionEnabled();
    DoRegisterPointerLuminanceChangeCallback();
    DoUnRegisterPointerLuminanceChangeCallback();
#endif
    DoSetScreenActiveMode();
    DoSetScreenActiveRect();
    DoSetRefreshRateMode();
    DoCreateVSyncConnection();
    DoSetScreenRefreshRate();
    DoGetBitmap();
    DoGetScreenCapability();
    DoGetScreenData();
    DoGetScreenHDRCapability();
    DoRegisterOcclusionChangeCallback();
    DoShowWatermark();
    DoTakeSurfaceCapture();
    DoSetHwcNodeBounds();
    DoSetScreenChangeCallback();
    DoSetFocusAppInfo();
    DoSetAncoForceDoDirect();
    DoGetActiveDirtyRegionInfo();
    DoGetGlobalDirtyRegionInfo();
    DoGetLayerComposeInfo();
    DoGetHwcDisabledReasonInfo();
}

void DoFuzzerTest2()
{
    DoGetUniRenderEnabled();
    DoCreateNode1();
    DoCreateNode2();
    DoGetDefaultScreenId();
    DoGetActiveScreenId();
    DoGetAllScreenIds();
    DoGetMemoryGraphics();
    DoGetTotalAppMemSize();
    DoSetVirtualScreenBlackList();
    DoSetVirtualScreenSecurityExemptionList();
    DoSetCastScreenEnableSkipWindow();
    DoSyncFrameRateRange();
    DoUnregisterFrameRateLinker();
    DoMarkPowerOffNeedProcessOneFrame();
    DoDisablePowerOffRenderControl();
    DoSetScreenCorrection();
    DoSetVirtualMirrorScreenCanvasRotation();
    DoSetVirtualMirrorScreenScaleMode();
    DoSetGlobalDarkColorMode();
    DoSetPixelFormat();
    DOGetScreenSupportedHDRFormats();
    DOGetScreenSupportedColorSpaces();
    DOSetVirtualScreenRefreshRate();
    DOSetSystemAnimatedScenes();
    DOResizeVirtualScreen();
    DOReportJankStats();
    DOReportEventResponse();
    DOReportEventComplete();
    DOReportEventJankFrame();
    DOReportGameStateData();
    DOSetHidePrivacyContent();
    DONotifyLightFactorStatus();
    DONotifyPackageEvent();
    DONotifyRefreshRateEvent();
    DONotifyTouchEvent();
    DONotifyDynamicModeEvent();
    DOSetCacheEnabledForRotation();
    DOSetDefaultDeviceRotationOffset();
    DOSetOnRemoteDiedCallback();
    DOSetVmaCacheStatus();
#ifdef TP_FEATURE_ENABLE
    DOSetTpFeatureConfig();
#endif
    DOSetVirtualScreenUsingStatus();
    DOSetCurtainScreenUsingStatus();
    DOSetVirtualScreenStatus();
    DOSetLayerTop();
    DOSetFreeMultiWindowStatus();
}
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!OHOS::Rosen::Init(data, size)) {
        return 0;
    }
    /* Run your code on data */
    OHOS::Rosen::DoFuzzerTest1();
    OHOS::Rosen::DoFuzzerTest2();
    return 0;
}