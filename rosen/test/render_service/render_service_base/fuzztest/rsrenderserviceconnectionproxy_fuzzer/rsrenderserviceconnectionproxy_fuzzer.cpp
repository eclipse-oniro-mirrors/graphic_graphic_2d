/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "rsrenderserviceconnectionproxy_fuzzer.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <hilog/log.h>
#include <iservice_registry.h>
#include <memory>
#include <securec.h>
#include <system_ability_definition.h>
#include <unistd.h>

#include "command/rs_animation_command.h"
#include "command/rs_node_showing_command.h"
#include "platform/ohos/rs_render_service_connection_proxy.h"
namespace OHOS {
namespace Rosen {
namespace {
const uint8_t* g_data = nullptr;
size_t g_size = 0;
size_t g_pos;
} // namespace

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
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    Rect srcRect;
    sptr<Surface> surface;
    sptr<IConsumerSurface> consumer = IConsumerSurface::Create("DisplayNode");
    sptr<IBufferProducer> producer = consumer->GetProducer();
    surface = Surface::CreateSurfaceAsProducer(producer);
    float cpuMemSize = GetData<float>();
    float gpuMemSize = GetData<float>();
    int pid = GetData<int>();
    uint64_t timeoutNS = GetData<uint64_t>();
    RSSurfaceRenderNodeConfig config;
    config.id = timeoutNS;
    auto transactionData = std::make_unique<RSTransactionData>();
    std::shared_ptr<RSSyncTask> task;
    sptr<VSyncIConnectionToken> token;
    std::string name("name");
    uint64_t id1 = GetData<uint64_t>();
    uint64_t windowNodeId = GetData<uint64_t>();
    int32_t pid1 = GetData<int32_t>();
    int32_t uid = GetData<int32_t>();
    uint32_t width = GetData<uint32_t>();
    uint32_t height = GetData<uint32_t>();
    Drawing::Bitmap bitmap;
    RSScreenHDRCapability screenHdrCapability;
    GraphicCM_ColorSpaceType colorSpace = GraphicCM_ColorSpaceType::GRAPHIC_CM_SRGB_FULL;
    RSScreenType screenType = RSScreenType::VIRTUAL_TYPE_SCREEN;
    sptr<IApplicationAgent> app;
    ScreenPowerStatus status = (ScreenPowerStatus)width;
    ScreenColorGamut screenColorGamut = (ScreenColorGamut)width;
    ScreenGamutMap screenGamutMap = (ScreenGamutMap)width;
    ScreenHDRFormat screenHDRFormat = (ScreenHDRFormat)width;
    SystemAnimatedScenes systemAnimatedScenes = (SystemAnimatedScenes)width;
    GraphicPixelFormat pixelFormat = GRAPHIC_PIXEL_FMT_BGRA_8888;
    FrameRateRange range;
    sptr<RSIScreenChangeCallback> callback;
    sptr<RSISurfaceCaptureCallback> callback1;
    sptr<RSIBufferAvailableCallback> callback2;
    sptr<RSIBufferClearCallback> callback3;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    sptr<RSIOcclusionChangeCallback> rsIOcclusionChangeCallback = iface_cast<RSIOcclusionChangeCallback>(remoteObject);
    sptr<RSISurfaceOcclusionChangeCallback> callbackTwo = iface_cast<RSISurfaceOcclusionChangeCallback>(remoteObject);
    sptr<RSIHgmConfigChangeCallback> rsIHgmConfigChangeCallback = iface_cast<RSIHgmConfigChangeCallback>(remoteObject);
    std::vector<ScreenColorGamut> mode;
    std::vector<ScreenHDRMetadataKey> keys;
    std::vector<ScreenHDRFormat> hdrFormats;
    std::vector<GraphicCM_ColorSpaceType> colorSpaces;
    std::vector<float> partitionPoints;
    std::vector<std::string> packageList;
    OnRemoteDiedCallback onRemoteDiedCallback = []() {};
    callback = iface_cast<RSIScreenChangeCallback>(remoteObject);
    std::shared_ptr<Media::PixelMap> pixelmap = std::make_shared<Media::PixelMap>();
    std::shared_ptr<Drawing::DrawCmdList> drawCmdList = std::make_shared<Drawing::DrawCmdList>();
    std::shared_ptr<Drawing::Typeface> typeface = Drawing::Typeface::MakeDefault();
    std::shared_ptr<Media::PixelMap> watermarkImg = std::make_shared<Media::PixelMap>();
    std::shared_ptr<MessageParcel> parcel = std::make_shared<MessageParcel>();
    MessageOption option;
    Drawing::Rect rect;
    EventInfo eventInfo;
    DataBaseRs info;
    GameStateData gameStateDataInfo;
    MessageParcel messageParcel;
    MessageParcel reply;
    RSRenderServiceConnectionProxy rsRenderServiceConnectionProxy(remoteObject);
    rsRenderServiceConnectionProxy.CommitTransaction(transactionData);
    rsRenderServiceConnectionProxy.ExecuteSynchronousTask(task);
    rsRenderServiceConnectionProxy.GetMemoryGraphic(pid);
    rsRenderServiceConnectionProxy.GetMemoryGraphics();
    rsRenderServiceConnectionProxy.GetTotalAppMemSize(cpuMemSize, gpuMemSize);
    rsRenderServiceConnectionProxy.GetUniRenderEnabled();
    rsRenderServiceConnectionProxy.CreateNode(config);
    rsRenderServiceConnectionProxy.CreateNodeAndSurface(config);
    rsRenderServiceConnectionProxy.CreateVSyncConnection(name, token, id1, windowNodeId);
    rsRenderServiceConnectionProxy.CreatePixelMapFromSurface(surface, srcRect);
    rsRenderServiceConnectionProxy.SetFocusAppInfo(pid1, uid, name, name, id1);
    rsRenderServiceConnectionProxy.GetDefaultScreenId();
    rsRenderServiceConnectionProxy.GetActiveScreenId();
    rsRenderServiceConnectionProxy.GetAllScreenIds();
    rsRenderServiceConnectionProxy.CreateVirtualScreen(name, width, height, surface);
    rsRenderServiceConnectionProxy.SetVirtualScreenSurface(id1, surface);
    rsRenderServiceConnectionProxy.RemoveVirtualScreen(id1);
    rsRenderServiceConnectionProxy.SetScreenChangeCallback(callback);
    rsRenderServiceConnectionProxy.SetScreenActiveMode(id1, width);
    rsRenderServiceConnectionProxy.SetScreenRefreshRate(id1, pid1, uid);
    rsRenderServiceConnectionProxy.SetRefreshRateMode(pid1);
    rsRenderServiceConnectionProxy.SyncFrameRateRange(id1, range, 0);
    rsRenderServiceConnectionProxy.GetScreenCurrentRefreshRate(id1);
    rsRenderServiceConnectionProxy.GetCurrentRefreshRateMode();
    rsRenderServiceConnectionProxy.GetScreenSupportedRefreshRates(id1);
    rsRenderServiceConnectionProxy.GetShowRefreshRateEnabled();
    rsRenderServiceConnectionProxy.SetShowRefreshRateEnabled(true);
    rsRenderServiceConnectionProxy.SetVirtualScreenResolution(id1, width, height);
    rsRenderServiceConnectionProxy.SetScreenPowerStatus(id1, status);
    rsRenderServiceConnectionProxy.RegisterApplicationAgent(width, app);
    rsRenderServiceConnectionProxy.GetVirtualScreenResolution(id1);
    rsRenderServiceConnectionProxy.GetScreenActiveMode(id1);
    rsRenderServiceConnectionProxy.GetScreenSupportedModes(id1);
    rsRenderServiceConnectionProxy.GetScreenCapability(id1);
    rsRenderServiceConnectionProxy.GetScreenPowerStatus(id1);
    rsRenderServiceConnectionProxy.GetScreenData(id1);
    rsRenderServiceConnectionProxy.GetScreenBacklight(id1);
    rsRenderServiceConnectionProxy.SetScreenBacklight(id1, width);
    rsRenderServiceConnectionProxy.RegisterBufferAvailableListener(id1, callback2, true);
    rsRenderServiceConnectionProxy.RegisterBufferClearListener(id1, callback3);
    rsRenderServiceConnectionProxy.GetScreenSupportedColorGamuts(id1, mode);
    rsRenderServiceConnectionProxy.GetScreenSupportedMetaDataKeys(id1, keys);
    rsRenderServiceConnectionProxy.GetScreenColorGamut(id1, screenColorGamut);
    rsRenderServiceConnectionProxy.SetScreenColorGamut(id1, uid);
    rsRenderServiceConnectionProxy.SetScreenGamutMap(id1, screenGamutMap);
    rsRenderServiceConnectionProxy.GetScreenHDRCapability(id1, screenHdrCapability);
    rsRenderServiceConnectionProxy.GetPixelFormat(id1, pixelFormat);
    rsRenderServiceConnectionProxy.SetPixelFormat(id1, pixelFormat);
    rsRenderServiceConnectionProxy.GetScreenSupportedHDRFormats(id1, hdrFormats);
    rsRenderServiceConnectionProxy.GetScreenHDRFormat(id1, screenHDRFormat);
    rsRenderServiceConnectionProxy.SetScreenHDRFormat(id1, pid1);
    rsRenderServiceConnectionProxy.GetScreenSupportedColorSpaces(id1, colorSpaces);
    rsRenderServiceConnectionProxy.GetScreenColorSpace(id1, colorSpace);
    rsRenderServiceConnectionProxy.SetScreenColorSpace(id1, colorSpace);
    rsRenderServiceConnectionProxy.GetScreenType(id1, screenType);
    rsRenderServiceConnectionProxy.GetBitmap(id1, bitmap);
    rsRenderServiceConnectionProxy.GetPixelmap(id1, pixelmap, &rect, drawCmdList);
    rsRenderServiceConnectionProxy.RegisterTypeface(id1, typeface);
    rsRenderServiceConnectionProxy.UnRegisterTypeface(id1);
    rsRenderServiceConnectionProxy.SetScreenSkipFrameInterval(id1, width);
    rsRenderServiceConnectionProxy.RegisterOcclusionChangeCallback(rsIOcclusionChangeCallback);
    rsRenderServiceConnectionProxy.RegisterSurfaceOcclusionChangeCallback(id1, callbackTwo, partitionPoints);
    rsRenderServiceConnectionProxy.UnRegisterSurfaceOcclusionChangeCallback(id1);
    rsRenderServiceConnectionProxy.RegisterHgmConfigChangeCallback(rsIHgmConfigChangeCallback);
    rsRenderServiceConnectionProxy.RegisterHgmRefreshRateModeChangeCallback(rsIHgmConfigChangeCallback);
    rsRenderServiceConnectionProxy.RegisterHgmRefreshRateUpdateCallback(rsIHgmConfigChangeCallback);
    rsRenderServiceConnectionProxy.SetAppWindowNum(width);
    rsRenderServiceConnectionProxy.SetSystemAnimatedScenes(systemAnimatedScenes);
    rsRenderServiceConnectionProxy.ShowWatermark(watermarkImg, true);
    rsRenderServiceConnectionProxy.ResizeVirtualScreen(id1, width, height);
    rsRenderServiceConnectionProxy.ReportJankStats();
    rsRenderServiceConnectionProxy.NotifyLightFactorStatus(true);
    rsRenderServiceConnectionProxy.NotifyPackageEvent(width, packageList);
    rsRenderServiceConnectionProxy.NotifyRefreshRateEvent(eventInfo);
    rsRenderServiceConnectionProxy.NotifyTouchEvent(pid1, uid);
    rsRenderServiceConnectionProxy.NotifyDynamicModeEvent(true);
    rsRenderServiceConnectionProxy.ReportEventResponse(info);
    rsRenderServiceConnectionProxy.ReportEventComplete(info);
    rsRenderServiceConnectionProxy.ReportEventJankFrame(info);
    rsRenderServiceConnectionProxy.ReportGameStateData(gameStateDataInfo);
    rsRenderServiceConnectionProxy.SetHardwareEnabled(id1, true, SelfDrawingNodeType::DEFAULT);
    rsRenderServiceConnectionProxy.SetCacheEnabledForRotation(true);
    rsRenderServiceConnectionProxy.SetOnRemoteDiedCallback(onRemoteDiedCallback);
    rsRenderServiceConnectionProxy.RunOnRemoteDiedCallback();
    rsRenderServiceConnectionProxy.GetActiveDirtyRegionInfo();
    rsRenderServiceConnectionProxy.GetGlobalDirtyRegionInfo();
    rsRenderServiceConnectionProxy.GetLayerComposeInfo();
    rsRenderServiceConnectionProxy.GetHwcDisabledReasonInfo();
    rsRenderServiceConnectionProxy.SetVmaCacheStatus(true);
    rsRenderServiceConnectionProxy.SetVmaCacheStatus(false);
    rsRenderServiceConnectionProxy.SetVirtualScreenUsingStatus(true);
    rsRenderServiceConnectionProxy.SetCurtainScreenUsingStatus(true);
    rsRenderServiceConnectionProxy.FillParcelWithTransactionData(transactionData, parcel);
    rsRenderServiceConnectionProxy.ReportDataBaseRs(messageParcel, reply, option, info);
    rsRenderServiceConnectionProxy.ReportGameStateDataRs(messageParcel, reply, option, gameStateDataInfo);
    return true;
}

#ifdef TP_FEATURE_ENABLE
bool OHOS::Rosen::DoSetTpFeatureConfigFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    // get data
    int32_t tpFeature = GetData<int32_t>();
    std::string tpConfig = GetData<std::string>();

    // test
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    RSRenderServiceConnectionProxy rsRenderServiceConnectionProxy(remoteObject);
    RSRenderServiceConnectionProxy.SetTpFeatureConfig(tpFeature, tpConfig);
    return true;
}
#endif
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Rosen::DoSomethingInterestingWithMyAPI(data, size);
#ifdef TP_FEATURE_ENABLE
    OHOS::Rosen::DoSetTpFeatureConfigFuzzTest(data, size);
#endif
    return 0;
}
