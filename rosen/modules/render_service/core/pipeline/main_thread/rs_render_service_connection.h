/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_PIPELINE_RS_RENDER_SERVICE_CONNECTION_H
#define RENDER_SERVICE_PIPELINE_RS_RENDER_SERVICE_CONNECTION_H

#include <mutex>
#include <unordered_set>

#include "hgm_config_callback_manager.h"
#include "ipc_callbacks/buffer_available_callback.h"
#include "ipc_callbacks/buffer_clear_callback.h"
#include "pipeline/hardware_thread/rs_hardware_thread.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/main_thread/rs_render_service.h"
#include "screen_manager/rs_screen_manager.h"
#include "transaction/rs_render_service_connection_stub.h"
#include "vsync_distributor.h"

namespace OHOS {
namespace Rosen {
class HgmFrameRateManager;
class RSRenderServiceConnection : public RSRenderServiceConnectionStub {
public:
    RSRenderServiceConnection(
        pid_t remotePid,
        wptr<RSRenderService> renderService,
        RSMainThread* mainThread,
        sptr<RSScreenManager> screenManager,
        sptr<IRemoteObject> token,
        sptr<VSyncDistributor> distributor);
    ~RSRenderServiceConnection() noexcept;
    RSRenderServiceConnection(const RSRenderServiceConnection&) = delete;
    RSRenderServiceConnection& operator=(const RSRenderServiceConnection&) = delete;

    sptr<IRemoteObject> GetToken() const
    {
        return token_;
    }

private:
    void CleanVirtualScreens() noexcept;
    void CleanRenderNodes() noexcept;
    void CleanFrameRateLinkers() noexcept;
    void CleanFrameRateLinkerExpectedFpsCallbacks() noexcept;
    void CleanAll(bool toDelete = false) noexcept;

    // IPC RSIRenderServiceConnection Interfaces
    ErrCode CommitTransaction(std::unique_ptr<RSTransactionData>& transactionData) override;
    ErrCode ExecuteSynchronousTask(const std::shared_ptr<RSSyncTask>& task) override;
    ErrCode GetMemoryGraphic(int pid, MemoryGraphic& memoryGraphic) override;
    ErrCode GetMemoryGraphics(std::vector<MemoryGraphic>& memoryGraphics) override;
    ErrCode GetTotalAppMemSize(float& cpuMemSize, float& gpuMemSize, bool& success) override;
    ErrCode GetUniRenderEnabled(bool& enable) override;

    ErrCode CreateNode(const RSSurfaceRenderNodeConfig& config, bool& success) override;
    ErrCode CreateNode(const RSDisplayNodeConfig& displayNodeConfig, NodeId nodeId, bool& success) override;
    ErrCode CreateNodeAndSurface(const RSSurfaceRenderNodeConfig& config, sptr<Surface>& sfc,
        bool unobscured = false) override;

    ErrCode CreateVSyncConnection(sptr<IVSyncConnection>& vsyncConn,
                                  const std::string& name,
                                  const sptr<VSyncIConnectionToken>& token,
                                  VSyncConnParam vsyncConnParam = {0, 0, false}) override;

    ErrCode GetPixelMapByProcessId(std::vector<PixelMapInfo>& pixelMapInfoVector, pid_t pid, int32_t& repCode) override;

    ErrCode CreatePixelMapFromSurface(sptr<Surface> surface,
        const Rect &srcRect, std::shared_ptr<Media::PixelMap> &pixelMap) override;

    int32_t SetFocusAppInfo(
        int32_t pid, int32_t uid, const std::string &bundleName, const std::string &abilityName,
        uint64_t focusNodeId) override;

    ScreenId GetDefaultScreenId() override;

    ScreenId GetActiveScreenId() override;

    std::vector<ScreenId> GetAllScreenIds() override;

    ScreenId CreateVirtualScreen(
        const std::string &name,
        uint32_t width,
        uint32_t height,
        sptr<Surface> surface,
        ScreenId mirrorId = 0,
        int32_t flags = 0,
        std::vector<NodeId> whiteList = {}) override;

    int32_t SetVirtualScreenBlackList(ScreenId id, std::vector<NodeId>& blackListVector) override;

    ErrCode AddVirtualScreenBlackList(ScreenId id, std::vector<NodeId>& blackListVector, int32_t& repCode) override;

    ErrCode RemoveVirtualScreenBlackList(ScreenId id, std::vector<NodeId>& blackListVector, int32_t& repCode) override;

    int32_t SetVirtualScreenSecurityExemptionList(
        ScreenId id, const std::vector<NodeId>& securityExemptionList) override;

    int32_t SetScreenSecurityMask(ScreenId id,
        std::shared_ptr<Media::PixelMap> securityMask) override;

    int32_t SetMirrorScreenVisibleRect(ScreenId id, const Rect& mainScreenRect, bool supportRotation = false) override;

    int32_t SetCastScreenEnableSkipWindow(ScreenId id, bool enable) override;
    
    int32_t SetVirtualScreenSurface(ScreenId id, sptr<Surface> surface) override;

    void RemoveVirtualScreen(ScreenId id) override;

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    int32_t SetPointerColorInversionConfig(float darkBuffer, float brightBuffer,
        int64_t interval, int32_t rangeSize) override;
 
    int32_t SetPointerColorInversionEnabled(bool enable) override;
 
    int32_t RegisterPointerLuminanceChangeCallback(sptr<RSIPointerLuminanceChangeCallback> callback) override;
 
    int32_t UnRegisterPointerLuminanceChangeCallback() override;
#endif

    int32_t SetScreenChangeCallback(sptr<RSIScreenChangeCallback> callback) override;

    void SetScreenActiveMode(ScreenId id, uint32_t modeId) override;

    void SetScreenRefreshRate(ScreenId id, int32_t sceneId, int32_t rate) override;

    void SetRefreshRateMode(int32_t refreshRateMode) override;

    void SyncFrameRateRange(FrameRateLinkerId id, const FrameRateRange& range,
        int32_t animatorExpectedFrameRate) override;

    void UnregisterFrameRateLinker(FrameRateLinkerId id) override;

    uint32_t GetScreenCurrentRefreshRate(ScreenId id) override;

    int32_t GetCurrentRefreshRateMode() override;

    std::vector<int32_t> GetScreenSupportedRefreshRates(ScreenId id) override;

    bool GetShowRefreshRateEnabled() override;

    void SetShowRefreshRateEnabled(bool enabled, int32_t type) override;

    uint32_t GetRealtimeRefreshRate(ScreenId screenId) override;

    ErrCode GetRefreshInfo(pid_t pid, std::string& enable) override;

    int32_t SetPhysicalScreenResolution(ScreenId id, uint32_t width, uint32_t height) override;

    int32_t SetVirtualScreenResolution(ScreenId id, uint32_t width, uint32_t height) override;

    void MarkPowerOffNeedProcessOneFrame() override;

    ErrCode RepaintEverything() override;

    void ForceRefreshOneFrameWithNextVSync() override;

    void DisablePowerOffRenderControl(ScreenId id) override;

    void SetScreenPowerStatus(ScreenId id, ScreenPowerStatus status) override;

    void TakeSurfaceCapture(NodeId id, sptr<RSISurfaceCaptureCallback> callback,
        const RSSurfaceCaptureConfig& captureConfig, const RSSurfaceCaptureBlurParam& blurParam,
        const Drawing::Rect& specifiedAreaRect = Drawing::Rect(0.f, 0.f, 0.f, 0.f),
        RSSurfaceCapturePermissions permissions = RSSurfaceCapturePermissions()) override;

    void TakeSelfSurfaceCapture(
        NodeId id, sptr<RSISurfaceCaptureCallback> callback, const RSSurfaceCaptureConfig& captureConfig) override;

    ErrCode SetWindowFreezeImmediately(NodeId id, bool isFreeze, sptr<RSISurfaceCaptureCallback> callback,
        const RSSurfaceCaptureConfig& captureConfig, const RSSurfaceCaptureBlurParam& blurParam) override;

    void SetHwcNodeBounds(int64_t rsNodeId, float positionX, float positionY,
        float positionZ, float positionW) override;

    ErrCode RegisterApplicationAgent(uint32_t pid, sptr<IApplicationAgent> app) override;

    void UnRegisterApplicationAgent(sptr<IApplicationAgent> app);

    RSVirtualScreenResolution GetVirtualScreenResolution(ScreenId id) override;

    RSScreenModeInfo GetScreenActiveMode(ScreenId id) override;

    std::vector<RSScreenModeInfo> GetScreenSupportedModes(ScreenId id) override;

    RSScreenCapability GetScreenCapability(ScreenId id) override;

    ScreenPowerStatus GetScreenPowerStatus(ScreenId id) override;

    RSScreenData GetScreenData(ScreenId id) override;

    int32_t GetScreenBacklight(ScreenId id) override;

    void SetScreenBacklight(ScreenId id, uint32_t level) override;

    ErrCode RegisterBufferAvailableListener(
        NodeId id, sptr<RSIBufferAvailableCallback> callback, bool isFromRenderThread) override;

    ErrCode RegisterBufferClearListener(
        NodeId id, sptr<RSIBufferClearCallback> callback) override;

    int32_t GetScreenSupportedColorGamuts(ScreenId id, std::vector<ScreenColorGamut>& mode) override;

    int32_t GetScreenSupportedMetaDataKeys(ScreenId id, std::vector<ScreenHDRMetadataKey>& keys) override;

    int32_t GetScreenColorGamut(ScreenId id, ScreenColorGamut& mode) override;

    int32_t SetScreenColorGamut(ScreenId id, int32_t modeIdx) override;

    int32_t SetScreenGamutMap(ScreenId id, ScreenGamutMap mode) override;

    int32_t SetScreenCorrection(ScreenId id, ScreenRotation screenRotation) override;

    bool SetVirtualMirrorScreenCanvasRotation(ScreenId id, bool canvasRotation) override;

    bool SetVirtualMirrorScreenScaleMode(ScreenId id, ScreenScaleMode scaleMode) override;

    bool SetGlobalDarkColorMode(bool isDark) override;

    int32_t GetScreenGamutMap(ScreenId id, ScreenGamutMap& mode) override;

    int32_t GetScreenHDRCapability(ScreenId id, RSScreenHDRCapability& screenHdrCapability) override;

    ErrCode GetPixelFormat(ScreenId id, GraphicPixelFormat& pixelFormat, int32_t& resCode) override;

    ErrCode SetPixelFormat(ScreenId id, GraphicPixelFormat pixelFormat, int32_t& resCode) override;

    ErrCode GetScreenSupportedHDRFormats(
        ScreenId id, std::vector<ScreenHDRFormat>& hdrFormats, int32_t& resCode) override;

    ErrCode GetScreenHDRFormat(ScreenId id, ScreenHDRFormat& hdrFormat, int32_t& resCode) override;

    ErrCode SetScreenHDRFormat(ScreenId id, int32_t modeIdx, int32_t& resCode) override;

    ErrCode GetScreenSupportedColorSpaces(
        ScreenId id, std::vector<GraphicCM_ColorSpaceType>& colorSpaces, int32_t& resCode) override;

    ErrCode GetScreenColorSpace(ScreenId id, GraphicCM_ColorSpaceType& colorSpace, int32_t& resCode) override;

    ErrCode SetScreenColorSpace(ScreenId id, GraphicCM_ColorSpaceType colorSpace, int32_t& resCode) override;

    int32_t GetScreenType(ScreenId id, RSScreenType& screenType) override;

    ErrCode GetBitmap(NodeId id, Drawing::Bitmap& bitmap, bool& success) override;
    ErrCode GetPixelmap(NodeId id, std::shared_ptr<Media::PixelMap> pixelmap,
        const Drawing::Rect* rect, std::shared_ptr<Drawing::DrawCmdList> drawCmdList, bool& success) override;
    bool RegisterTypeface(uint64_t globalUniqueId, std::shared_ptr<Drawing::Typeface>& typeface) override;
    bool UnRegisterTypeface(uint64_t globalUniqueId) override;

    int32_t GetDisplayIdentificationData(ScreenId id, uint8_t& outPort, std::vector<uint8_t>& edidData) override;

    int32_t SetScreenSkipFrameInterval(ScreenId id, uint32_t skipFrameInterval) override;

    ErrCode SetVirtualScreenRefreshRate(
        ScreenId id, uint32_t maxRefreshRate, uint32_t& actualRefreshRate, int32_t& retVal) override;

    uint32_t SetScreenActiveRect(ScreenId id, const Rect& activeRect) override;

    int32_t RegisterOcclusionChangeCallback(sptr<RSIOcclusionChangeCallback> callback) override;

    int32_t RegisterSurfaceOcclusionChangeCallback(
        NodeId id, sptr<RSISurfaceOcclusionChangeCallback> callback, std::vector<float>& partitionPoints) override;

    int32_t UnRegisterSurfaceOcclusionChangeCallback(NodeId id) override;

    int32_t RegisterHgmConfigChangeCallback(sptr<RSIHgmConfigChangeCallback> callback) override;

    int32_t RegisterHgmRefreshRateModeChangeCallback(sptr<RSIHgmConfigChangeCallback> callback) override;

    int32_t RegisterHgmRefreshRateUpdateCallback(sptr<RSIHgmConfigChangeCallback> callback) override;

    int32_t RegisterFrameRateLinkerExpectedFpsUpdateCallback(int32_t dstPid,
        sptr<RSIFrameRateLinkerExpectedFpsUpdateCallback> callback) override;

    ErrCode SetAppWindowNum(uint32_t num) override;

    bool SetSystemAnimatedScenes(SystemAnimatedScenes systemAnimatedScenes, bool isRegularAnimation) override;

    void ShowWatermark(const std::shared_ptr<Media::PixelMap> &watermarkImg, bool isShow) override;

    ErrCode SetWatermark(const std::string& name, std::shared_ptr<Media::PixelMap> watermark, bool& success) override;

    int32_t ResizeVirtualScreen(ScreenId id, uint32_t width, uint32_t height) override;

    ErrCode ReportJankStats() override;

    ErrCode ReportEventResponse(DataBaseRs info) override;

    ErrCode ReportEventComplete(DataBaseRs info) override;

    ErrCode ReportEventJankFrame(DataBaseRs info) override;

    void ReportRsSceneJankStart(AppInfo info) override;

    void ReportRsSceneJankEnd(AppInfo info) override;

    void ReportGameStateData(GameStateData info) override;

    ErrCode SetHardwareEnabled(NodeId id, bool isEnabled, SelfDrawingNodeType selfDrawingType,
        bool dynamicHardwareEnable) override;

    ErrCode SetHidePrivacyContent(NodeId id, bool needHidePrivacyContent, uint32_t& resCode) override;

    ErrCode NotifyLightFactorStatus(int32_t lightFactorStatus) override;

    void NotifyPackageEvent(uint32_t listSize, const std::vector<std::string>& packageList) override;

    void NotifyAppStrategyConfigChangeEvent(const std::string& pkgName, uint32_t listSize,
        const std::vector<std::pair<std::string, std::string>>& newConfig) override;

    void NotifyRefreshRateEvent(const EventInfo& eventInfo) override;

    ErrCode NotifySoftVsyncEvent(uint32_t pid, uint32_t rateDiscount) override;

    void NotifyTouchEvent(int32_t touchStatus, int32_t touchCnt) override;

    void NotifyDynamicModeEvent(bool enableDynamicModeEvent) override;

    ErrCode NotifyHgmConfigEvent(const std::string &eventName, bool state) override;

    ErrCode SetCacheEnabledForRotation(bool isEnabled) override;

    bool SetVirtualScreenStatus(ScreenId id, VirtualScreenStatus screenStatus) override;

    std::vector<ActiveDirtyRegionInfo> GetActiveDirtyRegionInfo() override;

    GlobalDirtyRegionInfo GetGlobalDirtyRegionInfo() override;

    LayerComposeInfo GetLayerComposeInfo() override;

    HwcDisabledReasonInfos GetHwcDisabledReasonInfo() override;

    ErrCode GetHdrOnDuration(int64_t& hdrOnDuration) override;

    ErrCode SetVmaCacheStatus(bool flag) override;

    int32_t RegisterUIExtensionCallback(uint64_t userId, sptr<RSIUIExtensionCallback> callback,
        bool unobscured = false) override;

#ifdef TP_FEATURE_ENABLE
    void SetTpFeatureConfig(int32_t feature, const char* config, TpFeatureConfigType tpFeatureConfigType) override;
#endif

    void SetVirtualScreenUsingStatus(bool isVirtualScreenUsingStatus) override;
    ErrCode SetCurtainScreenUsingStatus(bool isCurtainScreenOn) override;

    void DropFrameByPid(const std::vector<int32_t> pidList) override;

    ErrCode SetAncoForceDoDirect(bool direct, bool& res) override;

    void SetFreeMultiWindowStatus(bool enable) override;

    void SetLayerTop(const std::string &nodeIdStr, bool isTop) override;

    ErrCode RegisterSurfaceBufferCallback(pid_t pid, uint64_t uid,
        sptr<RSISurfaceBufferCallback> callback) override;
    ErrCode UnregisterSurfaceBufferCallback(pid_t pid, uint64_t uid) override;

    void NotifyScreenSwitched() override;

    ErrCode SetWindowContainer(NodeId nodeId, bool value) override;

    int32_t RegisterSelfDrawingNodeRectChangeCallback(sptr<RSISelfDrawingNodeRectChangeCallback> callback) override;

#ifdef RS_ENABLE_OVERLAY_DISPLAY
    ErrCode SetOverlayDisplayMode(int32_t mode) override;
#endif

    void NotifyPageName(const std::string &packageName, const std::string &pageName, bool isEnter) override;

    void TestLoadFileSubTreeToNode(NodeId nodeId, const std::string &filePath) override {};

    pid_t remotePid_;
    wptr<RSRenderService> renderService_;
    RSMainThread* mainThread_ = nullptr;
#ifdef RS_ENABLE_GPU
    RSUniRenderThread& renderThread_;
#endif
    sptr<RSScreenManager> screenManager_;
    sptr<IRemoteObject> token_;

    class RSConnectionDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit RSConnectionDeathRecipient(wptr<RSRenderServiceConnection> conn);
        virtual ~RSConnectionDeathRecipient() = default;

        void OnRemoteDied(const wptr<IRemoteObject>& token) override;

    private:
        wptr<RSRenderServiceConnection> conn_;
    };
    friend class RSConnectionDeathRecipient;
    sptr<RSConnectionDeathRecipient> connDeathRecipient_;

    class RSApplicationRenderThreadDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit RSApplicationRenderThreadDeathRecipient(wptr<RSRenderServiceConnection> conn);
        virtual ~RSApplicationRenderThreadDeathRecipient() = default;

        void OnRemoteDied(const wptr<IRemoteObject>& token) override;

    private:
        wptr<RSRenderServiceConnection> conn_;
    };
    friend class RSApplicationRenderThreadDeathRecipient;
    sptr<RSApplicationRenderThreadDeathRecipient> applicationDeathRecipient_ = nullptr;

    mutable std::mutex mutex_;
    bool cleanDone_ = false;
    const std::string VOTER_SCENE_BLUR = "VOTER_SCENE_BLUR";

    // save all virtual screenIds created by this connection.
    std::unordered_set<ScreenId> virtualScreenIds_;
    sptr<RSIScreenChangeCallback> screenChangeCallback_;
    sptr<VSyncDistributor> appVSyncDistributor_;

#ifdef RS_PROFILER_ENABLED
    friend class RSProfiler;
#endif
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_PIPELINE_RS_RENDER_SERVICE_CONNECTION_H
