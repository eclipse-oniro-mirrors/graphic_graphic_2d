/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <if_system_ability_manager.h>
#include <iremote_stub.h>
#include <iservice_registry.h>
#include <mutex>
#include <system_ability_definition.h>
#include <unistd.h>

#include "platform/ohos/rs_render_service_connection_proxy.h"
#include "command/rs_animation_command.h"
#include "command/rs_node_showing_command.h"
#include "iconsumer_surface.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSRenderServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static inline std::shared_ptr<RSRenderServiceConnectionProxy> proxy;
};

void RSRenderServiceProxyTest::SetUpTestCase()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    proxy = std::make_shared<RSRenderServiceConnectionProxy>(remoteObject);
}
void RSRenderServiceProxyTest::TearDownTestCase() {}
void RSRenderServiceProxyTest::SetUp() {}
void RSRenderServiceProxyTest::TearDown() {}

/**
 * @tc.name: CommitTransaction Test
 * @tc.desc: CommitTransaction Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, CommitTransaction, TestSize.Level1)
{
    std::unique_ptr<RSTransactionData> transactionData;
    proxy->CommitTransaction(transactionData);
    transactionData = std::make_unique<RSTransactionData>();
    std::unique_ptr<RSCommand> command = std::make_unique<RSAnimationCallback>(1, 1, FINISHED);
    NodeId nodeId = 1;
    FollowType followType = FollowType::FOLLOW_TO_PARENT;
    transactionData->AddCommand(command, nodeId, followType);
    proxy->CommitTransaction(transactionData);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: ExecuteSynchronousTask Test
 * @tc.desc: ExecuteSynchronousTask Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, ExecuteSynchronousTask, TestSize.Level1)
{
    std::shared_ptr<RSSyncTask> task;
    proxy->ExecuteSynchronousTask(task);
    NodeId targetId;
    std::shared_ptr<RSRenderPropertyBase> property = std::make_shared<RSRenderPropertyBase>();
    task = std::make_shared<RSNodeGetShowingPropertyAndCancelAnimation>(targetId, property);
    proxy->ExecuteSynchronousTask(task);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: GetUniRenderEnabled Test
 * @tc.desc: GetUniRenderEnabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetUniRenderEnabled, TestSize.Level1)
{
    proxy->GetUniRenderEnabled();
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: FillParcelWithTransactionData Test
 * @tc.desc: FillParcelWithTransactionData Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, FillParcelWithTransactionData, TestSize.Level1)
{
    std::shared_ptr<MessageParcel> parcel = std::make_shared<MessageParcel>();
    auto transactionData = std::make_unique<RSTransactionData>();
    ASSERT_TRUE(proxy->FillParcelWithTransactionData(transactionData, parcel));
}

/**
 * @tc.name: CreateNodeAndSurface Test
 * @tc.desc: CreateNodeAndSurface Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, CreateNodeAndSurface, TestSize.Level1)
{
    ASSERT_FALSE(proxy->CreateNode(RSSurfaceRenderNodeConfig()));
    ASSERT_EQ(proxy->CreateNodeAndSurface(RSSurfaceRenderNodeConfig()), nullptr);
}

/**
 * @tc.name: CreateVSyncConnection Test
 * @tc.desc: CreateVSyncConnection Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, CreateVSyncConnection, TestSize.Level1)
{
    sptr<VSyncIConnectionToken> token;
    std::string name("name");
    uint64_t id = 1;
    NodeId windowNodeId = 1;
    ASSERT_EQ(proxy->CreateVSyncConnection(name, token, id, windowNodeId), nullptr);
    token = new IRemoteStub<VSyncIConnectionToken>();
    ASSERT_EQ(proxy->CreateVSyncConnection(name, token, id, windowNodeId), nullptr);
}

/**
 * @tc.name: CreatePixelMapFromSurface Test
 * @tc.desc: CreatePixelMapFromSurface Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, CreatePixelMapFromSurface, TestSize.Level1)
{
    sptr<Surface> surface;
    Rect srcRect;
    ASSERT_EQ(proxy->CreatePixelMapFromSurface(surface, srcRect), nullptr);
    sptr<IConsumerSurface> consumer = IConsumerSurface::Create("DisplayNode");
    sptr<IBufferProducer> producer = consumer->GetProducer();
    surface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_EQ(proxy->CreatePixelMapFromSurface(surface, srcRect), nullptr);
}

/**
 * @tc.name: SetFocusAppInfo Test
 * @tc.desc: SetFocusAppInfo Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetFocusAppInfo, TestSize.Level1)
{
    int32_t pid = 1;
    int32_t uid = 1;
    std::string bundleName("bundle");
    std::string abilityName("ability");
    uint64_t focusNodeId = 1;
    ASSERT_EQ(proxy->SetFocusAppInfo(pid, uid, bundleName, abilityName, focusNodeId), 0);
}

/**
 * @tc.name: GetAllScreenIds Test
 * @tc.desc: GetAllScreenIds Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetAllScreenIds, TestSize.Level1)
{
    EXPECT_EQ(proxy->GetDefaultScreenId(), INVALID_SCREEN_ID);
    EXPECT_EQ(proxy->GetActiveScreenId(), INVALID_SCREEN_ID);
    EXPECT_EQ(proxy->GetAllScreenIds().size(), 0);
}

/**
 * @tc.name: CreateVirtualScreen Test
 * @tc.desc: CreateVirtualScreen Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, CreateVirtualScreen, TestSize.Level1)
{
    std::string name("name");
    uint32_t width = 1;
    uint32_t height = 1;
    sptr<IConsumerSurface> consumer = IConsumerSurface::Create("DisplayNode");
    sptr<IBufferProducer> producer = consumer->GetProducer();
    sptr<Surface> surface = Surface::CreateSurfaceAsProducer(producer);
    ScreenId mirrorId = 1;
    int32_t flags = 1;
    std::vector<NodeId> whiteList;
    EXPECT_EQ(proxy->CreateVirtualScreen(name, width, height, surface, mirrorId, flags, whiteList),
        INVALID_SCREEN_ID);
}

/**
 * @tc.name: SetVirtualScreenSurface Test
 * @tc.desc: SetVirtualScreenSurface Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetVirtualScreenSurface, TestSize.Level1)
{
    ScreenId id = 1;
    sptr<IConsumerSurface> consumer = IConsumerSurface::Create("DisplayNode");
    sptr<IBufferProducer> producer = consumer->GetProducer();
    sptr<Surface> surface = Surface::CreateSurfaceAsProducer(producer);
    EXPECT_EQ(proxy->SetVirtualScreenSurface(id, surface), 0);
}

/**
 * @tc.name: RemoveVirtualScreen Test
 * @tc.desc: RemoveVirtualScreen Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, RemoveVirtualScreen, TestSize.Level1)
{
    ScreenId id = 1;
    proxy->RemoveVirtualScreen(id);
    ASSERT_TRUE(true);
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
/**
 * @tc.name: SetPointerColorInversionConfig Test
 * @tc.desc: SetPointerColorInversionConfig Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetPointerColorInversionConfig, TestSize.Level1)
{
    float darkBuffer = 0.5f;
    float brightBuffer = 0.5f;
    int64_t interval = 50;
    int32_t rangeSize = 20;
    proxy->SetPointerColorInversionConfig(darkBuffer, brightBuffer, interval, rangeSize);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: SetPointerColorInversionEnabled Test
 * @tc.desc: SetPointerColorInversionEnabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetPointerColorInversionEnabled, TestSize.Level1)
{
    proxy->SetPointerColorInversionEnabled(false);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: RegisterPointerLuminanceChangeCallback Test
 * @tc.desc: RegisterPointerLuminanceChangeCallback Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, RegisterPointerLuminanceChangeCallback, TestSize.Level1)
{
    sptr<RSIPointerLuminanceChangeCallback> callback;
    proxy->RegisterPointerLuminanceChangeCallback(callback);
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    proxy->UnRegisterPointerLuminanceChangeCallback();
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    callback = iface_cast<RSIPointerLuminanceChangeCallback>(remoteObject);
    proxy->RegisterPointerLuminanceChangeCallback(callback);
    ASSERT_NE(proxy->transactionDataIndex_, 5);
}
#endif

/**
 * @tc.name: SetScreenChangeCallback Test
 * @tc.desc: SetScreenChangeCallback Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetScreenChangeCallback, TestSize.Level1)
{
    sptr<RSIScreenChangeCallback> callback;
    proxy->SetScreenChangeCallback(callback);
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    callback = iface_cast<RSIScreenChangeCallback>(remoteObject);
    ASSERT_EQ(proxy->SetScreenChangeCallback(callback), 0);
}

/**
 * @tc.name: SetScreenActiveMode Test
 * @tc.desc: SetScreenActiveMode Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetScreenActiveMode, TestSize.Level1)
{
    ScreenId id = 1;
    uint32_t modeId = 1;
    proxy->SetScreenActiveMode(id, modeId);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: SetScreenActiveRect Test
 * @tc.desc: SetScreenActiveRect Test
 * @tc.type:FUNC
 * @tc.require: issueIB3986
 */
HWTEST_F(RSRenderServiceProxyTest, SetScreenActiveRect, TestSize.Level1)
{
    ScreenId id = 1;
    Rect activeRect {
        .x = 0,
        .y = 0,
        .w = 0,
        .h = 0,
    };
    proxy->SetScreenActiveRect(id, activeRect);
    ASSERT_NE(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: SetScreenRefreshRate Test
 * @tc.desc: SetScreenRefreshRate Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetScreenRefreshRate, TestSize.Level1)
{
    ScreenId id = 1;
    int32_t sceneId = 1;
    int32_t rate = 1;
    proxy->SetScreenRefreshRate(id, sceneId, rate);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: SetRefreshRateMode Test
 * @tc.desc: SetRefreshRateMode Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetRefreshRateMode, TestSize.Level1)
{
    int32_t refreshRateMode = 1;
    proxy->SetRefreshRateMode(refreshRateMode);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: SyncFrameRateRange Test
 * @tc.desc: SyncFrameRateRange Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SyncFrameRateRange, TestSize.Level1)
{
    FrameRateLinkerId id = 1;
    FrameRateRange range;
    proxy->SyncFrameRateRange(id, range, 0);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: UnregisterFrameRateLinker Test
 * @tc.desc: UnregisterFrameRateLinker Test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceProxyTest, UnregisterFrameRateLinker, TestSize.Level1)
{
    FrameRateLinkerId id = 1;
    proxy->UnregisterFrameRateLinker(id);
    ASSERT_NE(proxy->transactionDataIndex_, 5);
}

/**
 * @tc.name: GetCurrentRefreshRateMode Test
 * @tc.desc: GetCurrentRefreshRateMode Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetCurrentRefreshRateMode, TestSize.Level1)
{
    ScreenId id = 1;
    EXPECT_EQ(proxy->GetScreenCurrentRefreshRate(id), 0);
    ASSERT_EQ(proxy->GetCurrentRefreshRateMode(), 0);
}

/**
 * @tc.name: GetScreenSupportedRefreshRates Test
 * @tc.desc: GetScreenSupportedRefreshRates Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenSupportedRefreshRates, TestSize.Level1)
{
    ScreenId id = 1;
    EXPECT_FALSE(proxy->GetShowRefreshRateEnabled());
    ASSERT_EQ(proxy->GetScreenSupportedRefreshRates(id).size(), 0);
}

/**
 * @tc.name: SetShowRefreshRateEnabled Test
 * @tc.desc: SetShowRefreshRateEnabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetShowRefreshRateEnabled, TestSize.Level1)
{
    proxy->SetShowRefreshRateEnabled(true);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: SetVirtualScreenResolution Test
 * @tc.desc: SetVirtualScreenResolution Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetVirtualScreenResolution, TestSize.Level1)
{
    ScreenId id = 1;
    uint32_t width = 1;
    uint32_t height = 1;
    ASSERT_EQ(proxy->SetVirtualScreenResolution(id, width, height), 2);
}

/**
 * @tc.name: SetScreenPowerStatus Test
 * @tc.desc: SetScreenPowerStatus Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetScreenPowerStatus, TestSize.Level1)
{
    ScreenId id = 1;
    proxy->SetScreenPowerStatus(id, ScreenPowerStatus::POWER_STATUS_STANDBY);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: RegisterApplicationAgent Test
 * @tc.desc: RegisterApplicationAgent Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, RegisterApplicationAgent, TestSize.Level1)
{
    uint32_t pid = 1;
    sptr<IApplicationAgent> app;
    proxy->RegisterApplicationAgent(pid, app);
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    app = iface_cast<IApplicationAgent>(remoteObject);
    proxy->RegisterApplicationAgent(pid, app);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: TakeSurfaceCapture Test
 * @tc.desc: TakeSurfaceCapture Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, TakeSurfaceCapture, TestSize.Level1)
{
    NodeId id = 1;
    sptr<RSISurfaceCaptureCallback> callback;
    RSSurfaceCaptureConfig captureConfig;
    captureConfig.scaleX = 1.0f;
    captureConfig.scaleY = 1.0f;
    captureConfig.useDma = false;
    captureConfig.captureType = SurfaceCaptureType::UICAPTURE;
    captureConfig.isSync = true;
    RSSurfaceCaptureBlurParam blurParam;
    blurParam.isNeedBlur = true;
    blurParam.blurRadius = 10;
    proxy->TakeSurfaceCapture(id, callback, captureConfig, blurParam);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    callback = iface_cast<RSISurfaceCaptureCallback>(remoteObject);
    proxy->TakeSurfaceCapture(id, callback, captureConfig, blurParam);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: SetHwcNodeBounds Test
 * @tc.desc: SetHwcNodeBounds Test
 * @tc.type:FUNC
 * @tc.require: issueIB2O0L
 */
HWTEST_F(RSRenderServiceProxyTest, SetHwcNodeBounds, TestSize.Level1)
{
    NodeId id = 1;
    proxy->SetHwcNodeBounds(id, 1.0f, 1.0f, 1.0f, 1.0f);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: GetVirtualScreenResolution Test
 * @tc.desc: GetVirtualScreenResolution Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetVirtualScreenResolution, TestSize.Level1)
{
    ScreenId id = 1;
    ASSERT_EQ(proxy->GetVirtualScreenResolution(id).width_, 0);
}

/**
 * @tc.name: GetScreenActiveMode Test
 * @tc.desc: GetScreenActiveMode Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenActiveMode, TestSize.Level1)
{
    ScreenId id = 1;
    ASSERT_EQ(proxy->GetScreenActiveMode(id).width_, -1);
}

/**
 * @tc.name: GetMemoryGraphics Test
 * @tc.desc: GetMemoryGraphics Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetMemoryGraphics, TestSize.Level1)
{
    ScreenId id = 1;
    EXPECT_EQ(proxy->GetScreenSupportedModes(id).size(), 0);
    ASSERT_EQ(proxy->GetMemoryGraphics().size(), 0);
}

/**
 * @tc.name: GetTotalAppMemSize Test
 * @tc.desc: GetTotalAppMemSize Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetTotalAppMemSize, TestSize.Level1)
{
    float cpuMemSize = 1.0f;
    float gpuMemSize = 1.0f;
    ASSERT_FALSE(proxy->GetTotalAppMemSize(cpuMemSize, gpuMemSize));
}

/**
 * @tc.name: GetScreenPowerStatus Test
 * @tc.desc: GetScreenPowerStatus Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenPowerStatus, TestSize.Level1)
{
    int pid = 1;
    EXPECT_EQ(proxy->GetMemoryGraphic(pid).pid_, 0);
    ScreenId id = 1;
    proxy->GetScreenCapability(id);
    EXPECT_EQ(proxy->GetScreenData(id).powerStatus_, INVALID_POWER_STATUS);
    EXPECT_EQ(proxy->GetScreenBacklight(id), -1);
    ASSERT_EQ(proxy->GetScreenPowerStatus(id), ScreenPowerStatus::INVALID_POWER_STATUS);
}

/**
 * @tc.name: SetScreenBacklight Test
 * @tc.desc: SetScreenBacklight Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetScreenBacklight, TestSize.Level1)
{
    ScreenId id = 1;
    uint32_t level = 1;
    proxy->SetScreenBacklight(id, level);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: RegisterBufferClearListener Test
 * @tc.desc: RegisterBufferClearListener Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, RegisterBufferClearListener, TestSize.Level1)
{
    NodeId id = 1;
    sptr<RSIBufferClearCallback> callback;
    proxy->RegisterBufferClearListener(id, callback);
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    callback = iface_cast<RSIBufferClearCallback>(remoteObject);
    proxy->RegisterBufferClearListener(id, callback);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: RegisterBufferAvailableListener Test
 * @tc.desc: RegisterBufferAvailableListener Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, RegisterBufferAvailableListener, TestSize.Level1)
{
    NodeId id = 1;
    sptr<RSIBufferAvailableCallback> callback;
    bool isFromRenderThread = true;
    proxy->RegisterBufferAvailableListener(id, callback, isFromRenderThread);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    callback = iface_cast<RSIBufferAvailableCallback>(remoteObject);
    proxy->RegisterBufferAvailableListener(id, callback, isFromRenderThread);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: GetScreenSupportedMetaDataKeys Test
 * @tc.desc: GetScreenSupportedMetaDataKeys Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenSupportedMetaDataKeys, TestSize.Level1)
{
    ScreenId id = 1;
    std::vector<ScreenColorGamut> mode;
    ASSERT_EQ(proxy->GetScreenSupportedColorGamuts(id, mode), 2);
    std::vector<ScreenHDRMetadataKey> keys;
    ASSERT_EQ(proxy->GetScreenSupportedMetaDataKeys(id, keys), 2);
}

/**
 * @tc.name: GetScreenColorGamut Test
 * @tc.desc: GetScreenColorGamut Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenColorGamut, TestSize.Level1)
{
    ScreenId id = 1;
    int32_t modeIdx = 7;
    proxy->SetScreenColorGamut(id, modeIdx);
    ScreenColorGamut mode = COLOR_GAMUT_BT2020;
    ASSERT_EQ(proxy->GetScreenColorGamut(id, mode), 2);
}

/**
 * @tc.name: GetScreenGamutMap Test
 * @tc.desc: GetScreenGamutMap Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenGamutMap, TestSize.Level1)
{
    ScreenId id = 1;
    ScreenGamutMap mode = GAMUT_MAP_EXTENSION;
    proxy->SetScreenGamutMap(id, mode);
    proxy->SetScreenCorrection(id, ScreenRotation::ROTATION_90);
    ASSERT_EQ(proxy->GetScreenGamutMap(id, mode), 2);
}

/**
 * @tc.name: GetScreenHDRCapability Test
 * @tc.desc: GetScreenHDRCapability Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenHDRCapability, TestSize.Level1)
{
    ScreenId id = 1;
    RSScreenHDRCapability screenHdrCapability;
    ASSERT_EQ(proxy->GetScreenHDRCapability(id, screenHdrCapability), 2);
}

/**
 * @tc.name: GetPixelFormat Test
 * @tc.desc: GetPixelFormat Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetPixelFormat, TestSize.Level1)
{
    ScreenId id = 1;
    GraphicPixelFormat pixelFormat = GRAPHIC_PIXEL_FMT_BGRA_8888;
    EXPECT_EQ(proxy->SetPixelFormat(id, pixelFormat), 2);
    ASSERT_EQ(proxy->GetPixelFormat(id, pixelFormat), 2);
}

/**
 * @tc.name: GetScreenHDRFormat Test
 * @tc.desc: GetScreenHDRFormat Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenHDRFormat, TestSize.Level1)
{
    ScreenId id = 1;
    std::vector<ScreenHDRFormat> hdrFormats;
    ASSERT_EQ(proxy->GetScreenSupportedHDRFormats(id, hdrFormats), 2);
    ScreenHDRFormat hdrFormat = IMAGE_HDR_ISO_DUAL;
    ASSERT_EQ(proxy->GetScreenHDRFormat(id, hdrFormat), 2);
}

/**
 * @tc.name: SetScreenHDRFormat Test
 * @tc.desc: SetScreenHDRFormat Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetScreenHDRFormat, TestSize.Level1)
{
    ScreenId id = 1;
    int32_t modeIdx = 1;
    ASSERT_EQ(proxy->SetScreenHDRFormat(id, modeIdx), 2);
    std::vector<GraphicCM_ColorSpaceType> colorSpaces;
    ASSERT_EQ(proxy->GetScreenSupportedColorSpaces(id, colorSpaces), 2);
}

/**
 * @tc.name: GetScreenColorSpace Test
 * @tc.desc: GetScreenColorSpace Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetScreenColorSpace, TestSize.Level1)
{
    ScreenId id = 1;
    GraphicCM_ColorSpaceType colorSpace = GraphicCM_ColorSpaceType::GRAPHIC_CM_SRGB_FULL;
    ASSERT_EQ(proxy->SetScreenColorSpace(id, colorSpace), 2);
    std::vector<GraphicCM_ColorSpaceType> colorSpaces;
    ASSERT_EQ(proxy->GetScreenColorSpace(id, colorSpace), 2);
}

/**
 * @tc.name: GetBitmap Test
 * @tc.desc: GetBitmap Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetBitmap, TestSize.Level1)
{
    ScreenId id = 1;
    RSScreenType screenType = RSScreenType::VIRTUAL_TYPE_SCREEN;
    ASSERT_EQ(proxy->GetScreenType(id, screenType), 2);
    Drawing::Bitmap bitmap;
    ASSERT_FALSE(proxy->GetBitmap(1, bitmap));
}

/**
 * @tc.name: SetVirtualMirrorScreenScaleMode Test
 * @tc.desc: SetVirtualMirrorScreenScaleMode Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetVirtualMirrorScreenScaleMode, TestSize.Level1)
{
    ScreenId id = 1;
    EXPECT_EQ(proxy->SetScreenSkipFrameInterval(id, 1), 2);
    EXPECT_FALSE(proxy->SetVirtualMirrorScreenCanvasRotation(id, true));
    ASSERT_FALSE(proxy->SetVirtualMirrorScreenScaleMode(id, ScreenScaleMode::UNISCALE_MODE));
}

/**
 * @tc.name: SetGlobalDarkColorMode Test
 * @tc.desc: SetGlobalDarkColorMode Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetGlobalDarkColorMode, TestSize.Level1)
{
    ASSERT_TRUE(proxy->SetGlobalDarkColorMode(true));
}

/**
 * @tc.name: GetPixelmap Test
 * @tc.desc: GetPixelmap Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, GetPixelmap, TestSize.Level1)
{
    std::shared_ptr<Media::PixelMap> pixelmap = std::make_shared<Media::PixelMap>();
    Drawing::Rect rect;
    NodeId id = 1;
    std::shared_ptr<Drawing::DrawCmdList> drawCmdList = std::make_shared<Drawing::DrawCmdList>();
    ASSERT_FALSE(proxy->GetPixelmap(id, pixelmap, &rect, drawCmdList));
}

/**
 * @tc.name: UnRegisterTypeface Test
 * @tc.desc: UnRegisterTypeface Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, UnRegisterTypeface, TestSize.Level1)
{
    std::shared_ptr<Drawing::Typeface> typeface = Drawing::Typeface::MakeDefault();
    EXPECT_FALSE(proxy->RegisterTypeface(1, typeface));
    ASSERT_TRUE(proxy->UnRegisterTypeface(1));
}

/**
 * @tc.name: RegisterSurfaceOcclusionChangeCallback Test
 * @tc.desc: RegisterSurfaceOcclusionChangeCallback Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, RegisterSurfaceOcclusionChangeCallback, TestSize.Level1)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    sptr<RSIOcclusionChangeCallback> callback = iface_cast<RSIOcclusionChangeCallback>(remoteObject);
    EXPECT_NE(proxy->RegisterOcclusionChangeCallback(callback), -1);
    NodeId id = 1;
    proxy->UnRegisterSurfaceOcclusionChangeCallback(id);
    sptr<RSISurfaceOcclusionChangeCallback> callbackTwo = iface_cast<RSISurfaceOcclusionChangeCallback>(remoteObject);
    std::vector<float> partitionPoints;
    ASSERT_EQ(proxy->RegisterSurfaceOcclusionChangeCallback(id, callbackTwo, partitionPoints), 2);
}

/**
 * @tc.name: RegisterHgmRefreshRateUpdateCallback Test
 * @tc.desc: RegisterHgmRefreshRateUpdateCallback Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, RegisterHgmRefreshRateUpdateCallback, TestSize.Level1)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    sptr<RSIHgmConfigChangeCallback> callback = iface_cast<RSIHgmConfigChangeCallback>(remoteObject);
    EXPECT_EQ(proxy->RegisterHgmConfigChangeCallback(callback), 2);
    EXPECT_EQ(proxy->RegisterHgmRefreshRateModeChangeCallback(callback), 2);
    ASSERT_EQ(proxy->RegisterHgmRefreshRateUpdateCallback(callback), 2);
}

/**
 * @tc.name: SetSystemAnimatedScenes Test
 * @tc.desc: SetSystemAnimatedScenes Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetSystemAnimatedScenes, TestSize.Level1)
{
    proxy->SetAppWindowNum(1);
    ASSERT_FALSE(proxy->SetSystemAnimatedScenes(SystemAnimatedScenes::ENTER_MISSION_CENTER));
}

/**
 * @tc.name: ResizeVirtualScreen Test
 * @tc.desc: ResizeVirtualScreen Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, ResizeVirtualScreen, TestSize.Level1)
{
    std::shared_ptr<Media::PixelMap> watermarkImg = std::make_shared<Media::PixelMap>();
    proxy->ShowWatermark(watermarkImg, true);
    proxy->ReportJankStats();
    ScreenId id = 1;
    ASSERT_EQ(proxy->ResizeVirtualScreen(id, 1, 1), 2);
}

/**
 * @tc.name: ReportEventJankFrame Test
 * @tc.desc: ReportEventJankFrame Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, ReportEventJankFrame, TestSize.Level1)
{
    DataBaseRs info;
    proxy->ReportEventResponse(info);
    proxy->ReportEventComplete(info);
    proxy->ReportEventJankFrame(info);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: ReportDataBaseRs Test
 * @tc.desc: ReportDataBaseRs Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, ReportDataBaseRs, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    DataBaseRs info;
    proxy->ReportDataBaseRs(data, reply, option, info);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: NotifyLightFactorStatus Test
 * @tc.desc: NotifyLightFactorStatus Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, NotifyLightFactorStatus, TestSize.Level1)
{
    GameStateData info;
    proxy->ReportGameStateData(info);
    NodeId id = 1;
    proxy->SetHardwareEnabled(id, true, SelfDrawingNodeType::DEFAULT, true);
    proxy->NotifyLightFactorStatus(true);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: SetCacheEnabledForRotation Test
 * @tc.desc: SetCacheEnabledForRotation Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, SetCacheEnabledForRotation, TestSize.Level1)
{
    std::vector<std::string> packageList;
    proxy->NotifyPackageEvent(1, packageList);
    EventInfo eventInfo;
    proxy->NotifyRefreshRateEvent(eventInfo);
    int32_t touchStatus = 1;
    int32_t touchCnt = 0;
    proxy->NotifyTouchEvent(touchStatus, touchCnt);
    proxy->NotifyDynamicModeEvent(true);
    proxy->SetCacheEnabledForRotation(true);
    ASSERT_EQ(proxy->transactionDataIndex_, 0);
}

/**
 * @tc.name: RunOnRemoteDiedCallback Test
 * @tc.desc: RunOnRemoteDiedCallback Test
 * @tc.type:FUNC
 * @tc.require: issueI9KXXE
 */
HWTEST_F(RSRenderServiceProxyTest, RunOnRemoteDiedCallback, TestSize.Level1)
{
    OnRemoteDiedCallback callback = []() {};
    proxy->SetOnRemoteDiedCallback(callback);
    proxy->RunOnRemoteDiedCallback();
    ASSERT_NE(proxy->OnRemoteDiedCallback_, nullptr);
}

/**
 * @tc.name: GetActiveDirtyRegionInfo Test
 * @tc.desc: GetActiveDirtyRegionInfo Test
 * @tc.type:FUNC
 * @tc.require: issueIA61E9
 */
HWTEST_F(RSRenderServiceProxyTest, GetActiveDirtyRegionInfo, TestSize.Level1)
{
    NodeId id = 0;
    std::string windowName = "Test";
    RectI rectI(0, 0, 0, 0);
    std::vector<RectI> rectIs = {rectI};
    GpuDirtyRegionCollection::GetInstance().UpdateActiveDirtyInfoForDFX(id, windowName, rectIs);
    ASSERT_EQ(proxy->GetActiveDirtyRegionInfo().size(), 0);
}

/**
 * @tc.name: GetGlobalDirtyRegionInfo Test
 * @tc.desc: GetGlobalDirtyRegionInfo Test
 * @tc.type:FUNC
 * @tc.require: issueIA61E9
 */
HWTEST_F(RSRenderServiceProxyTest, GetGlobalDirtyRegionInfo, TestSize.Level1)
{
    RectI rectI(0, 0, 0, 0);
    GpuDirtyRegionCollection::GetInstance().UpdateGlobalDirtyInfoForDFX(rectI);
    ASSERT_EQ(proxy->GetGlobalDirtyRegionInfo().globalFramesNumber, 0);
}

/**
 * @tc.name: GetLayerComposeInfo Test
 * @tc.desc: GetLayerComposeInfo Test
 * @tc.type:FUNC
 * @tc.require: issueIA61E9
 */
HWTEST_F(RSRenderServiceProxyTest, GetLayerComposeInfo, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateRedrawFrameNumberForDFX();
    ASSERT_EQ(proxy->GetLayerComposeInfo().redrawFrameNumber, 0);
}

/**
 * @tc.name: GetHwcDisabledReasonInfo Test
 * @tc.desc: GetHwcDisabledReasonInfo Test
 * @tc.type:FUNC
 * @tc.require: issueIACUOK
 */
HWTEST_F(RSRenderServiceProxyTest, GetHwcDisabledReasonInfo, TestSize.Level1)
{
    NodeId id = 0;
    std::string nodeName = "Test";
    HwcDisabledReasonCollection::GetInstance().UpdateHwcDisabledReasonForDFX(id,
        HwcDisabledReasons::DISABLED_BY_SRC_PIXEL, nodeName);
    ASSERT_EQ(proxy->GetHwcDisabledReasonInfo().size(), 0);
}

/**
 * @tc.name: GetHdrOnDuration Test
 * @tc.desc: GetHdrOnDuration Test
 * @tc.type: FUNC
 * @tc.require: issueIB4YDF
 */
HWTEST_F(RSRenderServiceProxyTest, GetHdrOnDuration, TestSize.Level1)
{
    ASSERT_NE(proxy, nullptr);
    EXPECT_GE(proxy->GetHdrOnDuration(), 0);
}

/**
 * @tc.name: RegisterUIExtensionCallback Test
 * @tc.desc: RegisterUIExtensionCallback Test, with empty/non-empty callback.
 * @tc.type:FUNC
 * @tc.require: issueIABHAX
 */
HWTEST_F(RSRenderServiceProxyTest, RegisterUIExtensionCallback, TestSize.Level1)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    sptr<RSIUIExtensionCallback> callback = iface_cast<RSIUIExtensionCallback>(remoteObject);
    uint64_t userId = 0;
    ASSERT_EQ(proxy->RegisterUIExtensionCallback(userId, nullptr), INVALID_ARGUMENTS);
    ASSERT_EQ(proxy->RegisterUIExtensionCallback(userId, callback), RS_CONNECTION_ERROR);
}

/**
 * @tc.name: SetLayerTop Test
 * @tc.desc: SetLayerTop Test
 * @tc.type:FUNC
 * @tc.require: issueIAOZFC
 */
HWTEST_F(RSRenderServiceProxyTest, SetLayerTop, TestSize.Level1)
{
    const std::string nodeIdStr = "123456";
    proxy->SetLayerTop(nodeIdStr, true);
    proxy->SetLayerTop(nodeIdStr, false);
    ASSERT_TRUE(proxy);
}
} // namespace Rosen
} // namespace OHOS