/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <memory>
#include "gtest/gtest.h"
#include "limit_number.h"

#include "pipeline/main_thread/rs_render_service_connection.h"
#include "pipeline/rs_test_util.h"
#include "platform/ohos/rs_render_service_connect_hub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSRenderServiceConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderServiceConnectionTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}
void RSRenderServiceConnectionTest::TearDownTestCase() {}
void RSRenderServiceConnectionTest::SetUp() {}
void RSRenderServiceConnectionTest::TearDown() {}

/**
 * @tc.name: GetMemoryGraphic001
 * @tc.desc: GetMemoryGraphic
 * @tc.type: FUNC
 * @tc.require:issueI590LM
 */
HWTEST_F(RSRenderServiceConnectionTest, GetMemoryGraphic001, TestSize.Level1)
{
    auto mainThread = RSMainThread::Instance();
    sptr<RSIConnectionToken> token = new IRemoteStub<RSIConnectionToken>();
    auto rsRenderServiceConnection = new RSRenderServiceConnection(
        0, nullptr, mainThread, CreateOrGetScreenManager(), token->AsObject(), nullptr);
    MemoryGraphic mem1;
    rsRenderServiceConnection->GetMemoryGraphic(123, mem1);
    ASSERT_EQ(mem1.GetGpuMemorySize(), 0);
    MemoryGraphic mem2;
    rsRenderServiceConnection->GetMemoryGraphic(0, mem2);
    ASSERT_EQ(mem2.GetGpuMemorySize(), 0);
}

/**
 * @tc.name: GetMemoryGraphic002
 * @tc.desc: GetMemoryGraphic
 * @tc.type: FUNC
 * @tc.require:issueI590LM
 */
HWTEST_F(RSRenderServiceConnectionTest, GetMemoryGraphic002, TestSize.Level1)
{
    auto mainThread = RSMainThread::Instance();
    sptr<RSIConnectionToken> token = new IRemoteStub<RSIConnectionToken>();
    auto rsRenderServiceConnection = new RSRenderServiceConnection(
        0, nullptr, mainThread, CreateOrGetScreenManager(), token->AsObject(), nullptr);
    std::vector<MemoryGraphic> memoryGraphics;
    rsRenderServiceConnection->GetMemoryGraphics(memoryGraphics);
    ASSERT_EQ(memoryGraphics.size(), 0);
}

/**
 * @tc.name: SetSurfaceSystemWatermarkTest001
 * @tc.desc: SetSurfaceSystemWatermarkTest001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceConnectionTest, SetSurfaceSystemWatermarkTest001, TestSize.Level1)
{
    constexpr uint32_t defaultScreenWidth = 400;
    constexpr uint32_t defaultScreenHight = 320;
    auto mainThread = RSMainThread::Instance();
    std::string watermarkName = "watermarkName";

    Media::InitializationOptions opts;
    opts.size.width = defaultScreenWidth * 2.5;
    opts.size.height = defaultScreenHight * 2.5;
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(opts);
    pid_t pid = 1000;
    // No store waterimg and pixelmap == nullptr
    auto res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(pid, watermarkName, nullptr,
        {}, SurfaceWatermarkType::SYSTEM_WATER_MARK, mainThread->GetContext(), true);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_PIXELMAP_INVALID);

    // Test pixelMap == nullptr and rs has stored watermask img.
    mainThread->surfaceWatermarkHelper_.surfaceWatermarks_[watermarkName];
    res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(pid, watermarkName, nullptr,
        {}, SurfaceWatermarkType::SYSTEM_WATER_MARK, mainThread->GetContext(), true);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_RS_CONNECTION_ERROR);

    // Test pixelMap != nullptr and has rsNode
    mainThread->surfaceWatermarkHelper_.surfaceWatermarks_[watermarkName];
    res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(pid, watermarkName, nullptr, {11235642},
        SurfaceWatermarkType::SYSTEM_WATER_MARK, mainThread->GetContext(), true);
    mainThread->surfaceWatermarkHelper_.surfaceWatermarks_.erase(watermarkName);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_NOT_SURFACE_NODE_ERROR);
    EXPECT_EQ(mainThread->surfaceWatermarkHelper_.surfaceWatermarks_.size(), 0);

    // Test pixelMap != nullptr and rs has not stored watermask img
    NodeId renderNodeId = 502232;
    auto renderNode = std::make_shared<RSRenderNode>(renderNodeId, true);
    mainThread->context_->nodeMap.RegisterRenderNode(renderNode);
    res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(ExtractPid(renderNodeId), watermarkName,
        pixelMap, {renderNodeId}, SurfaceWatermarkType::SYSTEM_WATER_MARK, mainThread->GetContext(), true);
    mainThread->surfaceWatermarkHelper_.surfaceWatermarks_.erase(watermarkName);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_NOT_SURFACE_NODE_ERROR);
    EXPECT_EQ(mainThread->surfaceWatermarkHelper_.surfaceWatermarks_.size(), 0);
    mainThread->surfaceWatermarkHelper_.ClearSurfaceWatermark(pid, watermarkName, mainThread->GetContext(), true);
    EXPECT_EQ(mainThread->surfaceWatermarkHelper_.surfaceWatermarks_.size(), 0);

    // Test pixelMap != nullptr and rs has store watermark img and node success
    NodeId surfaceNodeId = 502232;
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceNodeId);
    mainThread->context_->nodeMap.RegisterRenderNode(surfaceNode);
    res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(ExtractPid(surfaceNodeId), watermarkName,
        pixelMap, {surfaceNodeId}, SurfaceWatermarkType::SYSTEM_WATER_MARK, mainThread->GetContext(), true);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_SUCCESS);

    mainThread->surfaceWatermarkHelper_.ClearSurfaceWatermark(ExtractPid(surfaceNodeId), watermarkName,
        mainThread->GetContext(), true, false);
    surfaceNode->GetSurfaceWatermarkEnabledMap(SurfaceWatermarkType::SYSTEM_WATER_MARK);

    // code coverage
    auto param = std::move(surfaceNode->stagingRenderParams_);
    surfaceNode->GetSurfaceWatermarkEnabledMap(SurfaceWatermarkType::SYSTEM_WATER_MARK);
    surfaceNode->ClearWatermarkEnabled(watermarkName, SurfaceWatermarkType::SYSTEM_WATER_MARK);
    surfaceNode->stagingRenderParams_ = std::move(param);

    // Test Limit
    mainThread->surfaceWatermarkHelper_.registerSurfaceWatermarkCount_ = 1000;
    res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(ExtractPid(surfaceNodeId), "newWatermarkName",
        pixelMap, {}, SurfaceWatermarkType::SYSTEM_WATER_MARK, mainThread->GetContext(), true);
    EXPECT_EQ(mainThread->surfaceWatermarkHelper_.registerSurfaceWatermarkCount_, 1000);

    mainThread->surfaceWatermarkHelper_.registerSurfaceWatermarkCount_ = 0;

    // UnregisterRenderNode node
    mainThread->context_->nodeMap.UnregisterRenderNode(surfaceNodeId);
    mainThread->surfaceWatermarkHelper_.ClearSurfaceWatermark(pid, watermarkName, mainThread->GetContext(), true);
    EXPECT_EQ(mainThread->surfaceWatermarkHelper_.surfaceWatermarks_.size(), 0);
}

/**
 * @tc.name: SetSurfaceCustomWatermarkTest001
 * @tc.desc: SetSurfaceCustomWatermarkTest001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceConnectionTest, SetSurfaceCustomWatermarkTest001, TestSize.Level1)
{
    constexpr uint32_t defaultScreenWidth = 480;
    constexpr uint32_t defaultScreenHight = 320;
    auto screenManager = CreateOrGetScreenManager();
    ASSERT_NE(nullptr, screenManager);
    std::string name = "virtualScreen01";
    uint32_t width = defaultScreenWidth;
    uint32_t height = defaultScreenHight;
    auto csurface = IConsumerSurface::Create();
    ASSERT_NE(csurface, nullptr);
    auto producer = csurface->GetProducer();
    auto psurface = Surface::CreateSurfaceAsProducer(producer);
    ASSERT_NE(psurface, nullptr);
    auto id = screenManager->CreateVirtualScreen(name, width, height, psurface);
    ASSERT_NE(INVALID_SCREEN_ID, id);

    screenManager->SetDefaultScreenId(id);
    auto mainThread = RSMainThread::Instance();
    std::string watermarkName = "watermarkName";
    Media::InitializationOptions opts;
    opts.size.width = defaultScreenWidth;
    opts.size.height = defaultScreenHight;
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(opts);

    NodeId surfaceNodeId = 0XFFFFFFFFFFFF1234;
    auto screenId = screenManager->GetDefaultScreenId();
    auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceNodeId);
    surfaceNode->screenId_ = screenId;
    mainThread->context_->nodeMap.RegisterRenderNode(surfaceNode);

    // Test Check pid
    auto res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(ExtractPid(surfaceNodeId) + 1, watermarkName,
        pixelMap, {surfaceNodeId}, SurfaceWatermarkType::CUSTOM_WATER_MARK, mainThread->GetContext(), false);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_PERMISSION_ERROR);
    // Test upperNodeSize and less than screenSize
    NodeId screenRenderNodeId = 0X123;
    surfaceNode->screenNodeId_ = screenRenderNodeId;
    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(screenRenderNodeId, screenRenderNodeId);
    screenRenderNode->screenInfo_.width = defaultScreenWidth;
    screenRenderNode->screenInfo_.height = defaultScreenHight;
    mainThread->context_->nodeMap.RegisterRenderNode(screenRenderNode);

    surfaceNode->GetMutableRenderProperties().SetBoundsWidth(defaultScreenWidth - 50);
    surfaceNode->GetMutableRenderProperties().SetBoundsHeight(defaultScreenHight - 50);
    res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(ExtractPid(surfaceNodeId), watermarkName,
        pixelMap, {surfaceNodeId}, SurfaceWatermarkType::CUSTOM_WATER_MARK, mainThread->GetContext(), false);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_SUCCESS);
    mainThread->context_->nodeMap.UnregisterRenderNode(screenRenderNodeId);

    // Test less than NodeSize
    surfaceNode->GetMutableRenderProperties().SetBoundsWidth(defaultScreenWidth);
    surfaceNode->GetMutableRenderProperties().SetBoundsHeight(defaultScreenHight);
    res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(ExtractPid(surfaceNodeId), watermarkName,
        pixelMap, {surfaceNodeId}, SurfaceWatermarkType::CUSTOM_WATER_MARK, mainThread->GetContext(), false);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_SUCCESS);

    // Test piixelMap size greater than node size and screen size
    opts.size.width = defaultScreenWidth + 50;
    opts.size.height = defaultScreenHight + 50;
    pixelMap = Media::PixelMap::Create(opts);
    res = mainThread->surfaceWatermarkHelper_.SetSurfaceWatermark(ExtractPid(surfaceNodeId), watermarkName,
        pixelMap, {surfaceNodeId}, SurfaceWatermarkType::CUSTOM_WATER_MARK, mainThread->GetContext(), false);
    EXPECT_EQ(res, SurfaceWatermarkStatusCode::WATER_MARK_IMG_SIZE_ERROR);
    EXPECT_EQ(1, mainThread->surfaceWatermarkHelper_.surfaceWatermarks_.size());
    EXPECT_EQ(1, mainThread->surfaceWatermarkHelper_.watermarkNameMapNodeId_.size());

    auto iter = mainThread->surfaceWatermarkHelper_.watermarkNameMapNodeId_.find(watermarkName);
    EXPECT_NE(iter, mainThread->surfaceWatermarkHelper_.watermarkNameMapNodeId_.end());
    if (iter != mainThread->surfaceWatermarkHelper_.watermarkNameMapNodeId_.end()) {
        EXPECT_EQ(iter->second.first.size(), 1);
    }

    mainThread->surfaceWatermarkHelper_.ClearSurfaceWatermark(0, mainThread->GetContext());
    mainThread->surfaceWatermarkHelper_.ClearSurfaceWatermark(ExtractPid(surfaceNodeId), mainThread->GetContext());

    // Code coverage
    mainThread->surfaceWatermarkHelper_.ClearSurfaceWatermark(0, watermarkName,
        mainThread->GetContext(), false, false);
    mainThread->surfaceWatermarkHelper_.ClearSurfaceWatermarkForNodes(0, watermarkName, {},
        mainThread->GetContext(), false);
    mainThread->surfaceWatermarkHelper_.AddWatermarkNameMapNodeId(watermarkName, 0,
        SurfaceWatermarkType::CUSTOM_WATER_MARK);
    
    mainThread->surfaceWatermarkHelper_.watermarkNameMapNodeId_[watermarkName] = {{1},
        SurfaceWatermarkType::CUSTOM_WATER_MARK};
    mainThread->surfaceWatermarkHelper_.ClearSurfaceWatermark(0, watermarkName,
        mainThread->GetContext(), false, false);
    mainThread->context_->nodeMap.UnregisterRenderNode(surfaceNodeId);
}

/**
 * @tc.name: CreateNode
 * @tc.desc: CreateNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceConnectionTest, CreateNode, TestSize.Level1)
{
    auto mainThread = RSMainThread::Instance();
    ASSERT_NE(mainThread, nullptr);
    sptr<RSIConnectionToken> token = new IRemoteStub<RSIConnectionToken>();
    auto rsRenderServiceConnection = new RSRenderServiceConnection(
        0, nullptr, mainThread, CreateOrGetScreenManager(), token->AsObject(), nullptr);
    
    // create displayNode with async postTask (sync task processor not ready)
    RSDisplayNodeConfig rsDisplayNodeConfig = {};
    NodeId nodeId = 1;
    EXPECT_TRUE(rsRenderServiceConnection->CreateNode(rsDisplayNodeConfig, nodeId));

    // create dispalyNode with async postTask (sync task processor not ready, but isRunning_ was set to true)
    // at this time, CreateNode will first try to post sync task
    nodeId = 2;
    mainThread->isRunning_ = true;
    EXPECT_TRUE(rsRenderServiceConnection->CreateNode(rsDisplayNodeConfig, nodeId));

/**
 * @tc.name: RegisterTypefaceTest001
 * @tc.desc: test register typeface and unregister typeface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceConnectionTest, RegisterTypefaceTest001, TestSize.Level1)
{
    auto mainThread = RSMainThread::Instance();
    sptr<RSIConnectionToken> token = new IRemoteStub<RSIConnectionToken>();
    auto rsRenderServiceConnection =
        new RSRenderServiceConnection(0, nullptr, mainThread, CreateOrGetScreenManager(), token->AsObject(), nullptr);
    ASSERT_NE(rsRenderServiceConnection, nullptr);
    auto tf = Drawing::Typeface::MakeDefault();
    uint64_t uniqueId = 1;
    EXPECT_TRUE(rsRenderServiceConnection->RegisterTypeface(uniqueId, tf));
    EXPECT_TRUE(rsRenderServiceConnection->UnRegisterTypeface(uniqueId));
    EXPECT_TRUE(rsRenderServiceConnection->UnRegisterTypeface(0));
}

/**
 * @tc.name: GetBundleNameTest001
 * @tc.desc: GetBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceConnectionTest, GetBundleNameTest001, TestSize.Level1)
{
    auto mainThread = RSMainThread::Instance();
    ASSERT_NE(mainThread, nullptr);
    sptr<RSIConnectionToken> token = new IRemoteStub<RSIConnectionToken>();
    auto rsRenderServiceConnection = new RSRenderServiceConnection(
        0, nullptr, mainThread, CreateOrGetScreenManager(), token->AsObject(), nullptr);

    constexpr pid_t testPid = 1234;
    const std::string expectedBundleName = "com.example.app";
    rsRenderServiceConnection->pidToBundleName_[testPid] = expectedBundleName;

    std::string actualBundleName = rsRenderServiceConnection->GetBundleName(testPid);
    EXPECT_EQ(actualBundleName, expectedBundleName);
}

/**
 * @tc.name: GetBundleNameTest002
 * @tc.desc: GetBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceConnectionTest, GetBundleNameTest002, TestSize.Level1)
{
    auto mainThread = RSMainThread::Instance();
    ASSERT_NE(mainThread, nullptr);
    sptr<RSIConnectionToken> token = new IRemoteStub<RSIConnectionToken>();
    auto rsRenderServiceConnection = new RSRenderServiceConnection(
        0, nullptr, mainThread, CreateOrGetScreenManager(), token->AsObject(), nullptr);

    constexpr pid_t testPid = -1;
    const std::string bundleName = rsRenderServiceConnection->GetBundleName(testPid);
    EXPECT_TRUE(bundleName.empty());
}
} // namespace OHOS::Rosen