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
#include "gtest/gtest.h"
#include "impl_interface/typeface_impl.h"
#include "skia_adapter/skia_typeface.h"

#include "render/rs_typeface_cache.h"
#include "transaction/rs_interfaces.h"
#include "transaction/rs_render_service_client.h"
#include "ui/rs_canvas_node.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSInterfacesTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSInterfacesTest::SetUpTestCase() {}
void RSInterfacesTest::TearDownTestCase() {}
void RSInterfacesTest::SetUp() {}
void RSInterfacesTest::TearDown() {}

/**
 * @tc.name: TakeSurfaceCaptureForUI001
 * @tc.desc: test results of TakeSurfaceCaptureForUI
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, TakeSurfaceCaptureForUI001, TestSize.Level1)
{
    class TestSurfaceCapture : public SurfaceCaptureCallback {
    public:
        explicit TestSurfaceCapture() {}
        ~TestSurfaceCapture() {}
        void OnSurfaceCapture(std::shared_ptr<Media::PixelMap> pixelmap) override {}
    };
    RSInterfaces& instance = RSInterfaces::GetInstance();
    auto callback = std::make_shared<TestSurfaceCapture>();
    bool res = instance.TakeSurfaceCaptureForUI(nullptr, callback, 1.f, 1.f, true);
    EXPECT_TRUE(res == false);

    auto node = std::make_shared<RSNode>(true);
    res = instance.TakeSurfaceCaptureForUI(nullptr, callback, 1.f, 1.f, true);
    EXPECT_TRUE(res == false);

    RSUINodeType type = node->GetType();
    type = RSUINodeType::UNKNOW;
    res = instance.TakeSurfaceCaptureForUI(nullptr, callback, 1.f, 1.f, true);
    EXPECT_TRUE(res == false);

    RSDisplayNodeConfig config;
    auto rsDisplayNode = RSDisplayNode::Create(config);
    res = instance.TakeSurfaceCaptureForUI(rsDisplayNode, callback, 1.f, 1.f, true);
    EXPECT_TRUE(res == false);
}

/**
 * @tc.name: TakeSurfaceCaptureForUI002
 * @tc.desc: test results of TakeSurfaceCaptureForUI
 * @tc.type: FUNC
 * @tc.require: issueIA61E9
 */
HWTEST_F(RSInterfacesTest, TakeSurfaceCaptureForUI002, TestSize.Level1)
{
    std::shared_ptr<RSNode> node = nullptr;
    std::shared_ptr<SurfaceCaptureCallback> callback = nullptr;
    RSInterfaces& instance = RSInterfaces::GetInstance();
    bool res = instance.TakeSurfaceCaptureForUI(node, callback, 1.f, 1.f, true);
    EXPECT_TRUE(res == false);

    node = std::make_shared<RSNode>(true);
    res = instance.TakeSurfaceCaptureForUI(node, callback, 1.f, 1.f, true);
    EXPECT_TRUE(res == false);
}

/**
 * @tc.name: TakeSurfaceCaptureForUI003
 * @tc.desc: test results of TakeSurfaceCaptureForUI
 * @tc.type: FUNC
 * @tc.require: issueIA61E9
 */
HWTEST_F(RSInterfacesTest, TakeSurfaceCaptureForUI003, TestSize.Level1)
{
    std::shared_ptr<RSNode> node = nullptr;
    std::shared_ptr<SurfaceCaptureCallback> callback = nullptr;
    RSInterfaces& instance = RSInterfaces::GetInstance();
    Drawing::Rect specifiedAreaRect(0.f, 0.f, 0.f, 0.f);
    bool res = instance.TakeSurfaceCaptureForUI(node, callback, 1.f, 1.f, true, specifiedAreaRect);
    EXPECT_TRUE(res == false);

    node = std::make_shared<RSNode>(true);
    res = instance.TakeSurfaceCaptureForUI(node, callback, 1.f, 1.f, true, specifiedAreaRect);
    EXPECT_TRUE(res == false);
}

/**
 * @tc.name: SetHwcNodeBoundsTest
 * @tc.desc: test results of SetHwcNodeBounds
 * @tc.type: FUNC
 * @tc.require: issueIB2QCC
 */
HWTEST_F(RSInterfacesTest, SetHwcNodeBoundsTest, TestSize.Level1)
{
    NodeId nodeId = 1;
    RSInterfaces& instance = RSInterfaces::GetInstance();
    bool res = instance.SetHwcNodeBounds(nodeId, 1.0f, 1.0f, 1.0f, 1.0f);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: RegisterTypeface001
 * @tc.desc: test results of RegisterTypeface
 * @tc.type: FUNC
 * @tc.require: issueIA61E9
 */
HWTEST_F(RSInterfacesTest, RegisterTypeface001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    auto typefaceImpl = std::make_shared<Drawing::SkiaTypeface>();
    EXPECT_NE(typefaceImpl, nullptr);
    auto typeface = std::make_shared<Drawing::Typeface>(typefaceImpl);
    EXPECT_NE(typeface, nullptr);
    auto globalUniqueId = RSTypefaceCache::GenGlobalUniqueId(typeface->GetUniqueID());
    RSTypefaceCache& typefaceCache = RSTypefaceCache::Instance();
    typefaceCache.typefaceHashCode_.emplace(globalUniqueId, 0);
    instance.RegisterTypeface(typeface);
    typefaceCache.typefaceHashCode_.clear();
}

/**
 * @tc.name: UnRegisterTypeface001
 * @tc.desc: test results of UnRegisterTypeface
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, UnRegisterTypeface001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    auto typefaceImpl = std::make_shared<Drawing::SkiaTypeface>();
    auto typeface = std::make_shared<Drawing::Typeface>(typefaceImpl);
    bool res = instance.UnRegisterTypeface(typeface);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: GetMemoryGraphics001
 * @tc.desc: test results of GetMemoryGraphics
 * @tc.type: FUNC
 * @tc.require: issueIAS4B8
 */
HWTEST_F(RSInterfacesTest, GetMemoryGraphics001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    auto res = instance.GetMemoryGraphics();
    EXPECT_FALSE(res.empty());
}

/**
 * @tc.name: GetTotalAppMemSize001
 * @tc.desc: test results of GetTotalAppMemSize
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, GetTotalAppMemSize001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    float cpuMemSize = 1.f;
    float gpuMemSize = 1.f;
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    bool res = instance.GetTotalAppMemSize(cpuMemSize, gpuMemSize);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: SetAppWindowNum001
 * @tc.desc: test results of SetAppWindowNum
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, SetAppWindowNum001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.SetAppWindowNum(1);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: ReportJankStats001
 * @tc.desc: test results of ReportJankStats
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, ReportJankStats001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.ReportJankStats();
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: ReportEventResponse001
 * @tc.desc: test results of ReportEventResponse
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, ReportEventResponse001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    DataBaseRs info;
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.ReportEventResponse(info);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: ReportEventComplete001
 * @tc.desc: test results of ReportEventComplete
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, ReportEventComplete001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    DataBaseRs info;
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.ReportEventComplete(info);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: ReportEventJankFrame001
 * @tc.desc: test results of ReportEventJankFrame
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, ReportEventJankFrame001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    DataBaseRs info;
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.ReportEventJankFrame(info);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: ReportGameStateData001
 * @tc.desc: test results of ReportGameStateData
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, ReportGameStateData001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    GameStateData info;
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.ReportGameStateData(info);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: SetOnRemoteDiedCallback001
 * @tc.desc: test results of SetOnRemoteDiedCallback
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, SetOnRemoteDiedCallback001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    OnRemoteDiedCallback callback = []() {};
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.SetOnRemoteDiedCallback(callback);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: GetActiveDirtyRegionInfo001
 * @tc.desc: test results of GetActiveDirtyRegionInfo
 * @tc.type: FUNC
 * @tc.require: issueI97N4E
 */
HWTEST_F(RSInterfacesTest, GetActiveDirtyRegionInfo001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.GetActiveDirtyRegionInfo();
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: GetGlobalDirtyRegionInfo001
 * @tc.desc: test results of GetGlobalDirtyRegionInfo
 * @tc.type: FUNC
 * @tc.require: issueI97N4E
 */
HWTEST_F(RSInterfacesTest, GetGlobalDirtyRegionInfo001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.GetGlobalDirtyRegionInfo();
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: GetLayerComposeInfo001
 * @tc.desc: test results of GetLayerComposeInfo
 * @tc.type: FUNC
 * @tc.require: issueI97N4E
 */
HWTEST_F(RSInterfacesTest, GetLayerComposeInfo001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.GetLayerComposeInfo();
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: GetHardwareComposeDisabledReasonInfo001
 * @tc.desc: test results of GetHwcDisabledReasonInfo
 * @tc.type: FUNC
 * @tc.require: issueI97N4E
 */
HWTEST_F(RSInterfacesTest, GetHardwareComposeDisabledReasonInfo001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.GetHwcDisabledReasonInfo();
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: GetHdrOnDuration001
 * @tc.desc: test results of GetHdrOnDuration
 * @tc.type: FUNC
 * @tc.require: issueIB4YDF
 */
HWTEST_F(RSInterfacesTest, GetHdrOnDuration001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    EXPECT_GE(instance.GetHdrOnDuration(), 0);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: SetVmaCacheStatus001
 * @tc.desc: test results of SetVmaCacheStatus
 * @tc.type: FUNC
 * @tc.require: issueI97N4E
 */
HWTEST_F(RSInterfacesTest, SetVmaCacheStatus001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.SetVmaCacheStatus(true);
    instance.SetVmaCacheStatus(false);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

#ifdef TP_FEATURE_ENABLE
/**
 * @tc.name: SetTpFeatureConfig001
 * @tc.desc: test results of SetTpFeatureConfig
 * @tc.type: FUNC
 * @tc.require: issueI9N0I9
 */
HWTEST_F(RSInterfacesTest, SetTpFeatureConfig001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    int32_t feature = 1;
    std::string config = "config";
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.SetTpFeatureConfig(feature, config.c_str());
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: SetTpFeatureConfig002
 * @tc.desc: test results of SetTpFeatureConfig
 * @tc.type: FUNC
 * @tc.require: issueIB39L8
 */
HWTEST_F(RSInterfacesTest, SetTpFeatureConfig002, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    int32_t feature = 1;
    std::string config = "config";
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    instance.SetTpFeatureConfig(feature, config.c_str(), TpFeatureConfigType::AFT_TP_FEATURE);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}
#endif

/**
 * @tc.name: GetRefreshInfo001
 * @tc.desc: test results of GetRefreshInfo
 * @tc.type: FUNC
 * @tc.require: issueI97N4E
 */
HWTEST_F(RSInterfacesTest, GetRefreshInfo001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    GameStateData info;
    std::string str = instance.GetRefreshInfo(info.pid);
    EXPECT_TRUE(str == "");
}

/**
 * @tc.name: SetWatermark001
 * @tc.desc: test results of SetWatermark
 * @tc.type: FUNC
 * @tc.require: issueIASMZG
 */
HWTEST_F(RSInterfacesTest, SetWatermark001, TestSize.Level1)
{
    if (!RSSystemProperties::IsPcType()) {
        return;
    }
    RSInterfaces& instance = RSInterfaces::GetInstance();
    std::shared_ptr<Media::PixelMap> pixelmap = std::make_shared<Media::PixelMap>();
    instance.renderServiceClient_ = nullptr;
    bool res = instance.SetWatermark("test", pixelmap);
    EXPECT_FALSE(res);

    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    res = instance.SetWatermark("test", pixelmap);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: SetWatermark002
 * @tc.desc: test results of SetWatermark
 * @tc.type: FUNC
 * @tc.require: issueIASMZG
 */
HWTEST_F(RSInterfacesTest, SetWatermark002, TestSize.Level1)
{
    if (!RSSystemProperties::IsPcType()) {
        return;
    }
    RSInterfaces& instance = RSInterfaces::GetInstance();
    std::shared_ptr<Media::PixelMap> pixelmap = std::make_shared<Media::PixelMap>();

    std::string name1 = "";
    bool res = instance.SetWatermark(name1, pixelmap);
    EXPECT_FALSE(res);

    std::string name2(1, 't');
    res = instance.SetWatermark(name2, pixelmap);
    EXPECT_TRUE(res);

    std::string name3(2, 't');
    res = instance.SetWatermark(name3, pixelmap);
    EXPECT_TRUE(res);

    std::string name4(128, 't');
    res = instance.SetWatermark(name4, pixelmap);
    EXPECT_TRUE(res);

    std::string name5(129, 't');
    res = instance.SetWatermark(name5, pixelmap);
    EXPECT_FALSE(res);

    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    res = instance.SetWatermark("test", pixelmap);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: RegisterSurfaceBufferCallback001
 * @tc.desc: test results of RegisterSurfaceBufferCallback
 * @tc.type: FUNC
 * @tc.require: issueIASMZG
 */
HWTEST_F(RSInterfacesTest, RegisterSurfaceBufferCallback001, TestSize.Level1)
{
    class TestSurfaceBufferCallback : public SurfaceBufferCallback {
    public:
        void OnFinish(const FinishCallbackRet& ret) {}
        void OnAfterAcquireBuffer(const AfterAcquireBufferRet& ret) {}
    };
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();

    bool res = instance.RegisterSurfaceBufferCallback(1, 1, nullptr);
    EXPECT_FALSE(res);

    auto callback = std::make_shared<TestSurfaceBufferCallback>();
    res = instance.RegisterSurfaceBufferCallback(1, 1, callback);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: UnregisterSurfaceBufferCallback001
 * @tc.desc: test results of UnregisterSurfaceBufferCallback
 * @tc.type: FUNC
 * @tc.require: issueIASMZG
 */
HWTEST_F(RSInterfacesTest, UnregisterSurfaceBufferCallback001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    bool res = instance.UnregisterSurfaceBufferCallback(1, 1);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: SetWindowContainer001
 * @tc.desc: test results of SetWindowContainer
 * @tc.type: FUNC
 * @tc.require: issueIBIK1X
 */
HWTEST_F(RSInterfacesTest, SetWindowContainer001, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    instance.renderServiceClient_ = std::make_unique<RSRenderServiceClient>();
    NodeId nodeId = {};
    instance.SetWindowContainer(nodeId, false);
    EXPECT_TRUE(instance.renderServiceClient_ != nullptr);
}

/**
 * @tc.name: GetPixelMapByProcessIdTest
 * @tc.desc: test results of GetPixelMapByProcessId
 * @tc.type: FUNC
 * @tc.require: issueIBJFIK
 */
HWTEST_F(RSInterfacesTest, GetPixelMapByProcessIdTest, TestSize.Level1)
{
    RSInterfaces& instance = RSInterfaces::GetInstance();
    pid_t pid = 0;
    std::vector<std::shared_ptr<Media::PixelMap>> pixelMapVector;
    int32_t res = instance.GetPixelMapByProcessId(pixelMapVector, pid);
    EXPECT_EQ(res, SUCCESS);
}
} // namespace OHOS::Rosen
