/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hdi_layer.h"
#include "mock_hdi_device.h"
#include "surface_buffer_impl.h"
#include "rs_composer_client.h"
#include "rs_surface_layer.h"
#include "surface_buffer_impl.h"

using namespace testing;
using namespace testing::ext;

#define WIDTH_VAL 50
#define HEIGHT_VAL 50

namespace OHOS {
namespace Rosen {
class HdiLayerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    static inline std::shared_ptr<HdiLayer> hdiLayer_;
    static inline std::shared_ptr<RSLayer> rsLayer_;
    static inline Mock::HdiDeviceMock* hdiDeviceMock_;
    static inline std::vector<std::string> paramKey_ {};
};

void HdiLayerTest::SetUpTestCase()
{
    hdiLayer_ = HdiLayer::CreateHdiLayer(0);
    rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    sptr<IConsumerSurface> cSurface = IConsumerSurface::Create();
    rsLayer_->SetSurface(cSurface);
    GraphicIRect srcRect = {0, 0, WIDTH_VAL, HEIGHT_VAL};
    GraphicIRect dstRect = {0, 0, WIDTH_VAL, HEIGHT_VAL};
    rsLayer_->SetLayerSize(dstRect);
    std::vector<GraphicIRect> dirtyRegions;
    dirtyRegions.emplace_back(srcRect);
    rsLayer_->SetDirtyRegions(dirtyRegions);
    rsLayer_->SetCropRect(srcRect);
    std::vector<GraphicIRect> visibleRegions;
    visibleRegions.emplace_back(srcRect);
    rsLayer_->SetVisibleRegions(visibleRegions);
    GraphicLayerAlpha layerAlpha = {false, false, 0, 0, 0};
    rsLayer_->SetAlpha(layerAlpha);
    rsLayer_->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    rsLayer_->SetBlendType(GraphicBlendType::GRAPHIC_BLEND_NONE);
    rsLayer_->SetLayerMaskInfo(LayerMask::LAYER_MASK_NORMAL);
    sptr<SurfaceBuffer> buffer = new SurfaceBufferImpl();
    sptr<SyncFence> fence = new SyncFence(-1);
    rsLayer_->SetBuffer(buffer, fence);

    hdiDeviceMock_ = Mock::HdiDeviceMock::GetInstance();
    EXPECT_CALL(*hdiDeviceMock_, SetLayerAlpha(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerSize(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetTransformMode(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerVisibleRegion(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerDirtyRegion(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerBuffer(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerCompositionType(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerBlendType(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerCrop(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerZorder(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerPreMulti(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorDataSpace(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, GetLayerColorDataSpace(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaData(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, GetSupportedLayerPerFrameParameterKey()).WillRepeatedly(testing::ReturnRef(paramKey_));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerPerFrameParameter(_, _, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerTunnelHandle(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetTunnelLayerId(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetTunnelLayerProperty(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, GetSupportedPresentTimestampType(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, GetPresentTimestamp(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMaskInfo(_, _, _)).WillRepeatedly(testing::Return(0));
}

void HdiLayerTest::TearDownTestCase() {}

namespace {
class MockSurfaceBuffer : public SurfaceBufferImpl {
public:
    MOCK_CONST_METHOD0(GetBufferHandle, BufferHandle*());
};

/**
 * Function: SetHdiDeviceMock001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetHdiDeviceMock()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetHdiDeviceMock001, Function | MediumTest| Level1)
{
    // Set hdiLayer_->device_ to nullptr
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetHdiDeviceMock(nullptr), GRAPHIC_DISPLAY_NULL_PTR);
    // Set hdiLayer_->device_ to hdiDeviceMock_
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetHdiDeviceMock(hdiDeviceMock_), GRAPHIC_DISPLAY_SUCCESS);
    // Reset hdiLayer_->device_ to hdiDeviceMock_
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetHdiDeviceMock(hdiDeviceMock_), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: Init001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call Init()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, Init001, Function | MediumTest| Level1)
{
    ASSERT_EQ(HdiLayerTest::hdiLayer_->Init(nullptr), false);
    EXPECT_CALL(*hdiDeviceMock_, CreateLayer(_, _, _, _)).WillRepeatedly(testing::Return(1));
    ASSERT_EQ(HdiLayerTest::hdiLayer_->Init(HdiLayerTest::rsLayer_), false);
    EXPECT_CALL(*hdiDeviceMock_, CreateLayer(_, _, _, _)).WillRepeatedly(testing::Return(0));
    ASSERT_EQ(HdiLayerTest::hdiLayer_->Init(HdiLayerTest::rsLayer_), true);
}

/**
 * Function: GetReleaseFence001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call GetReleaseFence()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, GetReleaseFence001, Function | MediumTest| Level1)
{
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetHdiLayerInfo(), GRAPHIC_DISPLAY_FAILURE);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->GetReleaseFence().GetRefPtr()->Get(), -1);
    HdiLayerTest::hdiLayer_->UpdateCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    HdiLayerTest::hdiLayer_->UpdateRSLayer(rsLayer_);
    HdiLayerTest::hdiLayer_->UpdateCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_CLIENT);
    HdiLayerTest::hdiLayer_->RecordPresentTime(0);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->GetReleaseFence().GetRefPtr()->Get(), -1);
}

/**
 * Function: SetHdiLayerInfo002
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetHdiLayerInfo002(true)
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetHdiLayerInfo002, Function | MediumTest| Level1)
{
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).WillRepeatedly(testing::Return(0));
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetHdiLayerInfo(false), GRAPHIC_DISPLAY_SUCCESS);
    hdiLayer_->SavePrevRSLayer();
    hdiLayer_->prevRSLayer_->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetHdiLayerInfo(false), GRAPHIC_DISPLAY_SUCCESS);
    hdiLayer_->rsLayer_->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetHdiLayerInfo(false), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerTunnelHandle001
 * Type: Function
 * Rank: Important(3)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetLayerTunnelHandle()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerTunnelHandle001, Function | MediumTest| Level3)
{
    HdiLayerTest::rsLayer_->SetTunnelHandleChange(true);
    HdiLayerTest::rsLayer_->SetTunnelHandle(nullptr);
    HdiLayerTest::hdiLayer_->UpdateRSLayer(HdiLayerTest::rsLayer_);
    EXPECT_CALL(*hdiDeviceMock_, SetLayerTunnelHandle(_, _, _)).WillRepeatedly(testing::Return(0));
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetLayerTunnelHandle(), GRAPHIC_DISPLAY_SUCCESS);

    HdiLayerTest::rsLayer_->SetTunnelHandle(new SurfaceTunnelHandle());
    HdiLayerTest::hdiLayer_->UpdateRSLayer(HdiLayerTest::rsLayer_);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetLayerTunnelHandle(), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetTunnelLayerId001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetTunnelLayerId()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetTunnelLayerId001, Function | MediumTest| Level1)
{
    HdiLayerTest::hdiLayer_->prevRSLayer_ = nullptr;
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetTunnelLayerId(), GRAPHIC_DISPLAY_SUCCESS);
    HdiLayerTest::hdiLayer_->prevRSLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetTunnelLayerId(), GRAPHIC_DISPLAY_SUCCESS);
}
 
/**
 * Function: SetTunnelLayerId002
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetTunnelLayerId()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetTunnelLayerId002, Function | MediumTest| Level1)
{
    uint32_t devId = 1;
    uint32_t layerId = 2;
    uint64_t tunnelId = 3;
 
    EXPECT_CALL(*hdiDeviceMock_, SetTunnelLayerId(devId, layerId, tunnelId)).WillRepeatedly(testing::Return(0));
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetTunnelLayerId(), 0);
}
 
/**
 * Function: SetTunnelLayerProperty001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetTunnelLayerProperty()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetTunnelLayerProperty001, Function | MediumTest| Level1)
{
    uint32_t devId = 1;
    uint32_t layerId = 2;
    uint32_t property = 3;
 
    EXPECT_CALL(*hdiDeviceMock_, SetTunnelLayerProperty(devId, layerId, property)).WillRepeatedly(testing::Return(0));
    ASSERT_EQ(HdiLayerTest::hdiLayer_->SetTunnelLayerProperty(), 0);
}

/**
 * Function: GetLayerStatus001
 * Type: Function
 * Rank: Important(3)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetLayerStatus()
 *                  2. call GetLayerStatus()
 *                  3. check ret
 */
HWTEST_F(HdiLayerTest, GetLayerStatus001, Function | MediumTest| Level3)
{
    bool isUsing = true;
    HdiLayerTest::hdiLayer_->SetLayerStatus(isUsing);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->GetLayerStatus(), true);

    isUsing = false;
    HdiLayerTest::hdiLayer_->SetLayerStatus(isUsing);
    ASSERT_EQ(HdiLayerTest::hdiLayer_->GetLayerStatus(), false);
    std::string ret = "";
    hdiLayer_->SelectHitchsInfo("", ret);
    hdiLayer_->SelectHitchsInfo("surface", ret);

    sptr<SyncFence> fbAcquireFence = nullptr;
    hdiLayer_->MergeWithFramebufferFence(fbAcquireFence);
    hdiLayer_->MergeWithLayerFence(fbAcquireFence);
    fbAcquireFence = new SyncFence(-1);
    hdiLayer_->MergeWithFramebufferFence(fbAcquireFence);
    hdiLayer_->MergeWithLayerFence(fbAcquireFence);
    hdiLayer_->UpdateCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_CLIENT);
    hdiLayer_->SetLayerPresentTimestamp();
    sptr<SyncFence> releaseFence = new SyncFence(-1);
    hdiLayer_->SetReleaseFence(releaseFence);
    hdiLayer_->SetReleaseFence(nullptr);
    std::string dumpStr = "";
    hdiLayer_->Dump(dumpStr);
    hdiLayer_->DumpByName("surface", dumpStr);
    hdiLayer_->DumpMergedResult(ret);
    EXPECT_CALL(*hdiDeviceMock_, ClearLayerBuffer(_, _)).WillRepeatedly(testing::Return(0));
    hdiLayer_->ClearBufferCache();
}

/**
 * Function: CloseLayer001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call CloseLayer()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, CreateLayer001, Function | MediumTest| Level1)
{
    uint32_t layerId = 1;
    EXPECT_CALL(*hdiDeviceMock_, CreateLayer(_, _, _, layerId)).WillRepeatedly(testing::Return(0));
    ASSERT_EQ(HdiLayerTest::hdiLayer_->Init(HdiLayerTest::rsLayer_), true);
    auto tmpSurface = HdiLayerTest::hdiLayer_->GetRSLayer()->GetSurface();
    HdiLayerTest::rsLayer_->SetSurface(nullptr);
    EXPECT_CALL(*hdiDeviceMock_, CreateLayer(_, _, _, layerId)).WillRepeatedly(testing::Return(0));
    HdiLayerTest::rsLayer_->SetSurface(tmpSurface);
    EXPECT_CALL(*hdiDeviceMock_, CloseLayer(_, _)).WillRepeatedly(testing::Return(1));
}

/**
 * Function: ClearBufferCache001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call ClearBufferCache()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, ClearBufferCache001, Function | MediumTest| Level1)
{
    HdiLayerTest::hdiLayer_->ClearBufferCache();
    EXPECT_EQ(hdiLayer_->bufferCache_.size(), 0);
}

/**
 * Function: SetPerFrameParameters001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetPerFrameParameters()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetPerFrameParameters001, Function | MediumTest| Level1)
{
    int32_t result = HdiLayerTest::hdiLayer_->SetPerFrameParameters();
    EXPECT_EQ(result, GRAPHIC_DISPLAY_SUCCESS);
}
 
/**
 * Function: SetPerFrameParameters002
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetPerFrameParameters()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetPerFrameParameters002, Function | MediumTest| Level1)
{
    paramKey_.clear();
    rsLayer_->SetTunnelLayerId(0);
    rsLayer_->SetTunnelLayerProperty(0);
    int32_t result = HdiLayerTest::hdiLayer_->SetPerFrameParameters();
    EXPECT_EQ(result, GRAPHIC_DISPLAY_SUCCESS);
    EXPECT_CALL(*hdiDeviceMock_, GetSupportedLayerPerFrameParameterKey()).WillRepeatedly(testing::ReturnRef(paramKey_));
}
 
/**
 * Function: SetPerFrameParameters003
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetPerFrameParameters()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetPerFrameParameters003, Function | MediumTest| Level1)
{
    paramKey_.clear();
    rsLayer_->SetTunnelLayerId(1);
    rsLayer_->SetTunnelLayerProperty(0);
    int32_t result = HdiLayerTest::hdiLayer_->SetPerFrameParameters();
    EXPECT_EQ(result, GRAPHIC_DISPLAY_SUCCESS);
    EXPECT_CALL(*hdiDeviceMock_, GetSupportedLayerPerFrameParameterKey()).WillRepeatedly(testing::ReturnRef(paramKey_));
}
 
/**
 * Function: SetPerFrameParameters004
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetPerFrameParameters()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetPerFrameParameters004, Function | MediumTest| Level1)
{
    paramKey_.clear();
    rsLayer_->SetTunnelLayerId(0);
    rsLayer_->SetTunnelLayerProperty(1);
    int32_t result = HdiLayerTest::hdiLayer_->SetPerFrameParameters();
    EXPECT_EQ(result, GRAPHIC_DISPLAY_SUCCESS);
    EXPECT_CALL(*hdiDeviceMock_, GetSupportedLayerPerFrameParameterKey()).WillRepeatedly(testing::ReturnRef(paramKey_));
}
 
/**
 * Function: SetPerFrameParameters005
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetPerFrameParameters()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetPerFrameParameters005, Function | MediumTest| Level1)
{
    paramKey_.clear();
    rsLayer_->SetTunnelLayerId(1);
    rsLayer_->SetTunnelLayerProperty(1);
    int32_t result = HdiLayerTest::hdiLayer_->SetPerFrameParameters();
    EXPECT_EQ(result, GRAPHIC_DISPLAY_SUCCESS);
    EXPECT_CALL(*hdiDeviceMock_, GetSupportedLayerPerFrameParameterKey()).WillRepeatedly(testing::ReturnRef(paramKey_));
}

/**
 * Function: SetLayerBuffer001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetLayerBuffer()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerBuffer, Function | MediumTest| Level1)
{
    auto hdiLayer = HdiLayer::CreateHdiLayer(0);
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    auto rsLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer->prevRSLayer_ = prevRSLayer;
    hdiLayer->rsLayer_ = rsLayer;
    auto res = hdiLayer->SetLayerBuffer();
    EXPECT_EQ(res, GRAPHIC_DISPLAY_SUCCESS);

    BufferRequestConfig requestConfig = {
        .width = 0x100,
        .height = 0x100,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DCI_P3,
    };
    sptr<SurfaceBuffer> newBuffer = new SurfaceBufferImpl();
    newBuffer->Alloc(requestConfig);
    sptr<SyncFence> newFence = new SyncFence(-1);
    prevRSLayer->SetBuffer(newBuffer, newFence);
    rsLayer->SetBuffer(newBuffer, newFence);
    hdiLayer->SetHdiDeviceMock(hdiDeviceMock_);
    hdiLayer->doLayerInfoCompare_ = true;
    hdiLayer->bufferCleared_ = true;
    hdiLayer->SetLayerBuffer();
    EXPECT_FALSE(hdiLayer->bufferCleared_);

    hdiLayer->bufferCleared_ = false;
    res = hdiLayer->SetLayerBuffer();

    sptr<SurfaceBuffer> oldBuffer = new SurfaceBufferImpl();
    oldBuffer->Alloc(requestConfig);
    sptr<SyncFence> oldFence = new SyncFence(-1);
    prevRSLayer->SetBuffer(oldBuffer, oldFence);
    res = hdiLayer->SetLayerBuffer();
    EXPECT_EQ(res, GRAPHIC_DISPLAY_SUCCESS);

    auto mockBuffer = new MockSurfaceBuffer();
    EXPECT_CALL(*mockBuffer, GetBufferHandle()).WillRepeatedly(testing::Return(nullptr));
    rsLayer->SetBuffer(mockBuffer, newFence);
    res = hdiLayer->SetLayerBuffer();
    EXPECT_EQ(res, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SelectHitchsInfoTest
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SelectHitchsInfoTest()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SelectHitchsInfoTest, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    std::string ret = "";
    std::vector<std::string> windowsNameTest = {"testName1", "testName2", "testName3"};
    FPSInfo test1 = {1, windowsNameTest};
    FPSInfo test2 = {1, windowsNameTest};
    hdiLayer_->presentTimeRecords_[0] = test1;
    hdiLayer_->presentTimeRecords_[1] = test2;
    hdiLayer_->SelectHitchsInfo("testName1", ret);
    ret = "";
    hdiLayer_->SelectHitchsInfo("testName2", ret);
    EXPECT_NE(ret, "");
    hdiLayer_->presentTimeRecords_[1].presentTime = 70 * 1000000;
    hdiLayer_->SelectHitchsInfo("testName1", ret);
    EXPECT_NE(ret, "");
    hdiLayer_->presentTimeRecords_[1].presentTime = 35 * 1000000;
    hdiLayer_->SelectHitchsInfo("testName1", ret);
    EXPECT_NE(ret, "");
    hdiLayer_->presentTimeRecords_[1].presentTime = 20 * 1000000;
    hdiLayer_->SelectHitchsInfo("testName1", ret);
    EXPECT_NE(ret, "");
}

/**
 * Function: SetPerFrameLayerLinearMatrixTest
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetPerFrameLayerLinearMatrix()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetPerFrameLayerLinearMatrixTest, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    std::vector<float> preLayerLinearMatrix
        = { 1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f };
    prevRSLayer->SetLayerLinearMatrix(preLayerLinearMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;
    auto curRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->rsLayer_ = curRSLayer;
    auto ret = hdiLayer_->InitDevice();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
    EXPECT_CALL(*hdiDeviceMock_, SetLayerPerFrameParameterSmq(_, _, _, _)).WillRepeatedly(testing::Return(0));
    ret = hdiLayer_->SetPerFrameLayerLinearMatrix();
    ASSERT_EQ(ret, 0);
    std::vector<float> curLayerLinearMatrix
        = {1.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f};
    curRSLayer->SetLayerLinearMatrix(curLayerLinearMatrix);
    hdiLayer_->prevRSLayer_ = nullptr;
    ret = hdiLayer_->SetPerFrameLayerLinearMatrix();
    ASSERT_EQ(ret, 0);
}

/**
 * Function: IsSameLayerMetaDataTest
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call IsSameLayerMetaData()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, IsSameLayerMetaDataTest, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    std::vector<GraphicHDRMetaData> prevMetaData = { { GRAPHIC_MATAKEY_RED_PRIMARY_X, 1 } };
    prevRSLayer->SetMetaData(prevMetaData);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    auto curRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    std::vector<GraphicHDRMetaData> metaData = { { GRAPHIC_MATAKEY_RED_PRIMARY_X, 1 } };
    curRSLayer->SetMetaData(metaData);
    hdiLayer_->rsLayer_ = curRSLayer;
    auto ret = hdiLayer_->IsSameLayerMetaData();
    EXPECT_EQ(ret, true);

    prevMetaData[0].value = 2;
    prevRSLayer->SetMetaData(prevMetaData);
    ret = hdiLayer_->IsSameLayerMetaData();
    EXPECT_EQ(ret, false);

    prevMetaData.push_back({ GRAPHIC_MATAKEY_RED_PRIMARY_Y, 1 });
    prevRSLayer->SetMetaData(prevMetaData);
    ret = hdiLayer_->IsSameLayerMetaData();
    EXPECT_EQ(ret, false);
}

/**
 * Function: IsSameLayerMetaDataSetTest
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call IsSameLayerMetaDataSet()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, IsSameLayerMetaDataSetTest, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    GraphicHDRMetaDataSet prevMetaData = { GRAPHIC_MATAKEY_RED_PRIMARY_X, { 1 } };
    prevRSLayer->SetMetaDataSet(prevMetaData);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    auto curRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    GraphicHDRMetaDataSet metaData = { GRAPHIC_MATAKEY_RED_PRIMARY_X, { 1 } };
    curRSLayer->SetMetaDataSet(metaData);
    hdiLayer_->rsLayer_ = curRSLayer;
    auto ret = hdiLayer_->IsSameLayerMetaDataSet();
    EXPECT_EQ(ret, true);

    prevMetaData.metaData[0] = 2;
    prevRSLayer->SetMetaDataSet(prevMetaData);
    ret = hdiLayer_->IsSameLayerMetaDataSet();
    EXPECT_EQ(ret, false);

    prevMetaData.metaData.push_back(3);
    prevRSLayer->SetMetaDataSet(prevMetaData);
    ret = hdiLayer_->IsSameLayerMetaDataSet();
    EXPECT_EQ(ret, false);

    prevMetaData.key = GRAPHIC_MATAKEY_RED_PRIMARY_Y;
    prevRSLayer->SetMetaDataSet(prevMetaData);
    ret = hdiLayer_->IsSameLayerMetaDataSet();
    EXPECT_EQ(ret, false);
}

/**
 * Function: SetLayerAlpha001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetLayerAlpha()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerAlpha001, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->doLayerInfoCompare_ = true;
    hdiLayer_->rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    GraphicLayerAlpha layerAlpha1 = {false, false, 0, 0, 0};
    hdiLayer_->rsLayer_->SetAlpha(layerAlpha1);
    hdiLayer_->prevRSLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    GraphicLayerAlpha layerAlpha2 = {true, true, 0, 0, 0};
    hdiLayer_->prevRSLayer_->SetAlpha(layerAlpha2);
    ASSERT_EQ(hdiLayer_->SetLayerAlpha(), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerVisibleRegion001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetLayerVisibleRegion()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerVisibleRegion001, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->doLayerInfoCompare_ = true;
    GraphicIRect srcRect = {0, 0, WIDTH_VAL, HEIGHT_VAL};
    std::vector<GraphicIRect> visibleRegions1 = {};
    visibleRegions1.push_back(srcRect);
    std::vector<GraphicIRect> visibleRegions2 = {};
    visibleRegions2.push_back(srcRect);
    visibleRegions2.push_back(srcRect);

    hdiLayer_->rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->rsLayer_->SetVisibleRegions(visibleRegions1);
    hdiLayer_->prevRSLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->rsLayer_->SetVisibleRegions(visibleRegions2);
    ASSERT_EQ(hdiLayer_->SetLayerVisibleRegion(), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerDirtyRegion001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetLayerDirtyRegion()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerDirtyRegion001, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->doLayerInfoCompare_ = true;
    GraphicIRect srcRect = {0, 0, WIDTH_VAL, HEIGHT_VAL};
    std::vector<GraphicIRect> visibleRegions1 = {};
    visibleRegions1.push_back(srcRect);
    std::vector<GraphicIRect> visibleRegions2 = {};
    visibleRegions2.push_back(srcRect);
    visibleRegions2.push_back(srcRect);

    hdiLayer_->rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->rsLayer_->SetDirtyRegions(visibleRegions1);
    hdiLayer_->prevRSLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->rsLayer_->SetDirtyRegions(visibleRegions2);
    ASSERT_EQ(hdiLayer_->SetLayerDirtyRegion(), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: CheckAndUpdateLayerBufferCache001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call CheckAndUpdateLayerBufferCache()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, CheckAndUpdateLayerBufferCache001, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->bufferCache_.clear();
    hdiLayer_->bufferCache_.push_back(1);
    hdiLayer_->bufferCache_.push_back(2);
    hdiLayer_->bufferCacheCountMax_ = 1;
    uint32_t sequence = 0;
    uint32_t index = 0;
    std::vector<uint32_t> deletingList = {};
    EXPECT_CALL(*hdiDeviceMock_, ClearLayerBuffer(_, _)).WillRepeatedly(testing::Return(0));
    ASSERT_EQ(hdiLayer_->CheckAndUpdateLayerBufferCache(sequence, index, deletingList), false);
}

/**
 * Function: CheckAndUpdateLayerBufferCache002
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call CheckAndUpdateLayerBufferCache()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, CheckAndUpdateLayerBufferCache002, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->bufferCache_.clear();
    hdiLayer_->bufferCache_.push_back(1);
    hdiLayer_->bufferCache_.push_back(2);
    hdiLayer_->bufferCacheCountMax_ = 1;
    hdiLayer_->rsLayer_ = HdiLayerTest::rsLayer_;
    uint32_t sequence = 0;
    uint32_t index = 0;
    std::vector<uint32_t> deletingList = {};
    EXPECT_CALL(*hdiDeviceMock_, ClearLayerBuffer(_, _)).WillRepeatedly(testing::Return(0));
    ASSERT_EQ(hdiLayer_->CheckAndUpdateLayerBufferCache(sequence, index, deletingList), false);
}

/**
 * Function: SetLayerPresentTimestamp001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetLayerPresentTimestamp()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetLayerPresentTimestamp001, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->InitDevice();
    ASSERT_NE(hdiLayer_->device_, nullptr);
    hdiLayer_->supportedPresentTimestamptype_ = GRAPHIC_DISPLAY_PTS_TIMESTAMP;
    auto ret = hdiLayer_->SetLayerPresentTimestamp();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: RecordMergedPresentTime001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetLayerPresentTimestamp()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, RecordMergedPresentTime001, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->bufferCache_.clear();
    hdiLayer_->InitDevice();
    ASSERT_NE(hdiLayer_->device_, nullptr);
    hdiLayer_->RecordMergedPresentTime(0);
}

/**
 * Function: ClearBufferCache002
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call ClearBufferCache()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, ClearBufferCache002, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->bufferCache_.clear();
    hdiLayer_->bufferCache_.push_back(1);
    hdiLayer_->rsLayer_ = nullptr;
    hdiLayer_->ClearBufferCache();
}

/**
 * Function: SetTunnelLayerParametersTest
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call SetTunnelLayerParameters()
 *                  2. check ret
 */
HWTEST_F(HdiLayerTest, SetTunnelLayerParametersTest, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    auto rsLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    rsLayer->SetTunnelLayerId(1);
    rsLayer->SetTunnelLayerProperty(1);
    hdiLayer_->rsLayer_ = rsLayer;
    EXPECT_CALL(*hdiDeviceMock_, SetTunnelLayerId(_, _, _)).WillRepeatedly(testing::Return(-1));
    auto ret = hdiLayer_->SetTunnelLayerParameters();
    EXPECT_EQ(ret, -1);
    EXPECT_CALL(*hdiDeviceMock_, SetTunnelLayerId(_, _, _)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*hdiDeviceMock_, SetTunnelLayerProperty(_, _, _)).WillRepeatedly(testing::Return(-1));
    ret = hdiLayer_->SetTunnelLayerParameters();
    EXPECT_EQ(ret, -1);
}

/**
 * Function: ResetBufferCache001
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call ResetBufferCache() with rsLayer_ is nullptr
 *                  2. check bufferCache_ is cleared and bufferCleared_ is true
 */
HWTEST_F(HdiLayerTest, ResetBufferCache001, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->bufferCache_.clear();
    hdiLayer_->bufferCache_.push_back(1);
    hdiLayer_->bufferCleared_ = false;
    hdiLayer_->rsLayer_ = nullptr;

    hdiLayer_->ResetBufferCache();

    EXPECT_EQ(hdiLayer_->bufferCache_.size(), 0);
    EXPECT_TRUE(hdiLayer_->bufferCleared_);
}

/**
 * Function: ResetBufferCache002
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call ResetBufferCache() with rsLayer_ is not nullptr but buffer is nullptr
 *                  2. check bufferCache_ is cleared and bufferCleared_ is true
 */
HWTEST_F(HdiLayerTest, ResetBufferCache002, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->bufferCache_.clear();
    hdiLayer_->bufferCache_.push_back(1);
    hdiLayer_->bufferCleared_ = false;
    hdiLayer_->rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->rsLayer_->SetBuffer(nullptr);

    hdiLayer_->ResetBufferCache();

    EXPECT_EQ(hdiLayer_->bufferCache_.size(), 0);
    EXPECT_TRUE(hdiLayer_->bufferCleared_);
}

/**
 * Function: ResetBufferCache003
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. call ResetBufferCache() with rsLayer_ is not nullptr and buffer is not nullptr
 *                  2. check bufferCache_ is cleared, bufferCleared_ is true, and currBuffer_ is set
 */
HWTEST_F(HdiLayerTest, ResetBufferCache003, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->bufferCache_.clear();
    hdiLayer_->bufferCache_.push_back(1);
    hdiLayer_->bufferCleared_ = false;
    hdiLayer_->currBuffer_ = nullptr;
    hdiLayer_->rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    sptr<SurfaceBuffer> buffer = new SurfaceBufferImpl();
    hdiLayer_->rsLayer_->SetBuffer(buffer);

    hdiLayer_->ResetBufferCache();

    EXPECT_EQ(hdiLayer_->bufferCache_.size(), 0);
    EXPECT_TRUE(hdiLayer_->bufferCleared_);
    EXPECT_EQ(hdiLayer_->currBuffer_, buffer);
}

/**
 * Function: SetTransformMode_NoChangeOrButt
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. Skip setting when transform is GRAPHIC_ROTATE_BUTT or equals prev
 *                  2. check return value
 */
HWTEST_F(HdiLayerTest, SetTransformMode_NoChangeOrButt, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->prevRSLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);

    hdiLayer_->rsLayer_->SetTransform(GraphicTransformType::GRAPHIC_ROTATE_BUTT);
    ASSERT_EQ(hdiLayer_->SetTransformMode(), GRAPHIC_DISPLAY_SUCCESS);

    hdiLayer_->rsLayer_->SetTransform(GraphicTransformType::GRAPHIC_ROTATE_90);
    hdiLayer_->prevRSLayer_->SetTransform(GraphicTransformType::GRAPHIC_ROTATE_90);
    hdiLayer_->doLayerInfoCompare_ = true;
    ASSERT_EQ(hdiLayer_->SetTransformMode(), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerZorder_And_PreMulti_NoChange
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. Skip setting when Zorder/PreMulti equals prev
 *                  2. check return value
 */
HWTEST_F(HdiLayerTest, SetLayerZorder_And_PreMulti_NoChange, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->prevRSLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->doLayerInfoCompare_ = true;

    hdiLayer_->rsLayer_->SetZorder(5);
    hdiLayer_->prevRSLayer_->SetZorder(5);
    ASSERT_EQ(hdiLayer_->SetLayerZorder(), GRAPHIC_DISPLAY_SUCCESS);

    hdiLayer_->rsLayer_->SetPreMulti(true);
    hdiLayer_->prevRSLayer_->SetPreMulti(true);
    ASSERT_EQ(hdiLayer_->SetLayerPreMulti(), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorDataSpace_Set
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. Set color data space, expect success
 *                  2. check return value
 */
HWTEST_F(HdiLayerTest, SetLayerColorDataSpace_Set, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->rsLayer_ = std::make_shared<RSSurfaceLayer>(0, nullptr);
    hdiLayer_->rsLayer_->SetColorDataSpace(GraphicColorDataSpace::GRAPHIC_GAMUT_DISPLAY_P3);
    ASSERT_EQ(hdiLayer_->SetLayerColorDataSpace(), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaData_Different
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. When metaData differs from prev, take setting path
 *                  2. check return value
 */
HWTEST_F(HdiLayerTest, SetLayerMetaData_Different, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    std::vector<GraphicHDRMetaData> prevMetaData = { { GRAPHIC_MATAKEY_RED_PRIMARY_X, 1 } };
    prevRSLayer->SetMetaData(prevMetaData);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    auto curRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    std::vector<GraphicHDRMetaData> metaData = { { GRAPHIC_MATAKEY_RED_PRIMARY_X, 2 } };
    curRSLayer->SetMetaData(metaData);
    hdiLayer_->rsLayer_ = curRSLayer;
    ASSERT_EQ(hdiLayer_->SetLayerMetaData(), GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: CheckAndUpdateLayerBufferCache_Found
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. Return true when sequence is found
 *                  2. check index/deletingList
 */
HWTEST_F(HdiLayerTest, CheckAndUpdateLayerBufferCache_Found, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->bufferCache_.clear();
    hdiLayer_->bufferCache_.push_back(10);
    hdiLayer_->bufferCache_.push_back(20);
    hdiLayer_->bufferCacheCountMax_ = 5;
    uint32_t index = 0;
    std::vector<uint32_t> deletingList;
    bool found = hdiLayer_->CheckAndUpdateLayerBufferCache(10, index, deletingList);
    ASSERT_TRUE(found);
    ASSERT_EQ(index, 0u);
    ASSERT_TRUE(deletingList.empty());
}


/**
 * Function: SetLayerPresentTimestamp_Unsupported
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. Return success when timestamp type is unsupported
 *                  2. check return value
 */
HWTEST_F(HdiLayerTest, SetLayerPresentTimestamp_Unsupported, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    hdiLayer_->supportedPresentTimestamptype_ = GRAPHIC_DISPLAY_PTS_UNSUPPORTED;
    auto ret = hdiLayer_->SetLayerPresentTimestamp();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetPerFrameParameters_LinearMatrixParamErr_Last
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. Only linear matrix key; invalid matrix size leads to final error code
 *                  2. check return value
 */
HWTEST_F(HdiLayerTest, SetPerFrameParameters_LinearMatrixParamErr_Last, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    paramKey_.clear();
    paramKey_.push_back("LayerLinearMatrix");
    auto curRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    // Invalid size, triggers GRAPHIC_DISPLAY_PARAM_ERR
    curRSLayer->SetLayerLinearMatrix({1.0f, 2.0f});
    hdiLayer_->rsLayer_ = curRSLayer;
    auto ret = hdiLayer_->SetPerFrameParameters();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_PARAM_ERR);
}

/**
 * Function: SetPerFrameParameters_AllKeys_Success
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. Set all keys in order; final return is success
 *                  2. check return value
 */
HWTEST_F(HdiLayerTest, SetPerFrameParameters_AllKeys_Success, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);
    paramKey_.clear();
    paramKey_.push_back("SDRBrightnessNit");
    paramKey_.push_back("BrightnessNit");
    paramKey_.push_back("SDRBrightnessRatio");
    paramKey_.push_back("LayerLinearMatrix");
    paramKey_.push_back("SourceCropTuning");

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetLayerLinearMatrix({ 1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f });
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    auto curRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    curRSLayer->SetSdrNit(10.0f);
    curRSLayer->SetDisplayNit(200.0f);
    curRSLayer->SetBrightnessRatio(1.0f);
    curRSLayer->SetLayerLinearMatrix({ 1.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f });
    curRSLayer->SetLayerSourceTuning(7);
    hdiLayer_->rsLayer_ = curRSLayer;

    EXPECT_CALL(*hdiDeviceMock_, SetLayerPerFrameParameterSmq(_, _, _, _)).WillRepeatedly(testing::Return(0));
    auto ret = hdiLayer_->SetPerFrameParameters();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColor_ColorsMatch_Line379_TrueBranch
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true and colors match
 *                  2. call SetLayerColor
 *                  3. verify early return (line 379 true branch)
 */
HWTEST_F(HdiLayerTest, SetLayerColor_ColorsMatch_Line379_TrueBranch, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    // Create prevRSLayer with GRAPHIC_COMPOSITION_DEVICE type
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    GraphicLayerColor color = { 200, 100, 50, 255 };
    prevRSLayer->SetLayerColor(color);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set same color on current rsLayer
    hdiLayer_->rsLayer_->SetLayerColor(color);

    // Expect SetLayerColor NOT to be called (line 379 true branch - colors match)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).Times(0);
    auto ret = hdiLayer_->SetLayerColor();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColor_ColorsDiffer_Line379_FalseBranch
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true but colors differ
 *                  2. call SetLayerColor
 *                  3. verify SetLayerColor is called (line 379 false branch)
 */
HWTEST_F(HdiLayerTest, SetLayerColor_ColorsDiffer_Line379_FalseBranch, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    // Create prevRSLayer with GRAPHIC_COMPOSITION_DEVICE type
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    GraphicLayerColor prevColor = { 100, 50, 25, 128 };
    prevRSLayer->SetLayerColor(prevColor);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set different color on current rsLayer
    GraphicLayerColor curColor = { 200, 150, 75, 255 };
    hdiLayer_->rsLayer_->SetLayerColor(curColor);

    // Expect SetLayerColor to be called (line 379 false branch - colors differ)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColor();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColor_RComponentDiffer_Line379_FalseBranch
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. red component differs between current and previous
 *                  2. call SetLayerColor
 *                  3. verify SetLayerColor is called
 */
HWTEST_F(HdiLayerTest, SetLayerColor_RComponentDiffer_Line379_FalseBranch, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    GraphicLayerColor prevColor = { 100, 50, 25, 128 };
    prevRSLayer->SetLayerColor(prevColor);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Change only R component
    GraphicLayerColor curColor = { 200, 50, 25, 128 };
    hdiLayer_->rsLayer_->SetLayerColor(curColor);

    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColor();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColor_GComponentDiffer_Line379_FalseBranch
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. green component differs between current and previous
 *                  2. call SetLayerColor
 *                  3. verify SetLayerColor is called
 */
HWTEST_F(HdiLayerTest, SetLayerColor_GComponentDiffer_Line379_FalseBranch, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    GraphicLayerColor prevColor = { 100, 50, 25, 128 };
    prevRSLayer->SetLayerColor(prevColor);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Change only G component
    GraphicLayerColor curColor = { 100, 200, 25, 128 };
    hdiLayer_->rsLayer_->SetLayerColor(curColor);

    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColor();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColor_BComponentDiffer_Line379_FalseBranch
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. blue component differs between current and previous
 *                  2. call SetLayerColor
 *                  3. verify SetLayerColor is called
 */
HWTEST_F(HdiLayerTest, SetLayerColor_BComponentDiffer_Line379_FalseBranch, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    GraphicLayerColor prevColor = { 100, 50, 25, 128 };
    prevRSLayer->SetLayerColor(prevColor);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Change only B component
    GraphicLayerColor curColor = { 100, 50, 200, 128 };
    hdiLayer_->rsLayer_->SetLayerColor(curColor);

    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColor();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColor_AComponentDiffer_Line379_FalseBranch
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. alpha component differs between current and previous
 *                  2. call SetLayerColor
 *                  3. verify SetLayerColor is called
 */
HWTEST_F(HdiLayerTest, SetLayerColor_AComponentDiffer_Line379_FalseBranch, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    GraphicLayerColor prevColor = { 100, 50, 25, 128 };
    prevRSLayer->SetLayerColor(prevColor);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Change only A component
    GraphicLayerColor curColor = { 100, 50, 25, 255 };
    hdiLayer_->rsLayer_->SetLayerColor(curColor);

    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColor();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColor_PrevCompositionTypeNotDevice_Line379_FalseBranch
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. prevRSLayer composition type is not GRAPHIC_COMPOSITION_DEVICE
 *                  2. call SetLayerColor
 *                  3. verify SetLayerColor is called (doLayerInfoCompare_ will be false)
 */
HWTEST_F(HdiLayerTest, SetLayerColor_PrevCompositionTypeNotDevice_Line379_FalseBranch, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    // Set prevRSLayer with CLIENT composition type (not DEVICE)
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_CLIENT);
    GraphicLayerColor color = { 100, 50, 25, 128 };
    prevRSLayer->SetLayerColor(color);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set same color on current rsLayer
    hdiLayer_->rsLayer_->SetLayerColor(color);

    // Expect SetLayerColor to be called (doLayerInfoCompare_ will be false due to composition type)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColor();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColor_MultipleDifferingComponents_Line379_FalseBranch
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. multiple color components differ
 *                  2. call SetLayerColor
 *                  3. verify SetLayerColor is called
 */
HWTEST_F(HdiLayerTest, SetLayerColor_MultipleDifferingComponents_Line379_FalseBranch, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    GraphicLayerColor prevColor = { 100, 100, 100, 100 };
    prevRSLayer->SetLayerColor(prevColor);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Change all components
    GraphicLayerColor curColor = { 200, 150, 175, 255 };
    hdiLayer_->rsLayer_->SetLayerColor(curColor);

    EXPECT_CALL(*hdiDeviceMock_, SetLayerColor(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColor();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_MatricesMatch_Line397_False
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, matrices are identical
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform NOT called (line 397 false)
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_MatricesMatch_Line397_False, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    // Set up prevRSLayer with DEVICE composition type to make doLayerInfoCompare_ true
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> matrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    prevRSLayer->SetColorTransform(matrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set same matrix on current rsLayer
    hdiLayer_->rsLayer_->SetColorTransform(matrix);

    // Line 395: doLayerInfoCompare_ is true
    // Line 397: IsNeedSetInfoToDevice returns false (matrices match)
    // Expect SetLayerColorTransform NOT to be called
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).Times(0);
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_MatricesDiffer_Line397_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, matrices differ
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform IS called (line 397 true)
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_MatricesDiffer_Line397_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    // Set up prevRSLayer with DEVICE composition type
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> prevMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    prevRSLayer->SetColorTransform(prevMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set different matrix on current rsLayer
    std::vector<float> curMatrix = {1.0f, 0.1f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    hdiLayer_->rsLayer_->SetColorTransform(curMatrix);

    // Line 395: doLayerInfoCompare_ is true
    // Line 397: IsNeedSetInfoToDevice returns true (matrices differ)
    // Expect SetLayerColorTransform to be called
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_SizeDiffers_Line397_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, matrix sizes differ
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform IS called
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_SizeDiffers_Line397_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    // Set up prevRSLayer with DEVICE composition type
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> prevMatrix = {1.0f, 0.0f, 0.0f};
    prevRSLayer->SetColorTransform(prevMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set different size matrix on current rsLayer
    std::vector<float> curMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f};
    hdiLayer_->rsLayer_->SetColorTransform(curMatrix);

    // Line 395: doLayerInfoCompare_ is true
    // Line 397: IsNeedSetInfoToDevice returns true (sizes differ)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_AllZero_Line397_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, prev matrix has zeros, current has values
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform IS called
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_AllZero_Line397_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> prevMatrix = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    prevRSLayer->SetColorTransform(prevMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    std::vector<float> curMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    hdiLayer_->rsLayer_->SetColorTransform(curMatrix);

    // Line 395: true, Line 397: true (matrices differ)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_EmptyMatrix_Line397_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, empty vs non-empty matrices
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform IS called
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_EmptyMatrix_Line397_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> prevMatrix = {}; // Empty
    prevRSLayer->SetColorTransform(prevMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    std::vector<float> curMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    hdiLayer_->rsLayer_->SetColorTransform(curMatrix);

    // Line 395: true, Line 397: true (sizes differ: 0 vs 9)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_IdentityMatrices_Line397_False
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, both are identity matrices
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform NOT called
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_IdentityMatrices_Line397_False, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    // Identity matrix
    std::vector<float> identityMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    prevRSLayer->SetColorTransform(identityMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    hdiLayer_->rsLayer_->SetColorTransform(identityMatrix);

    // Line 395: true, Line 397: false (matrices are identical)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).Times(0);
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_LargeMatrix_Line397_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, large matrices differ
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform IS called
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_LargeMatrix_Line397_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> prevMatrix(16, 0.5f); // 4x4 matrix
    prevRSLayer->SetColorTransform(prevMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    std::vector<float> curMatrix(16, 0.6f); // Different values
    hdiLayer_->rsLayer_->SetColorTransform(curMatrix);

    // Line 395: true, Line 397: true (matrices differ)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_SingleDiff_Line397_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, single element differs
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform IS called
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_SingleDiff_Line397_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> prevMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    prevRSLayer->SetColorTransform(prevMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Change only one element
    std::vector<float> curMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.1f, 1.0f};
    hdiLayer_->rsLayer_->SetColorTransform(curMatrix);

    // Line 395: true, Line 397: true (one element differs)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_NegativeValues_Line397_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, matrices with negative values differ
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform IS called
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_NegativeValues_Line397_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> prevMatrix = {-0.5f, 0.0f, 0.0f, 0.0f, -0.5f, 0.0f, 0.0f, 0.0f, 1.0f};
    prevRSLayer->SetColorTransform(prevMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    std::vector<float> curMatrix = {-0.6f, 0.0f, 0.0f, 0.0f, -0.6f, 0.0f, 0.0f, 0.0f, 1.0f};
    hdiLayer_->rsLayer_->SetColorTransform(curMatrix);

    // Line 395: true, Line 397: true (matrices differ)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerColorTransform_DoLayerInfoCompareTrue_LastElementDiff_Line397_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, last matrix element differs
 *                  2. call SetLayerColorTransform
 *                  3. verify SetLayerColorTransform IS called
 */
HWTEST_F(HdiLayerTest, SetLayerColorTransform_DoLayerInfoCompareTrue_LastElementDiff_Line397_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<float> prevMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    prevRSLayer->SetColorTransform(prevMatrix);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Change last element
    std::vector<float> curMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.9f};
    hdiLayer_->rsLayer_->SetColorTransform(curMatrix);

    // Line 395: true, Line 397: true (last element differs)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerColorTransform(_, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerColorTransform();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_MetaDataSetSame_Line476_False
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, meta data sets are identical
 *                  2. call SetLayerMetaDataSet
 *                  3. verify early return (line 476 false, no call to SetLayerMetaDataSet)
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_MetaDataSetSame_Line476_False, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    // Set up prevRSLayer with DEVICE composition type
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    // Set meta data set
    std::vector<uint8_t> metaData = {1, 2, 3, 4};
    GraphicHDRMetaDataSet metaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, metaData};
    prevRSLayer->SetMetaDataSet(metaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set same meta data set on current rsLayer
    hdiLayer_->rsLayer_->SetMetaDataSet(metaDataSet);

    // Line 474: doLayerInfoCompare_ is true
    // Line 476: IsSameLayerMetaDataSet returns true (meta data sets are same)
    // Expect SetLayerMetaDataSet NOT to be called
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).Times(0);
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_MetaDataDiffer_Line476_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, meta data differs
 *                  2. call SetLayerMetaDataSet
 *                  3. verify SetLayerMetaDataSet IS called (line 476 true)
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_MetaDataDiffer_Line476_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    // Set up prevRSLayer with DEVICE composition type
    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    std::vector<uint8_t> prevMetaData = {1, 2, 3, 4};
    GraphicHDRMetaDataSet prevMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, prevMetaData};
    prevRSLayer->SetMetaDataSet(prevMetaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set different meta data on current rsLayer
    std::vector<uint8_t> curMetaData = {1, 2, 3, 5}; // Different last element
    GraphicHDRMetaDataSet curMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, curMetaData};
    hdiLayer_->rsLayer_->SetMetaDataSet(curMetaDataSet);

    // Line 474: doLayerInfoCompare_ is true
    // Line 476: IsSameLayerMetaDataSet returns false (meta data differs)
    // Expect SetLayerMetaDataSet to be called
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_KeyDiffers_Line476_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, keys differ
 *                  2. call SetLayerMetaDataSet
 *                  3. verify SetLayerMetaDataSet IS called
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_KeyDiffers_Line476_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    std::vector<uint8_t> metaData = {1, 2, 3, 4};
    GraphicHDRMetaDataSet prevMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, metaData}; // Key = 5
    prevRSLayer->SetMetaDataSet(prevMetaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set different key on current rsLayer
    GraphicHDRMetaDataSet curMetaDataSet = {GRAPHIC_MATAKEY_WHITE_PRIMARY_X, metaData}; // Key = 6
    hdiLayer_->rsLayer_->SetMetaDataSet(curMetaDataSet);

    // Line 474: true, Line 476: true (keys differ)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_MetaDataSizeDiffers_Line476_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, meta data sizes differ
 *                  2. call SetLayerMetaDataSet
 *                  3. verify SetLayerMetaDataSet IS called
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_MetaDataSizeDiffers_Line476_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    std::vector<uint8_t> prevMetaData = {1, 2, 3, 4};
    GraphicHDRMetaDataSet prevMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, prevMetaData};
    prevRSLayer->SetMetaDataSet(prevMetaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Set different size meta data on current rsLayer
    std::vector<uint8_t> curMetaData = {1, 2, 3};
    GraphicHDRMetaDataSet curMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, curMetaData};
    hdiLayer_->rsLayer_->SetMetaDataSet(curMetaDataSet);

    // Line 474: true, Line 476: true (sizes differ)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_EmptyMetaData_Line476_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, empty vs non-empty meta data
 *                  2. call SetLayerMetaDataSet
 *                  3. verify SetLayerMetaDataSet IS called
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_EmptyMetaData_Line476_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    // Empty meta data
    std::vector<uint8_t> emptyMetaData = {};
    GraphicHDRMetaDataSet prevMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, emptyMetaData};
    prevRSLayer->SetMetaDataSet(prevMetaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Non-empty meta data on current
    std::vector<uint8_t> curMetaData = {1, 2};
    GraphicHDRMetaDataSet curMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, curMetaData};
    hdiLayer_->rsLayer_->SetMetaDataSet(curMetaDataSet);

    // Line 474: true, Line 476: true (empty vs non-empty)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_MetaDataEmptyBoth_Line476_False
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, both meta data are empty
 *                  2. call SetLayerMetaDataSet
 *                  3. verify early return (line 476 false)
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_MetaDataEmptyBoth_Line476_False, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    // Empty meta data for both
    std::vector<uint8_t> emptyMetaData = {};
    GraphicHDRMetaDataSet metaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, emptyMetaData};
    prevRSLayer->SetMetaDataSet(metaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    hdiLayer_->rsLayer_->SetMetaDataSet(metaDataSet);

    // Line 474: true, Line 476: false (both empty, same)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).Times(0);
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_LargeMetaData_Line476_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, large meta data with difference
 *                  2. call SetLayerMetaDataSet
 *                  3. verify SetLayerMetaDataSet IS called
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_LargeMetaData_Line476_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    // Large meta data
    std::vector<uint8_t> prevMetaData(100, 128);
    GraphicHDRMetaDataSet prevMetaDataSet = {GRAPHIC_MATAKEY_MAX_CONTENT_LIGHT_LEVEL, prevMetaData};
    prevRSLayer->SetMetaDataSet(prevMetaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Different large meta data
    std::vector<uint8_t> curMetaData(100, 129);
    GraphicHDRMetaDataSet curMetaDataSet = {GRAPHIC_MATAKEY_MAX_CONTENT_LIGHT_LEVEL, curMetaData};
    hdiLayer_->rsLayer_->SetMetaDataSet(curMetaDataSet);

    // Line 474: true, Line 476: true (large meta data differs)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_FirstElementDiffers_Line476_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, first meta data element differs
 *                  2. call SetLayerMetaDataSet
 *                  3. verify SetLayerMetaDataSet IS called
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_FirstElementDiffers_Line476_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    std::vector<uint8_t> prevMetaData = {1, 2, 3, 4};
    GraphicHDRMetaDataSet prevMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, prevMetaData};
    prevRSLayer->SetMetaDataSet(prevMetaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // First element differs
    std::vector<uint8_t> curMetaData = {0, 2, 3, 4};
    GraphicHDRMetaDataSet curMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, curMetaData};
    hdiLayer_->rsLayer_->SetMetaDataSet(curMetaDataSet);

    // Line 474: true, Line 476: true (first element differs)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_LastElementDiffers_Line476_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, last meta data element differs
 *                  2. call SetLayerMetaDataSet
 *                  3. verify SetLayerMetaDataSet IS called
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_LastElementDiffers_Line476_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    std::vector<uint8_t> prevMetaData = {1, 2, 3, 4};
    GraphicHDRMetaDataSet prevMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, prevMetaData};
    prevRSLayer->SetMetaDataSet(prevMetaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Last element differs
    std::vector<uint8_t> curMetaData = {1, 2, 3, 5};
    GraphicHDRMetaDataSet curMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, curMetaData};
    hdiLayer_->rsLayer_->SetMetaDataSet(curMetaDataSet);

    // Line 474: true, Line 476: true (last element differs)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_AllZeroMetaData_Line476_False
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, both meta data are all zeros
 *                  2. call SetLayerMetaDataSet
 *                  3. verify early return (line 476 false)
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_AllZeroMetaData_Line476_False, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    // All zero meta data
    std::vector<uint8_t> zeroMetaData = {0, 0, 0, 0};
    GraphicHDRMetaDataSet metaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, zeroMetaData};
    prevRSLayer->SetMetaDataSet(metaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    hdiLayer_->rsLayer_->SetMetaDataSet(metaDataSet);

    // Line 474: true, Line 476: false (both identical)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).Times(0);
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}

/**
 * Function: SetLayerMetaDataSet_DoLayerInfoCompareTrue_MaxMetaData_Line476_True
 * Type: Function
 * Rank: Important(1)
 * EnvConditions: N/A
 * CaseDescription: 1. doLayerInfoCompare_ is true, max value meta data differs
 *                  2. call SetLayerMetaDataSet
 *                  3. verify SetLayerMetaDataSet IS called
 */
HWTEST_F(HdiLayerTest, SetLayerMetaDataSet_DoLayerInfoCompareTrue_MaxMetaData_Line476_True, Function | MediumTest| Level1)
{
    ASSERT_NE(hdiLayer_, nullptr);

    auto prevRSLayer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    prevRSLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    // Max value meta data
    std::vector<uint8_t> prevMetaData = {255, 255, 255, 255};
    GraphicHDRMetaDataSet prevMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, prevMetaData};
    prevRSLayer->SetMetaDataSet(prevMetaDataSet);
    hdiLayer_->prevRSLayer_ = prevRSLayer;

    // Slightly different
    std::vector<uint8_t> curMetaData = {254, 255, 255, 255};
    GraphicHDRMetaDataSet curMetaDataSet = {GRAPHIC_MATAKEY_BLUE_PRIMARY_Y, curMetaData};
    hdiLayer_->rsLayer_->SetMetaDataSet(curMetaDataSet);

    // Line 474: true, Line 476: true (meta data differs)
    EXPECT_CALL(*hdiDeviceMock_, SetLayerMetaDataSet(_, _, _, _)).WillOnce(testing::Return(0));
    auto ret = hdiLayer_->SetLayerMetaDataSet();
    ASSERT_EQ(ret, GRAPHIC_DISPLAY_SUCCESS);
}
} // namespace
} // namespace Rosen
} // namespace OHOS