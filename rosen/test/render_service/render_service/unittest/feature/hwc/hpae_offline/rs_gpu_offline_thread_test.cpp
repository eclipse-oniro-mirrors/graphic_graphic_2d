/*
 * Copyright (c) 2026 HUA[REPLACED] Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <memory>
#include <chrono>

#include "feature/hwc/hpae_offline/rs_offline_processor.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_device.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_buffer.h"
#include "feature/hwc/hpae_offline/rs_gpu_offline_thread.h"
#include "feature/hwc/hpae_offline/rs_offline_device.h"
#include "feature/hwc/hpae_offline/rs_offline_util.h"
#include "feature/hwc/hpae_offline/rs_offline_result.h"
#include "feature/hwc/rs_uni_hwc_prevalidate_util.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_system_properties.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Rosen;

// ==================== RSGPUOfflineThreadTest Tests ====================
class RSGPUOfflineThreadTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSGPUOfflineThreadTest::SetUpTestCase() {}
void RSGPUOfflineThreadTest::TearDownTestCase() {}
void RSGPUOfflineThreadTest::SetUp() {}
void RSGPUOfflineThreadTest::TearDown() {}


/**
 * @tc.name: GetRenderEngineTest001
 * @tc.desc: Test GetRenderEngine before initialization
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_018
 */
HWTEST_F(RSGPUOfflineThreadTest, GetRenderEngineTest001, TestSize.Level1)
{
    auto thread = std::make_shared<RSGPUOfflineThread>();

    auto engine = thread->GetRenderEngine();
    EXPECT_EQ(engine, nullptr);
}
// ==================== RSGPUOfflineThreadPrivateTest Tests ====================

class RSGPUOfflineThreadPrivateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSGPUOfflineThreadPrivateTest::SetUpTestCase() {}
void RSGPUOfflineThreadPrivateTest::TearDownTestCase() {}
void RSGPUOfflineThreadPrivateTest::SetUp() {}
void RSGPUOfflineThreadPrivateTest::TearDown() {}


/**
 * @tc.name: ThreadStopWithRenderEngineTest001
 * @tc.desc: Test Stop when renderEngine_ is not null (after InitRenderEngine)
 *           - After calling InitRenderEngine, renderEngine_ should be set.
 *           Stop with renderEngine_ not null covers the GPU context cleanup path.
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_019
 */
HWTEST_F(RSGPUOfflineThreadPrivateTest, StopWithRenderEngineTest001, TestSize.Level1)
{
    auto thread = std::make_shared<RSGPUOfflineThread>();

    // InitRenderEngine creates a renderEngine_
    thread->InitRenderEngine();

    auto engine = thread->GetRenderEngine();
    EXPECT_NE(engine, nullptr);

    // Stop with renderEngine_ not null should work
    thread->Stop();
    EXPECT_FALSE(thread->isInitialized_);

    // Clean up GPU resources to prevent crash in ~RSBaseRenderEngine()
    if (thread->renderEngine_) {
        if (thread->renderEngine_->renderContext_) {
            thread->renderEngine_->renderContext_->drGPUContext_ = nullptr;
        }
        thread->renderEngine_->skContext_ = nullptr;
        thread->renderEngine_->renderContext_ = nullptr;
        if (thread->renderEngine_->protectedRenderContext_) {
            thread->renderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        thread->renderEngine_->protectedRenderContext_ = nullptr;
        thread->renderEngine_->imageManager_ = nullptr;
        thread->renderEngine_->gpuCacheManager_ = nullptr;
        thread->renderEngine_ = nullptr;
    }
}

/**
 * @tc.name: ThreadPostTaskHandlerNullTest001
 * @tc.desc: Test PostTask when handler_ is null (after failed Start)
 *           - If Start fails, handler_ stays null, PostTask returns false
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_sup_021
 */
HWTEST_F(RSGPUOfflineThreadPrivateTest, PostTaskHandlerNullTest001, TestSize.Level1)
{
    auto thread = std::make_shared<RSGPUOfflineThread>();

    // Force isInitialized_ to true but handler_ to null
    thread->isInitialized_ = true;
    thread->handler_ = nullptr;

    bool result = thread->PostTask([]() {}, "test_task");
    EXPECT_FALSE(result); // handler_ null returns false

    std::shared_ptr<AppExecFwk::EventRunner> runner = nullptr;
    thread->runner_ = runner;
    thread->handler_ = std::make_shared<AppExecFwk::EventHandler>(thread->runner_);
    result = thread->PostTask([]() {}, "test_task");
    EXPECT_FALSE(result);

    runner = AppExecFwk::EventRunner::Create("RSGPUOfflineThread");
    thread->runner_ = runner;
    thread->handler_ = std::make_shared<AppExecFwk::EventHandler>(thread->runner_);
    result = thread->PostTask([]() {}, "test_task");
    EXPECT_TRUE(result);
}

HWTEST_F(RSGPUOfflineThreadPrivateTest, StartSuccessTest001, TestSize.Level1)
{
    auto thread = std::make_shared<RSGPUOfflineThread>();
    EXPECT_TRUE(thread->Start());
}

HWTEST_F(RSGPUOfflineThreadPrivateTest, StopTest001, TestSize.Level1)
{
    auto thread = std::make_shared<RSGPUOfflineThread>();
    thread->isInitialized_ = true;
    thread->renderEngine_ = nullptr;
    thread->Stop();

    thread->InitRenderEngine();
    thread->renderEngine_->renderContext_ = nullptr;
    thread->Stop();

    thread->renderEngine_->renderContext_ = RenderContext::Create();
    if (thread->renderEngine_->renderContext_) {
        thread->renderEngine_->renderContext_->drGPUContext_ = nullptr;
        thread->renderEngine_->renderContext_ = nullptr;
    }
    if (thread->renderEngine_->protectedRenderContext_) {
        thread->renderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
    }
    thread->renderEngine_->protectedRenderContext_ = nullptr;
    thread->Stop();

    thread->renderEngine_->renderContext_ = RenderContext::Create();
    thread->renderEngine_->renderContext_->drGPUContext_ = std::make_shared<Drawing::GPUContext>();
    thread->Stop();

    // Clean up GPU resources to prevent crash in ~RSBaseRenderEngine()
    if (thread->renderEngine_) {
        if (thread->renderEngine_->renderContext_) {
            thread->renderEngine_->renderContext_->drGPUContext_ = nullptr;
            thread->renderEngine_->renderContext_ = nullptr;
        }
        if (thread->renderEngine_->protectedRenderContext_) {
            thread->renderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        thread->renderEngine_->protectedRenderContext_ = nullptr;
        thread->renderEngine_ = nullptr;
    }
}
// ==================== GPUOfflineDrawParamsTest Tests ====================

class GPUOfflineDrawParamsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void GPUOfflineDrawParamsTest::SetUpTestCase() {}
void GPUOfflineDrawParamsTest::TearDownTestCase() {}
void GPUOfflineDrawParamsTest::SetUp() {}
void GPUOfflineDrawParamsTest::TearDown() {}


/**
 * @tc.name: EqualityOperatorTest001
 * @tc.desc: Test GPUOfflineDrawParams equality operator with same params
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_020
 */
HWTEST_F(GPUOfflineDrawParamsTest, EqualityOperatorTest001, TestSize.Level1)
{
    GPUOfflineDrawParams params1;
    GPUOfflineDrawParams params2;

    params1.sdrNit = 100.0f;
    params2.sdrNit = 100.0f;

    params1.displayNit = 200.0f;
    params2.displayNit = 200.0f;

    params1.resultWidth = 1920;
    params2.resultWidth = 1920;

    params1.resultHeight = 1080;
    params2.resultHeight = 1080;

    EXPECT_TRUE(params1 == params2);
}

/**
 * @tc.name: GPUOfflineDrawParamsLayerLinearMatrixDefaultTest001
 * @tc.desc: Test GPUOfflineDrawParams layerLinearMatrix default is identity matrix
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_014
 */
HWTEST_F(GPUOfflineDrawParamsTest, LayerLinearMatrixDefaultTest001, TestSize.Level1)
{
    GPUOfflineDrawParams params;

    // Identity matrix: {1,0,0, 0,1,0, 0,0,1}
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[0], 1.0f);
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[1], 0.0f);
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[2], 0.0f);
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[3], 0.0f);
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[4], 1.0f);
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[5], 0.0f);
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[6], 0.0f);
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[7], 0.0f);
    EXPECT_FLOAT_EQ(params.layerLinearMatrix[8], 1.0f);
}

/**
 * @tc.name: EqualityDifferentBrightnessRatioTest001
 * @tc.desc: Test GPUOfflineDrawParams equality with different brightnessRatio values
 *           - brightnessRatio differs by more than epsilon (1e-5)
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_071
 */
HWTEST_F(GPUOfflineDrawParamsTest, EqualityDifferentBrightnessRatioTest001, TestSize.Level1)
{
    GPUOfflineDrawParams params1;
    GPUOfflineDrawParams params2;

    params1.brightnessRatio = 1.0f;
    params2.brightnessRatio = 1.000001f; // Within epsilon

    // Within epsilon tolerance - should be considered equal
    EXPECT_TRUE(params1 == params2);

    params2.brightnessRatio = 1.1f; // Beyond epsilon
    EXPECT_FALSE(params1 == params2);
}

/**
 * @tc.name: EqualityOperatorDifferentFieldsTest001
 * @tc.desc: Test GPUOfflineDrawParams operator== detects single-field differences
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_consolidated
 */
HWTEST_F(GPUOfflineDrawParamsTest, EqualityOperatorDifferentFieldsTest001, TestSize.Level1)
{
    GPUOfflineDrawParams params1;
    GPUOfflineDrawParams params2;

    // Identical params should be equal
    EXPECT_TRUE(params1 == params2);

    // Differ in sdrNit
    params2.sdrNit = 100.0f;
    EXPECT_FALSE(params1 == params2);
    params2.sdrNit = 0.0f;

    // Differ in displayNit
    params2.displayNit = 200.0f;
    EXPECT_FALSE(params1 == params2);
    params2.displayNit = 0.0f;

    // Differ in brightnessRatio
    params2.brightnessRatio = 2.0f;
    EXPECT_FALSE(params1 == params2);
    params2.brightnessRatio = 1.0f;

    // Differ in useBilinearInterpolation
    params2.useBilinearInterpolation = true;
    EXPECT_FALSE(params1 == params2);
    params2.useBilinearInterpolation = false;

    // Differ in ignoreAlpha
    params2.ignoreAlpha = true;
    EXPECT_FALSE(params1 == params2);
    params2.ignoreAlpha = false;

    // Differ in colorFollow
    params2.colorFollow = true;
    EXPECT_FALSE(params1 == params2);
    params2.colorFollow = false;

    // Differ in screenId
    params2.screenId = 1;
    EXPECT_FALSE(params1 == params2);
    params2.screenId = INVALID_SCREEN_ID;

    // Differ in hdrPresent
    params2.hdrPresent = true;
    EXPECT_FALSE(params1 == params2);
    params2.hdrPresent = false;

    // Differ in gAlpha
    params2.gAlpha = 128;
    EXPECT_FALSE(params1 == params2);
    params2.gAlpha = 0;

    // Differ in transformType
    params2.transformType = GraphicTransformType::GRAPHIC_ROTATE_90;
    EXPECT_FALSE(params1 == params2);
    params2.transformType = GraphicTransformType::GRAPHIC_ROTATE_NONE;

    // Differ in targetColorGamut
    params2.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DISPLAY_P3;
    EXPECT_FALSE(params1 == params2);
    params2.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;

    // Differ in resultWidth
    params2.resultWidth = 1920;
    EXPECT_FALSE(params1 == params2);
    params2.resultWidth = 0;

    // Differ in resultHeight
    params2.resultHeight = 1080;
    EXPECT_FALSE(params1 == params2);
    params2.resultHeight = 0;

    // Differ in layerLinearMatrix size
    params2.layerLinearMatrix = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f};
    EXPECT_FALSE(params1 == params2);

    // Differ in layerLinearMatrix values (same size, different values)
    params2.layerLinearMatrix = {2.0f, 0.0f, 0.0f, 0.0f, 2.0f, 0.0f, 0.0f, 0.0f, 2.0f};
    EXPECT_FALSE(params1 == params2);
}

/**
 * @tc.name: GPUOfflineDrawParamsDefaultValuesTest001
 * @tc.desc: Test GPUOfflineDrawParams all default values
 * @tc.type: FUNC
 * @tc.require: issue_gpu_offline_branch_013
 */
HWTEST_F(GPUOfflineDrawParamsTest, DefaultValuesTest001, TestSize.Level1)
{
    GPUOfflineDrawParams params;

    EXPECT_FLOAT_EQ(params.sdrNit, 0.0f);
    EXPECT_FLOAT_EQ(params.displayNit, 0.0f);
    EXPECT_FLOAT_EQ(params.brightnessRatio, 1.0f);
    EXPECT_EQ(params.layerLinearMatrix.size(), 9u);
    EXPECT_FALSE(params.useBilinearInterpolation);
    EXPECT_FALSE(params.ignoreAlpha);
    EXPECT_FALSE(params.colorFollow);
    EXPECT_EQ(params.screenId, INVALID_SCREEN_ID);
    EXPECT_FALSE(params.hdrPresent);
    EXPECT_EQ(params.gAlpha, 0u);
    EXPECT_EQ(params.transformType, GraphicTransformType::GRAPHIC_ROTATE_NONE);
    EXPECT_EQ(params.targetColorGamut, GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB);
    EXPECT_EQ(params.resultWidth, 0);
    EXPECT_EQ(params.resultHeight, 0);
}

