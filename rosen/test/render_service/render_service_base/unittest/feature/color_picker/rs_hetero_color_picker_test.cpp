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

#include "feature/color_picker/rs_hetero_color_picker.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#ifdef MHC_ENABLE
#include "mhc/rs_mhc_manager.h"
#endif

#include "pipeline/rs_paint_filter_canvas.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class MockRSHeteroColorPicker : public RSHeteroColorPicker {
public:
    MockRSHeteroColorPicker() = default;
    ~MockRSHeteroColorPicker() = default;
};

class SingletonMockRSHeteroColorPicker {
public:
    static MockRSHeteroColorPicker& Instance()
    {
        static MockRSHeteroColorPicker instance;
        return instance;
    }
};

class MockSurfaceImpl : public Drawing::SurfaceImpl {
public:
    MockSurfaceImpl() = default;
    ~MockSurfaceImpl() override = default;

    MOCK_METHOD(Drawing::AdapterType, GetType, (), (const, override));
    MOCK_METHOD(bool, Bind, (const Drawing::Bitmap& bitmap), (override));
#ifdef RS_ENABLE_GPU
    MOCK_METHOD(bool, Bind, (const Drawing::Image& image), (override));
    MOCK_METHOD(bool, Bind, (const Drawing::FrameBuffer& frameBuffer), (override));
#endif
    MOCK_METHOD(std::shared_ptr<Drawing::Canvas>, GetCanvas, (), (const, override));
    MOCK_METHOD(std::shared_ptr<Drawing::Image>, GetImageSnapshot, (), (const, override));
    MOCK_METHOD(std::shared_ptr<Drawing::Image>, GetImageSnapshot, (const Drawing::RectI& bounds, bool allowRefCache),
        (const, override));
    MOCK_METHOD(std::shared_ptr<Drawing::Surface>, MakeSurface, (int width, int height), (const, override));
    MOCK_METHOD(
        std::shared_ptr<Drawing::Surface>, MakeSurface, (const Drawing::ImageInfo& imageInfo), (const, override));
    MOCK_METHOD(Drawing::BackendTexture, GetBackendTexture, (Drawing::BackendAccess access), (const, override));
    MOCK_METHOD(void, FlushAndSubmit, (bool syncCpu), (override));
    MOCK_METHOD(Drawing::SemaphoresSubmited, Flush, (Drawing::FlushInfo * drawingflushInfo), (override));
#ifdef RS_ENABLE_GL
    MOCK_METHOD(void, Wait, (const std::vector<GrGLsync>& syncs), (override));
#endif
#ifdef RS_ENABLE_VK
    MOCK_METHOD(void, Wait, (int32_t time, const VkSemaphore& semaphore), (override));
    MOCK_METHOD(void, SetDrawingArea, (const std::vector<Drawing::RectI>& rects), (override));
    MOCK_METHOD(void, ClearDrawingArea, (), (override));
#endif
    MOCK_METHOD(void, SetHeadroom, (float headroom), (override));
    MOCK_METHOD(float, GetHeadroom, (), (const, override));
    MOCK_METHOD(int, Width, (), (const, override));
    MOCK_METHOD(int, Height, (), (const, override));
};

class PaintFilterCanvasBaseTest : public RSPaintFilterCanvasBase {
public:
    explicit PaintFilterCanvasBaseTest(Drawing::Canvas* canvas) : RSPaintFilterCanvasBase(canvas) {};
    bool OnFilter() const override
    {
        return true;
    };
    bool OnFilterWithBrush(Drawing::Brush& brush) const override
    {
        return true;
    };
    Drawing::Brush* GetFilteredBrush() const override
    {
        return nullptr;
    };
    MOCK_METHOD(bool, DrawImageEffectHPS,
        (const Drawing::Image& image, const std::vector<std::shared_ptr<Drawing::HpsEffectParameter>>& params),
        (override));
};

template <typename Derived>
class MockRSMhcManagerBase : public RSMhcManager {
public:
    using RSMhcManager::RSMhcManager;
#ifdef RS_ENABLE_VK
    bool IsInterfaceTypeBasicRender() {
        return static_cast<Derived*>(this)->IsInterfaceTypeBasicRender();
    }
#endif // RS_ENABLE_VK
    std::optional<bool> CheckIfInCaptureProcess() const {
        return static_cast<Derived*>(this)->CheckIfInCaptureProcess();
    }
};

class MockRSMhcManager : public MockRSMhcManagerBase<MockRSMhcManager> {
public:
#ifdef RS_ENABLE_VK
    MOCK_METHOD(bool, IsInterfaceTypeBasicRender, (), ());
#endif // RS_ENABLE_VK
    MOCK_METHOD(std::optional<bool>, CheckIfInCaptureProcess, (), (const));
};

class SingletonMockRSMhcManager {
public:
    static MockRSMhcManager& Instance()
    {
        static MockRSMhcManager instance;
        return instance;
    }
};

template <typename Derived>
class MockRSPaintFilterCanvasBase : public RSPaintFilterCanvas {
public:
    explicit MockRSPaintFilterCanvasBase(Drawing::Canvas* canvas = nullptr)
        : RSPaintFilterCanvas(canvas) {}

    Drawing::Surface* GetSurface() const {
        return static_cast<const Derived*>(this)->GetSurface();
    }
};

class MockRSPaintFilterCanvas : public MockRSPaintFilterCanvasBase<MockRSPaintFilterCanvas> {
public:
    explicit MockRSPaintFilterCanvas(Drawing::Canvas* canvas = nullptr)
        : MockRSPaintFilterCanvasBase<MockRSPaintFilterCanvas>(canvas) {}

    MOCK_METHOD(bool, IsSubTreeInParallel, (), (const));
    MOCK_METHOD(bool, GetIsParallelCanvas, (), (const));
    MOCK_METHOD(Drawing::Surface*, GetSurface, (), (const, override));
};

class RSHeteroColorPickerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSHeteroColorPickerTest::SetUpTestCase() {}
void RSHeteroColorPickerTest::TearDownTestCase() {}
void RSHeteroColorPickerTest::SetUp() {}
void RSHeteroColorPickerTest::TearDown() {}

HWTEST_F(RSHeteroColorPickerTest, GetColor_NotBasicRender, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    std::shared_ptr<Drawing::Image> image = std::make_shared<Drawing::Image>();

    bool result = SingletonMockRSHeteroColorPicker::Instance().GetColor(
        [](Drawing::ColorQuad& color) {}, mockCanvas, image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_RenderThreadInCaptureProcess, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(true));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    std::shared_ptr<Drawing::Image> image = std::make_shared<Drawing::Image>();

    bool result = SingletonMockRSHeteroColorPicker::Instance().GetColor(
        [](Drawing::ColorQuad& color) {}, mockCanvas, image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_InvalidUpdateColor, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    auto surface = std::make_shared<Drawing::Surface>();
    auto mockImpl = std::make_shared<MockSurfaceImpl>();
    surface->impl_ = mockImpl;
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(surface.get()));
    auto image = std::make_shared<Drawing::Image>();

    bool result = SingletonMockRSHeteroColorPicker::Instance().GetColor(nullptr, // invalid updateColor
        mockCanvas, image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_InvalidSurface, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(nullptr));
    auto image = std::make_shared<Drawing::Image>();

    bool result = SingletonMockRSHeteroColorPicker::Instance().GetColor([](Drawing::ColorQuad& color) {},
        mockCanvas, // invalid surface
        image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_InvalidImage, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    auto surface = std::make_shared<Drawing::Surface>();
    auto mockImpl = std::make_shared<MockSurfaceImpl>();
    surface->impl_ = mockImpl;
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(surface.get()));
    std::shared_ptr<Drawing::Image> image = nullptr;

    bool result = SingletonMockRSHeteroColorPicker::Instance().GetColor([](Drawing::ColorQuad& color) {}, mockCanvas,
        image // invalid image
    );

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_MakeSurfaceFailed, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    auto surface = std::make_shared<Drawing::Surface>();
    auto mockImpl = std::make_shared<MockSurfaceImpl>();
    surface->impl_ = mockImpl;
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(surface.get()));
    auto image = std::make_shared<Drawing::Image>();
    EXPECT_CALL(*mockImpl, MakeSurface(1, 1)).WillOnce(testing::Return(nullptr));

    bool result =
        SingletonMockRSHeteroColorPicker::Instance().GetColor([](Drawing::ColorQuad& color) {}, mockCanvas, image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_GetCanvasFailed, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    auto surface = std::make_shared<Drawing::Surface>();
    auto mockImpl = std::make_shared<MockSurfaceImpl>();
    surface->impl_ = mockImpl;
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(surface.get()));
    auto image = std::make_shared<Drawing::Image>();
    EXPECT_CALL(*mockImpl, MakeSurface(1, 1)).WillOnce(testing::Return(surface));
    EXPECT_CALL(*mockImpl, GetCanvas()).WillOnce(testing::Return(nullptr));

    bool result =
        SingletonMockRSHeteroColorPicker::Instance().GetColor([](Drawing::ColorQuad& color) {}, mockCanvas, image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_DrawImageEffectHPSFailed, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    auto surface = std::make_shared<Drawing::Surface>();
    auto mockImpl = std::make_shared<MockSurfaceImpl>();
    surface->impl_ = mockImpl;
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(surface.get()));
    auto image = std::make_shared<Drawing::Image>();
    std::shared_ptr<PaintFilterCanvasBaseTest> paintFilterCanvasBase =
        std::make_shared<PaintFilterCanvasBaseTest>(nullptr);
    EXPECT_NE(paintFilterCanvasBase, nullptr);
    std::shared_ptr<Drawing::Canvas> canvasPtr = std::static_pointer_cast<Drawing::Canvas>(paintFilterCanvasBase);
    EXPECT_CALL(*mockImpl, MakeSurface(1, 1)).WillOnce(testing::Return(surface));
    EXPECT_CALL(*mockImpl, GetCanvas()).WillOnce(testing::Return(canvasPtr));
    EXPECT_CALL(*paintFilterCanvasBase, DrawImageEffectHPS(_, _)).WillOnce(testing::Return(false));

    bool result =
        SingletonMockRSHeteroColorPicker::Instance().GetColor([](Drawing::ColorQuad& color) {}, mockCanvas, image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_GetImageSnapshotFailed, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    auto surface = std::make_shared<Drawing::Surface>();
    auto mockImpl = std::make_shared<MockSurfaceImpl>();
    surface->impl_ = mockImpl;
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(surface.get()));
    auto image = std::make_shared<Drawing::Image>();
    std::shared_ptr<PaintFilterCanvasBaseTest> paintFilterCanvasBase =
        std::make_shared<PaintFilterCanvasBaseTest>(nullptr);
    EXPECT_NE(paintFilterCanvasBase, nullptr);
    std::shared_ptr<Drawing::Canvas> canvasPtr = std::static_pointer_cast<Drawing::Canvas>(paintFilterCanvasBase);
    EXPECT_CALL(*mockImpl, MakeSurface(1, 1)).WillOnce(testing::Return(surface));
    EXPECT_CALL(*mockImpl, GetCanvas()).WillOnce(testing::Return(canvasPtr));
    EXPECT_CALL(*paintFilterCanvasBase, DrawImageEffectHPS(_, _)).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockImpl, GetImageSnapshot()).WillOnce(testing::Return(nullptr));

    bool result =
        SingletonMockRSHeteroColorPicker::Instance().GetColor([](Drawing::ColorQuad& color) {}, mockCanvas, image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_GetBackendTextureFailed, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    auto surface = std::make_shared<Drawing::Surface>();
    auto mockImpl = std::make_shared<MockSurfaceImpl>();
    surface->impl_ = mockImpl;
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(surface.get()));
    auto image = std::make_shared<Drawing::Image>();
    std::shared_ptr<PaintFilterCanvasBaseTest> paintFilterCanvasBase =
        std::make_shared<PaintFilterCanvasBaseTest>(nullptr);
    EXPECT_NE(paintFilterCanvasBase, nullptr);
    std::shared_ptr<Drawing::Canvas> canvasPtr = std::static_pointer_cast<Drawing::Canvas>(paintFilterCanvasBase);
    auto invalidTexture = Drawing::BackendTexture(false);
    EXPECT_CALL(*mockImpl, MakeSurface(1, 1)).WillOnce(testing::Return(surface));
    EXPECT_CALL(*mockImpl, GetCanvas()).WillOnce(testing::Return(canvasPtr));
    EXPECT_CALL(*paintFilterCanvasBase, DrawImageEffectHPS(_, _)).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockImpl, GetImageSnapshot()).WillOnce(testing::Return(image));
    EXPECT_CALL(*mockImpl, GetBackendTexture(testing::_)).WillOnce(testing::Return(invalidTexture));

    bool result =
        SingletonMockRSHeteroColorPicker::Instance().GetColor([](Drawing::ColorQuad& color) {}, mockCanvas, image);

    EXPECT_FALSE(result);
}

HWTEST_F(RSHeteroColorPickerTest, GetColor_RegisterFuncFailed, TestSize.Level1)
{
    MockRSMhcManager& mockMhcManager = SingletonMockRSMhcManager::Instance();
    EXPECT_CALL(mockMhcManager, IsInterfaceTypeBasicRender()).WillOnce(Return(true));
    EXPECT_CALL(mockMhcManager, CheckIfInCaptureProcess()).WillOnce(Return(false));
    MockRSPaintFilterCanvas mockCanvas;
    EXPECT_CALL(mockCanvas, IsSubTreeInParallel()).WillOnce(Return(false));
    EXPECT_CALL(mockCanvas, GetIsParallelCanvas()).WillOnce(Return(false));
    auto surface = std::make_shared<Drawing::Surface>();
    auto mockImpl = std::make_shared<MockSurfaceImpl>();
    surface->impl_ = mockImpl;
    EXPECT_CALL(mockCanvas, GetSurface()).WillOnce(Return(surface.get()));
    auto image = std::make_shared<Drawing::Image>();
    std::shared_ptr<PaintFilterCanvasBaseTest> paintFilterCanvasBase =
        std::make_shared<PaintFilterCanvasBaseTest>(nullptr);
    EXPECT_NE(paintFilterCanvasBase, nullptr);
    std::shared_ptr<Drawing::Canvas> canvasPtr = std::static_pointer_cast<Drawing::Canvas>(paintFilterCanvasBase);
    auto backendTexture = Drawing::BackendTexture(true);
    EXPECT_CALL(*mockImpl, MakeSurface(1, 1)).WillOnce(testing::Return(surface));
    EXPECT_CALL(*mockImpl, GetCanvas()).WillOnce(testing::Return(canvasPtr));
    EXPECT_CALL(*paintFilterCanvasBase, DrawImageEffectHPS(_, _)).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockImpl, GetImageSnapshot()).WillOnce(testing::Return(image));
    EXPECT_CALL(*mockImpl, GetBackendTexture(testing::_)).WillOnce(testing::Return(backendTexture));

    bool result =
        SingletonMockRSHeteroColorPicker::Instance().GetColor([](Drawing::ColorQuad& color) {}, mockCanvas, image);

    EXPECT_FALSE(result);
}

} // namespace OHOS::Rosen