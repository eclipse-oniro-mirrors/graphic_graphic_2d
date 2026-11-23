/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "rs_graphic_test.h"
#include "rs_graphic_test_img.h"
#include "ui/rs_effect_node.h"
#include "rs_graphic_test_director.h"
#include "ui_effect/property/include/rs_ui_mask_base.h"
#include "ui_effect/property/include/rs_ui_shader_base.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

// Default values
const float defaultBloomIntensityCutoff = 0.2f;
const float defaultLightMaxIntensity = 1.0f;
const float defaultMaxBloomIntensity = 1.0f;
const float defaultBloomFalloff = 2.0f;
const float defaultMinBorderWidth = 1.0f;
const float defaultMaxBorderWidth = 3.0f;
const float defaultInnerBorderBloomWidth = 2.0f;
const float defaultOuterBorderBloomWidth = 2.0f;
const Vector3f defaultColor = Vector3f{1.0f, 1.0f, 1.0f};

// Default FrameGradientMask params
const Vector4f defaultInnerBezier = Vector4f{0.0f, 0.0f, 0.0f, 0.0f};
const Vector4f defaultOuterBezier = Vector4f{0.0f, 0.0f, 0.0f, 0.0f};
const float defaultCornerRadius = 0.0f;
const float defaultInnerFrameWidth = 1000.0f;
const float defaultOuterFrameWidth = 0.1f;
const Vector2f defaultRectWH = Vector2f{1.0f, 0.3f};
const Vector2f defaultRectPos = Vector2f{0.0f, 0.0f};
const float defaultAxialFeatherStrength = 1.0f;
const float defaultAxialCenter = 0.5f;
const float defaultAxialCoreWidth = 0.3f;
const Vector2f defaultAxialDirection = Vector2f{0.0f, 1.0f};
const float defaultBoxAngleDeg = 45.0f;

static std::shared_ptr<RSNGMaskBase> CreateDefaultFrameGradientMask()
{
    auto frameGradientMask = std::make_shared<RSNGFrameGradientMask>();
    frameGradientMask->Setter<FrameGradientMaskInnerBezierTag>(defaultInnerBezier);
    frameGradientMask->Setter<FrameGradientMaskOuterBezierTag>(defaultOuterBezier);
    frameGradientMask->Setter<FrameGradientMaskCornerRadiusTag>(defaultCornerRadius);
    frameGradientMask->Setter<FrameGradientMaskInnerFrameWidthTag>(defaultInnerFrameWidth);
    frameGradientMask->Setter<FrameGradientMaskOuterFrameWidthTag>(defaultOuterFrameWidth);
    frameGradientMask->Setter<FrameGradientMaskRectWHTag>(defaultRectWH);
    frameGradientMask->Setter<FrameGradientMaskRectPosTag>(defaultRectPos);
    frameGradientMask->Setter<FrameGradientMaskAxialFeatherStrengthTag>(defaultAxialFeatherStrength);
    frameGradientMask->Setter<FrameGradientMaskAxialCenterTag>(defaultAxialCenter);
    frameGradientMask->Setter<FrameGradientMaskAxialCoreWidthTag>(defaultAxialCoreWidth);
    frameGradientMask->Setter<FrameGradientMaskAxialDirectionTag>(defaultAxialDirection);
    frameGradientMask->Setter<FrameGradientMaskBoxAngleDegTag>(defaultBoxAngleDeg);

    return std::static_pointer_cast<RSNGMaskBase>(frameGradientMask);
}

void InitSDFEdgeLightEffect(std::shared_ptr<RSNGSDFEdgeLightEffect>& sdfEdgeLightEffect)
{
    if (!sdfEdgeLightEffect) {
        return;
    }
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
    sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
}

namespace {
const std::string TEST_IMAGE_PATH = "/data/local/tmp/Images/backGroundImage.jpg";
const int SCREEN_WIDTH = 1200;
const int SCREEN_HEIGHT = 2000;
const float BLUR_RADIUS = 10.f;

// Param arrays
std::vector<float> bloomIntensityCutoffParams = {
    0.0f,
    0.2f,
    1.0f,
    -0.2f,
    std::numeric_limits<float>::infinity(),
};

std::vector<float> lightMaxIntensityParams = {
    0.0f,
    1.0f,
    5.0f,
    -1.0f,
    std::numeric_limits<float>::infinity(),
};

std::vector<float> maxBloomIntensityParams = {
    0.0f,
    1.0f,
    5.0f,
    -1.0f,
    std::numeric_limits<float>::infinity(),
};

std::vector<float> bloomFalloffPowParams = {
    0.0f,
    2.0f,
    8.0f,
    -2.0f,
    std::numeric_limits<float>::infinity(),
};

std::vector<float> minBorderWidthParams = {
    0.0f,
    1.0f,
    20.0f,
    -1.0f,
    std::numeric_limits<float>::infinity(),
};

std::vector<float> maxBorderWidthParams = {
    0.0f,
    3.0f,
    50.0f,
    -3.0f,
    std::numeric_limits<float>::infinity(),
};

std::vector<float> innerBorderBloomWidthParams = {
    0.0f,
    2.0f,
    20.0f,
    -2.0f,
    std::numeric_limits<float>::infinity(),
};

std::vector<float> outerBorderBloomWidthParams = {
    0.0f,
    2.0f,
    20.0f,
    -2.0f,
    std::numeric_limits<float>::infinity(),
};

std::vector<Vector3f> colorParams = {
    Vector3f{1.0f, 1.0f, 1.0f},
    Vector3f{1.0f, 0.0f, 0.0f},
    Vector3f{0.0f, 1.0f, 0.0f},
    Vector3f{0.0f, 0.0f, 1.0f},
    Vector3f{0.0f, 0.0f, 0.0f},
    Vector3f{-1.0f, 1.0f, 1.0f},
    Vector3f{std::numeric_limits<float>::infinity(), 1.0f, 1.0f},
};

std::shared_ptr<RSCanvasNode> CreateEffectChildNode(const int i, const int columnCount, const int rowCount,
    std::shared_ptr<RSEffectNode>& effectNode, std::shared_ptr<RSNGSDFEdgeLightEffect>& sdfEdgeLightEffect)
{
    auto sizeX = (columnCount != 0) ? (SCREEN_WIDTH / columnCount) : SCREEN_WIDTH;
    auto sizeY = (rowCount != 0) ? (SCREEN_HEIGHT * columnCount / rowCount) : SCREEN_HEIGHT;

    int x = (columnCount != 0) ? (i % columnCount) * sizeX : 0;
    int y = (columnCount != 0) ? (i / columnCount) * sizeY : 0;

    auto effectChildNode = RSCanvasNode::Create(false, false, RSGraphicTestDirector::Instance().GetRSUIContext());
    effectChildNode->SetBounds(x, y, sizeX, sizeY);
    effectChildNode->SetFrame(x, y, sizeX, sizeY);
    effectChildNode->SetOverlayNGShader(sdfEdgeLightEffect);
    effectNode->AddChild(effectChildNode);
    return effectChildNode;
}
}

class NGShaderSDFEdgeLightTest : public RSGraphicTest {
public:
    void BeforeEach() override
    {
        SetScreenSize(SCREEN_WIDTH, SCREEN_HEIGHT);
    }

    void SetEffectChildNode(const int i, const int columnCount, const int rowCount,
        std::shared_ptr<RSEffectNode>& effectNode, std::shared_ptr<RSNGSDFEdgeLightEffect>& sdfEdgeLightEffect)
    {
        auto effectChildNode = CreateEffectChildNode(i, columnCount, rowCount, effectNode, sdfEdgeLightEffect);
        RegisterNode(effectChildNode);
    }

    std::shared_ptr<RSEffectNode> SetUpEffectNode()
    {
        auto backgroundTestNode = SetUpNodeBgImage(TEST_IMAGE_PATH, {0, 0, SCREEN_WIDTH, SCREEN_HEIGHT});
        auto effectNode = RSEffectNode::Create(false, false, RSGraphicTestDirector::Instance().GetRSUIContext());
        effectNode->SetBounds({0, 0, SCREEN_WIDTH, SCREEN_HEIGHT});
        effectNode->SetFrame({0, 0, SCREEN_WIDTH, SCREEN_HEIGHT});
        std::shared_ptr<Rosen::RSFilter> backFilter = Rosen::RSFilter::CreateMaterialFilter(BLUR_RADIUS, 1, 1, 0,
            BLUR_COLOR_MODE::DEFAULT, true);
        effectNode->SetBackgroundFilter(backFilter);
        effectNode->SetClipToBounds(false);
        GetRootNode()->AddChild(backgroundTestNode);
        backgroundTestNode->AddChild(effectNode);
        RegisterNode(effectNode);
        RegisterNode(backgroundTestNode);
        return effectNode;
    }
};

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_BloomIntensityCutoffTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(bloomIntensityCutoffParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < bloomIntensityCutoffParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(bloomIntensityCutoffParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_LightMaxIntensityTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(lightMaxIntensityParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < lightMaxIntensityParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(lightMaxIntensityParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_MaxBloomIntensityTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(maxBloomIntensityParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < maxBloomIntensityParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(maxBloomIntensityParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_BloomFalloffPowTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(bloomFalloffPowParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < bloomFalloffPowParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(bloomFalloffPowParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_MinBorderWidthTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(minBorderWidthParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < minBorderWidthParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(minBorderWidthParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_MaxBorderWidthTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(maxBorderWidthParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < maxBorderWidthParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(maxBorderWidthParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_InnerBorderBloomWidthTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(innerBorderBloomWidthParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < innerBorderBloomWidthParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(innerBorderBloomWidthParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_OuterBorderBloomWidthTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(outerBorderBloomWidthParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < outerBorderBloomWidthParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(defaultColor);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(outerBorderBloomWidthParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

GRAPHIC_TEST(NGShaderSDFEdgeLightTest, EFFECT_TEST, Set_NG_Effect_SDF_Edge_Light_ColorTest)
{
    const int columnCount = 1;
    const int rowCount = static_cast<int>(colorParams.size());
    auto effectNode = SetUpEffectNode();

    for (size_t i = 0; i < colorParams.size(); i++) {
        auto sdfEdgeLightEffect = std::make_shared<RSNGSDFEdgeLightEffect>();
        InitSDFEdgeLightEffect(sdfEdgeLightEffect);
        auto lightMask = CreateDefaultFrameGradientMask();

        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomIntensityCutoffTag>(defaultBloomIntensityCutoff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaxIntensityTag>(defaultLightMaxIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBloomIntensityTag>(defaultMaxBloomIntensity);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectBloomFalloffPowTag>(defaultBloomFalloff);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMinBorderWidthTag>(defaultMinBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectMaxBorderWidthTag>(defaultMaxBorderWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectInnerBorderBloomWidthTag>(defaultInnerBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectOuterBorderBloomWidthTag>(defaultOuterBorderBloomWidth);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectColorTag>(colorParams[i]);
        sdfEdgeLightEffect->Setter<SDFEdgeLightEffectLightMaskTag>(lightMask);

        SetEffectChildNode(static_cast<int>(i), columnCount, rowCount, effectNode, sdfEdgeLightEffect);
    }
}

} // namespace OHOS::Rosen