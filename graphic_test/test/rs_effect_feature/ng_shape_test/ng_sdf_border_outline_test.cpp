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

#include "effect/rs_render_shape_base.h"
#include "rs_graphic_test.h"
#include "rs_graphic_test_img.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {

class NGSDFBorderOutlineTest;
constexpr int screenWidth = 1200;
constexpr int screenHeight = 2000;

// border宽度参数
static const std::vector<float> borderWidthParams = {
    1.0f, 5.0f, 10.0f, 20.0f, 50.0f
};

// border颜色参数
static const std::vector<Drawing::Color> borderColorParams = {
    Drawing::Color::COLOR_RED,
    Drawing::Color::COLOR_BLUE,
    Drawing::Color::COLOR_GREEN,
    Drawing::Color::COLOR_YELLOW
};

// 负宽度参数（用于边界测试）
static const std::vector<float> negativeWidthParams = {
    -1.0f, -10.0f, -100.0f
};

/**
 * @tc.name: Set_SDF_Border_Outline_Test_1
 * @tc.desc: 测试不同borderWidth的外描边效果
 * @tc.type: FUNC
 */
GRAPHIC_TEST(NGSDFBorderOutlineTest, EFFECT_TEST, Set_SDF_Border_Outline_Test_1)
{
    int columnCount = 2;
    int rowCount = static_cast<int>(borderWidthParams.size());
    auto sizeX = screenWidth / columnCount;
    auto sizeY = screenHeight * columnCount / rowCount;

    for (int i = 0; i < rowCount; i++) {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        int x = (i % columnCount) * sizeX;
        int y = (i / columnCount) * sizeY;
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, sizeX, sizeY};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        // 创建RRect形状用于外描边测试
        auto rRectShape = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
        auto rrectChildShape = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShape);
        rrectChildShape->Setter<SDFRRectShapeLeftTag>(0);
        rrectChildShape->Setter<SDFRRectShapeTopTag>(0);
        rrectChildShape->Setter<SDFRRectShapeWidthTag>(300);
        rrectChildShape->Setter<SDFRRectShapeHeightTag>(300);
        rrectChildShape->Setter<SDFRRectShapeRadiusXTag>(20);
        rrectChildShape->Setter<SDFRRectShapeRadiusYTag>(20);

        // 创建border filter并设置isOutline=true
        Drawing::GESDFBorderParams borderParam;
        borderParam.color = borderColorParams[i];
        borderParam.width = borderWidthParams[i];
        borderParam.isOutline = true;  // 外描边

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(rrectChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {x, y, sizeX, sizeY});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }
}

/**
 * @tc.name: Set_SDF_Border_Compare_Test_1
 * @tc.desc: 同一形状的内/外描边对比
 * @tc.type: FUNC
 */
GRAPHIC_TEST(NGSDFBorderOutlineTest, EFFECT_TEST, Set_SDF_Border_Compare_Test_1)
{
    int columnCount = 2;
    int rowCount = 2;
    auto sizeX = screenWidth / columnCount;
    auto sizeY = screenHeight * columnCount / rowCount;

    // 内描边 (row 0)
    {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        int x = 0;
        int y = 0;
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, sizeX, sizeY};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        auto rRectShape = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
        auto rrectChildShape = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShape);
        rrectChildShape->Setter<SDFRRectShapeLeftTag>(0);
        rrectChildShape->Setter<SDFRRectShapeTopTag>(0);
        rrectChildShape->Setter<SDFRRectShapeWidthTag>(300);
        rrectChildShape->Setter<SDFRRectShapeHeightTag>(300);
        rrectChildShape->Setter<SDFRRectShapeRadiusXTag>(20);
        rrectChildShape->Setter<SDFRRectShapeRadiusYTag>(20);

        Drawing::GESDFBorderParams borderParam;
        borderParam.color = Drawing::Color::COLOR_RED;
        borderParam.width = 10.0f;
        borderParam.isOutline = false;  // 内描边

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(rrectChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {x, y, sizeX, sizeY});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }

    // 外描边 (row 1)
    {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        int x = sizeX;
        int y = 0;
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, sizeX, sizeY};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        auto rRectShape = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
        auto rrectChildShape = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShape);
        rrectChildShape->Setter<SDFRRectShapeLeftTag>(0);
        rrectChildShape->Setter<SDFRRectShapeTopTag>(0);
        rrectChildShape->Setter<SDFRRectShapeWidthTag>(300);
        rrectChildShape->Setter<SDFRRectShapeHeightTag>(300);
        rrectChildShape->Setter<SDFRRectShapeRadiusXTag>(20);
        rrectChildShape->Setter<SDFRRectShapeRadiusYTag>(20);

        Drawing::GESDFBorderParams borderParam;
        borderParam.color = Drawing::Color::COLOR_RED;
        borderParam.width = 10.0f;
        borderParam.isOutline = true;  // 外描边

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(rrectChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {x, y, sizeX, sizeY});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }
}

/**
 * @tc.name: Set_SDF_Border_Outline_Colors_Test_1
 * @tc.desc: 验证不同颜色值的外描边
 * @tc.type: FUNC
 */
GRAPHIC_TEST(NGSDFBorderOutlineTest, EFFECT_TEST, Set_SDF_Border_Outline_Colors_Test_1)
{
    int columnCount = 2;
    int rowCount = static_cast<int>(borderColorParams.size());
    auto sizeX = screenWidth / columnCount;
    auto sizeY = screenHeight * columnCount / rowCount;

    Vector2f v0(100, 100);
    Vector2f v1(200, 100);
    Vector2f v2(150, 200);

    for (int i = 0; i < rowCount; i++) {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        int x = (i % columnCount) * sizeX;
        int y = (i / columnCount) * sizeY;
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, sizeX, sizeY};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        auto triangleShape = CreateShape(RSNGEffectType::SDF_TRIANGLE_SHAPE);
        auto triangleChildShape = std::static_pointer_cast<RSNGSDFTriangleShape>(triangleShape);
        triangleChildShape->Setter<SDFTriangleShapeVertex0Tag>(v0);
        triangleChildShape->Setter<SDFTriangleShapeVertex1Tag>(v1);
        triangleChildShape->Setter<SDFTriangleShapeVertex2Tag>(v2);
        triangleChildShape->Setter<SDFTriangleShapeRadiusTag>(20);

        Drawing::GESDFBorderParams borderParam;
        borderParam.color = borderColorParams[i];
        borderParam.width = 10.0f;
        borderParam.isOutline = true;  // 外描边

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(triangleChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {x, y, sizeX, sizeY});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }
}

/**
 * @tc.name: Set_SDF_Border_Outline_Shapes_Test_1
 * @tc.desc: 验证不同SDF形状的外描边
 * @tc.type: FUNC
 */
GRAPHIC_TEST(NGSDFBorderOutlineTest, EFFECT_TEST, Set_SDF_Border_Outline_Shapes_Test_1)
{
    int columnCount = 4;
    int rowCount = 2;
    auto sizeX = screenWidth / columnCount;
    auto sizeY = screenHeight * columnCount / rowCount;

    // 行0: RRect外描边
    {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        int x = 0;
        int y = 0;
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, sizeX, sizeY};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        auto rRectShape = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
        auto rrectChildShape = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShape);
        rrectChildShape->Setter<SDFRRectShapeLeftTag>(0);
        rrectChildShape->Setter<SDFRRectShapeTopTag>(0);
        rrectChildShape->Setter<SDFRRectShapeWidthTag>(300);
        rrectChildShape->Setter<SDFRRectShapeHeightTag>(300);
        rrectChildShape->Setter<SDFRRectShapeRadiusXTag>(20);
        rrectChildShape->Setter<SDFRRectShapeRadiusYTag>(20);

        Drawing::GESDFBorderParams borderParam;
        borderParam.color = Drawing::Color::COLOR_RED;
        borderParam.width = 10.0f;
        borderParam.isOutline = true;

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(rrectChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {x, y, sizeX, sizeY});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }

    // 行0: Triangle外描边
    {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        int x = sizeX;
        int y = 0;
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, sizeX, sizeY};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        Vector2f v0(100, 100);
        Vector2f v1(200, 100);
        Vector2f v2(150, 200);

        auto triangleShape = CreateShape(RSNGEffectType::SDF_TRIANGLE_SHAPE);
        auto triangleChildShape = std::static_pointer_cast<RSNGSDFTriangleShape>(triangleShape);
        triangleChildShape->Setter<SDFTriangleShapeVertex0Tag>(v0);
        triangleChildShape->Setter<SDFTriangleShapeVertex1Tag>(v1);
        triangleChildShape->Setter<SDFTriangleShapeVertex2Tag>(v2);
        triangleChildShape->Setter<SDFTriangleShapeRadiusTag>(20);

        Drawing::GESDFBorderParams borderParam;
        borderParam.color = Drawing::Color::COLOR_BLUE;
        borderParam.width = 10.0f;
        borderParam.isOutline = true;

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(triangleChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {x, y, sizeX, sizeY});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }

    // 行1: Pixelmap外描边
    {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        int x = 0;
        int y = sizeY;
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, sizeX, sizeY};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        auto pixelmapShape = CreateShape(RSNGEffectType::SDF_PIXELMAP_SHAPE);
        auto pixelmapChildShape = std::static_pointer_cast<RSNGSDFPixelmapShape>(pixelmapShape);
        auto image = CreateDawnImageFromColor(Drawing::Color::COLOR_GREEN);

        // 300x300的纯色图
        pixelmapChildShape->Setter<SDFPixelmapShapeImageTag>(image);
        pixelmapChildShape->Setter<SDFPixelmapShapeWidthTag>(300);
        pixelmapChildShape->Setter<SDFPixelmapShapeHeightTag>(300);

        Drawing::GESDFBorderParams borderParam;
        borderParam.color = Drawing::Color::COLOR_GREEN;
        borderParam.width = 10.0f;
        borderParam.isOutline = true;

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(pixelmapChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {x, y, sizeX, sizeY});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }

    // 行1: Union形状外描边
    {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        int x = sizeX;
        int y = sizeY;
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, sizeX, sizeY};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        auto unionShape = CreateShape(RSNGEffectType::SDF_SMOOTH_UNION_OP_SHAPE);
        auto unionChildShape = std::static_pointer_cast<RSNGSDFSmoothUnionOpShape>(unionShape);

        // 创建两个圆角RRect进行合并
        auto rRectShapeX = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
        auto rrectChildShapeX = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShapeX);
        rrectChildShapeX->Setter<SDFRRectShapeLeftTag>(0);
        rrectChildShapeX->Setter<SDFRRectShapeTopTag>(0);
        rrectChildShapeX->Setter<SDFRRectShapeWidthTag>(100);
        rrectChildShapeX->Setter<SDFRRectShapeHeightTag>(100);
        rrectChildShapeX->Setter<SDFRRectShapeRadiusXTag>(10);
        rrectChildShapeX->Setter<SDFRRectShapeRadiusYTag>(10);

        unionChildShape->Setter<SDFSmoothUnionOpShapeShapeXTag>(rrectChildShapeX);

        auto rRectShapeY = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
        auto rrectChildShapeY = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShapeY);
        rrectChildShapeY->Setter<SDFRRectShapeLeftTag>(100);
        rrectChildShapeY->Setter<SDFRRectShapeTopTag>(0);
        rrectChildShapeY->Setter<SDFRRectShapeWidthTag>(100);
        rrectChildShapeY->Setter<SDFRRectShapeHeightTag>(100);
        rrectChildShapeY->Setter<SDFRRectShapeRadiusXTag>(10);
        rrectChildShapeY->Setter<SDFRRectShapeRadiusYTag>(10);

        unionChildShape->Setter<SDFSmoothUnionOpShapeShapeYTag>(rrectChildShapeY);
        unionChildShape->Setter<SDFSmoothUnionOpShapeSpacingTag>(20);

        Drawing::GESDFBorderParams borderParam;
        borderParam.color = Drawing::Color::COLOR_YELLOW;
        borderParam.width = 10.0f;
        borderParam.isOutline = true;

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(unionChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {x, y, sizeX, sizeY});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }
}

/**
 * @tc.name: Set_SDF_Border_Outline_ZeroWidth_Test
 * @tc.desc: 验证borderWidth=0的外描边处理
 * @tc.type: FUNC
 */
GRAPHIC_TEST(NGSDFBorderOutlineTest, EFFECT_TEST, Set_SDF_Border_Outline_ZeroWidth_Test)
{
    auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
    InitFrostedGlassFilter(frostedGlassFilter);
    auto backgroundTestNode = RSCanvasNode::Create();
    Rosen::Vector4f bounds{0, 0, 600, 600};
    backgroundTestNode->SetBounds(bounds);
    backgroundTestNode->SetFrame(bounds);
    backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

    auto rRectShape = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
    auto rrectChildShape = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShape);
    rrectChildShape->Setter<SDFRRectShapeLeftTag>(0);
    rrectChildShape->Setter<SDFRRectShapeTopTag>(0);
    rrectChildShape->Setter<SDFRRectShapeWidthTag>(600);
    rrectChildShape->Setter<SDFRRectShapeHeightTag>(600);
    rrectChildShape->Setter<SDFRRectShapeRadiusXTag>(20);
    rrectChildShape->Setter<SDFRRectShapeRadiusYTag>(20);

    Drawing::GESDFBorderParams borderParam;
    borderParam.color = Drawing::Color::COLOR_RED;
    borderParam.width = 0.0f;
    borderParam.isOutline = true;

    auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
    borderShape->SetSDFBorderParam(borderParam);
    borderShape->SetSDFShape(rrectChildShape);

    backgroundTestNode->SetSDFShape(borderShape);

    auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {0, 0, 600, 600});
    childNode->AddChild(backgroundTestNode);
    RegisterNode(backgroundTestNode);
    GetRootNode()->AddChild(childNode);
    RegisterNode(childNode);
}

/**
 * @tc.name: Set_SDF_Border_Outline_NegativeWidth_Test
 * @tc.desc: 验证borderWidth<0的外描边处理
 * @tc.type: FUNC
 */
GRAPHIC_TEST(NGSDFBorderOutlineTest, EFFECT_TEST, Set_SDF_Border_Outline_NegativeWidth_Test)
{
    for (float width : negativeWidthParams) {
        auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
        InitFrostedGlassFilter(frostedGlassFilter);
        auto backgroundTestNode = RSCanvasNode::Create();
        Rosen::Vector4f bounds{0, 0, 300, 300};
        backgroundTestNode->SetBounds(bounds);
        backgroundTestNode->SetFrame(bounds);
        backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

        auto rRectShape = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
        auto rrectChildShape = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShape);
        rrectChildShape->Setter<SDFRRectShapeLeftTag>(0);
        rrectChildShape->Setter<SDFRRectShapeTopTag>(0);
        rrectChildShape->Setter<SDFRRectShapeWidthTag>(300);
        rrectChildShape->Setter<SDFRRectShapeHeightTag>(300);
        rrectChildShape->Setter<SDFRRectShapeRadiusXTag>(20);
        rrectChildShape->Setter<SDFRRectShapeRadiusYTag>(20);

        Drawing::GESDFBorderParams borderParam;
        borderParam.color = Drawing::Color::COLOR_RED;
        borderParam.width = width;
        borderParam.isOutline = true;

        auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
        borderShape->SetSDFBorderParam(borderParam);
        borderShape->SetSDFShape(rrectChildShape);

        backgroundTestNode->SetSDFShape(borderShape);

        auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {0, 0, 300, 300});
        childNode->AddChild(backgroundTestNode);
        RegisterNode(backgroundTestNode);
        GetRootNode()->AddChild(childNode);
        RegisterNode(childNode);
    }
}

/**
 * @tc.name: Set_SDF_Border_Outline_ExcessiveWidth_Test
 * @tc.desc: 验证borderWidth过大值的处理
 * @tc.type: FUNC
 */
GRAPHIC_TEST(NGSDFBorderOutlineTest, EFFECT_TEST, Set_SDF_Border_Outline_ExcessiveWidth_Test)
{
    auto frostedGlassFilter = std::make_shared<RSNGFrostedGlassFilter>();
    InitFrostedGlassFilter(frostedGlassFilter);
    auto backgroundTestNode = RSCanvasNode::Create();
    Rosen::Vector4f bounds{0, 0, 600, 600};
    backgroundTestNode->SetBounds(bounds);
    backgroundTestNode->SetFrame(bounds);
    backgroundTestNode->SetMaterialNGFilter(frostedGlassFilter);

    auto rRectShape = CreateShape(RSNGEffectType::SDF_RRECT_SHAPE);
    auto rrectChildShape = std::static_pointer_cast<RSNGSDFRRectShape>(rRectShape);
    rrectChildShape->Setter<SDFRRectShapeLeftTag>(0);
    rrectChildShape->Setter<SDFRRectShapeTopTag>(0);
    rrectChildShape->Setter<SDFRRectShapeWidthTag>(600);
    rrectChildShape->Setter<SDFRRectShapeHeightTag>(600);
    rrectChildShape->Setter<SDFRRectShapeRadiusXTag>(20);
    rrectChildShape->Setter<SDFRRectShapeRadiusYTag>(20);

    Drawing::GESDFBorderParams borderParam;
    borderParam.color = Drawing::Color::COLOR_RED;
    borderParam.width = 1000.0f;  // 过大宽度
    borderParam.isOutline = true;

    auto borderShape = std::static_pointer_cast<RSNGSDFBorderShape>(CreateShape(RSNGEffectType::SDF_BORDER));
    borderShape->SetSDFBorderParam(borderParam);
    borderShape->SetSDFShape(rrectChildShape);

    backgroundTestNode->SetSDFShape(borderShape);

    auto childNode = SetUpNodeBgImage("/data/local/tmp/fg_test.jpg", {0, 0, 600, 600});
    childNode->AddChild(backgroundTestNode);
    RegisterNode(backgroundTestNode);
    GetRootNode()->AddChild(childNode);
    RegisterNode(childNode);
}

} // namespace OHOS::Rosen