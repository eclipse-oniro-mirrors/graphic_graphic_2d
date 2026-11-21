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

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <vector>

#include "rs_graphic_test.h"
#include "rs_graphic_test_img.h"
#include "rs_graphic_test_text.h"

#include "effect/color_matrix.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
// 3x3 matrix grid block, top of the screen.
constexpr int MATRIX_GRID_SIZE = 3;
constexpr int MATRIX_CELL_SIZE = 150;
constexpr int MATRIX_CELL_GAP = 10;
constexpr int MATRIX_ORIGIN_X = 10;
constexpr int MATRIX_ORIGIN_Y = 10;
constexpr int MATRIX_CELL_STRIDE = MATRIX_CELL_SIZE + MATRIX_CELL_GAP;

// Alpha scenario rows: one row per scenario, each row holds three nodes left to right:
//   [0] opaque reference (alpha = 1.0, no color matrix)
//   [1] alpha = 0.3 without color matrix
//   [2] alpha = 0.3 with the RGB scale color matrix
constexpr int ALPHA_NODE_COUNT = 3;
constexpr int ALPHA_OPAQUE_INDEX = 0;
constexpr int ALPHA_MATRIX_INDEX = ALPHA_NODE_COUNT - 1;
constexpr float ALPHA_THREE_TENTHS = 0.3f;

constexpr int ALPHA_CELL_SIZE = 220;
constexpr int ALPHA_CELL_GAP = 20;
constexpr int ALPHA_ORIGIN_X = 10;
constexpr int ALPHA_ROW_STRIDE = ALPHA_CELL_SIZE + ALPHA_CELL_GAP;
constexpr int ALPHA_FIRST_ROW_Y = 520;
constexpr int ALPHA_ROW_BG_IMAGE_Y = ALPHA_FIRST_ROW_Y;
constexpr int ALPHA_ROW_BG_COLOR_Y = ALPHA_FIRST_ROW_Y + ALPHA_ROW_STRIDE;
constexpr int ALPHA_ROW_CONTENT_IMAGE_Y = ALPHA_FIRST_ROW_Y + 2 * ALPHA_ROW_STRIDE;
constexpr int ALPHA_ROW_CONTENT_TEXT_Y = ALPHA_FIRST_ROW_Y + 3 * ALPHA_ROW_STRIDE;
constexpr int ALPHA_ROW_CHILDREN_Y = ALPHA_FIRST_ROW_Y + 4 * ALPHA_ROW_STRIDE;

constexpr float ALPHA_TEXT_FONT_SIZE = 40.0f;
constexpr float ALPHA_TEXT_POSITION_X = 10.0f;
constexpr float ALPHA_TEXT_POSITION_Y = 30.0f;
constexpr uint32_t ALPHA_BG_COLOR = 0xff3366cc;
constexpr uint32_t ALPHA_CHILD_COLOR = 0xffff0000;
constexpr uint32_t ALPHA_TEXT_COLOR = 0xff000000;
constexpr const char* ALPHA_BG_IMAGE_PATH = "/data/local/tmp/geom_test.jpg";

// Comparison block at the bottom of the screen.
constexpr int COMPARE_NODE_SIZE = 200;
constexpr int COMPARE_NODE_GAP = 10;
constexpr int COMPARE_ORIGIN_X = 10;
constexpr int COMPARE_ROW_Y = 1740;
constexpr int COMPARE_THREE_NODE_COUNT = 3;
constexpr float COMPARE_ALPHA = 0.5f;
constexpr float COMPARE_BORDER_WIDTH = 10.0f;
constexpr uint32_t COMPARE_BORDER_COLOR = 0xff000000;
constexpr uint32_t COMPARE_BG_COLOR = 0xff3366cc;

Drawing::ColorMatrix CreateScaleColorMatrix()
{
    Drawing::ColorMatrix colorMatrix;
    std::array<float, Drawing::ColorMatrix::MATRIX_SIZE> array = {
        0.9, 0, 0, 0, 0,
        0, 0.9, 0, 0, 0,
        0, 0, 0.9, 0, 0,
        0, 0, 0, 1, 0
    };
    colorMatrix.SetArray(array.data());
    return colorMatrix;
}

void ApplyBorderContent(const std::shared_ptr<RSCanvasNode>& node)
{
    node->SetBackgroundColor(COMPARE_BG_COLOR);
    node->SetBorderColor(COMPARE_BORDER_COLOR);
    node->SetBorderWidth(COMPARE_BORDER_WIDTH);
    node->SetBorderStyle(Vector4<BorderStyle>(BorderStyle::SOLID));
}

void AddNodeToRoot(RSGraphicTest& test, const std::shared_ptr<RSCanvasNode>& node)
{
    test.GetRootNode()->AddChild(node);
    test.RegisterNode(node);
}

std::vector<Vector4f> BuildAlphaRowBounds(int count, int originY)
{
    std::vector<Vector4f> boundsList;
    for (int i = 0; i < count; i++) {
        float x = static_cast<float>(ALPHA_ORIGIN_X + i * ALPHA_ROW_STRIDE);
        boundsList.emplace_back(x, static_cast<float>(originY),
            static_cast<float>(ALPHA_CELL_SIZE), static_cast<float>(ALPHA_CELL_SIZE));
    }
    return boundsList;
}

std::shared_ptr<RSCanvasNode> CreateAlphaCanvasNode(const Vector4f& bounds)
{
    auto node = RSCanvasNode::Create(false, false, RSGraphicTestDirector::Instance().GetRSUIContext());
    node->SetBounds(bounds);
    return node;
}

// Apply the fixed per-row alpha policy: opaque reference, alpha = 0.3 without matrix,
// then alpha = 0.3 with the RGB scale color matrix.
void ApplyAlphaPolicy(const std::shared_ptr<RSCanvasNode>& node, int index)
{
    if (index == ALPHA_OPAQUE_INDEX) {
        return;
    }
    node->SetAlpha(ALPHA_THREE_TENTHS);
    if (index == ALPHA_MATRIX_INDEX) {
        node->SetColorMatrix(CreateScaleColorMatrix());
    }
}

std::vector<std::vector<float>> BuildDifferentMatrices()
{
    return {
        // identity
        {1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0},
        // grayscale
        {0.2126f, 0.7152f, 0.0722f, 0, 0,
         0.2126f, 0.7152f, 0.0722f, 0, 0,
         0.2126f, 0.7152f, 0.0722f, 0, 0,
         0, 0, 0, 1, 0},
        // invert
        {-1, 0, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0},
        // sepia
        {0.393f, 0.769f, 0.189f, 0, 0,
         0.349f, 0.686f, 0.168f, 0, 0,
         0.272f, 0.534f, 0.131f, 0, 0,
         0, 0, 0, 1, 0},
        // red channel only
        {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
        // green channel only
        {0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
        // blue channel only
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0},
        // brightness boost
        {1, 0, 0, 0, 0.2f, 0, 1, 0, 0, 0.2f, 0, 0, 1, 0, 0.2f, 0, 0, 0, 1, 0},
        // saturation boost
        {1.6f, -0.2f, -0.2f, 0, 0,
         -0.2f, 1.6f, -0.2f, 0, 0,
         -0.2f, -0.2f, 1.6f, 0, 0,
         0, 0, 0, 1, 0}
    };
}

void AddMatrixGrid(RSGraphicTest& test)
{
    constexpr int matrixSize = Drawing::ColorMatrix::MATRIX_SIZE;
    auto matrices = BuildDifferentMatrices();
    int index = 0;
    for (int row = 0; row < MATRIX_GRID_SIZE; row++) {
        for (int col = 0; col < MATRIX_GRID_SIZE; col++) {
            auto testNode = SetUpNodeBgImage(ALPHA_BG_IMAGE_PATH,
                { static_cast<float>(MATRIX_ORIGIN_X + col * MATRIX_CELL_STRIDE),
                  static_cast<float>(MATRIX_ORIGIN_Y + row * MATRIX_CELL_STRIDE),
                  static_cast<float>(MATRIX_CELL_SIZE), static_cast<float>(MATRIX_CELL_SIZE) });
            Drawing::ColorMatrix colorMatrix;
            std::array<float, matrixSize> array = {};
            std::copy(matrices[index].begin(), matrices[index].end(), array.begin());
            colorMatrix.SetArray(array.data());
            testNode->SetColorMatrix(colorMatrix);
            // the last node is cleared with std::nullopt, so it renders the original image
            if (index == MATRIX_GRID_SIZE * MATRIX_GRID_SIZE - 1) {
                testNode->SetColorMatrix(std::nullopt);
            }
            AddNodeToRoot(test, testNode);
            index++;
        }
    }
}

void AddAlphaBgImageRow(RSGraphicTest& test, int originY)
{
    auto boundsList = BuildAlphaRowBounds(ALPHA_NODE_COUNT, originY);
    for (int i = 0; i < ALPHA_NODE_COUNT; i++) {
        auto testNode = SetUpNodeBgImage(ALPHA_BG_IMAGE_PATH, boundsList[i]);
        ApplyAlphaPolicy(testNode, i);
        AddNodeToRoot(test, testNode);
    }
}

void AddAlphaBgColorRow(RSGraphicTest& test, int originY)
{
    auto boundsList = BuildAlphaRowBounds(ALPHA_NODE_COUNT, originY);
    for (int i = 0; i < ALPHA_NODE_COUNT; i++) {
        auto testNode = CreateAlphaCanvasNode(boundsList[i]);
        testNode->SetBackgroundColor(ALPHA_BG_COLOR);
        ApplyAlphaPolicy(testNode, i);
        AddNodeToRoot(test, testNode);
    }
}

void AddAlphaContentImageRow(RSGraphicTest& test, int originY)
{
    auto boundsList = BuildAlphaRowBounds(ALPHA_NODE_COUNT, originY);
    for (int i = 0; i < ALPHA_NODE_COUNT; i++) {
        auto testNode = CreateAlphaCanvasNode(boundsList[i]);
        auto imageModifier = std::make_shared<ImageCustomModifier>();
        imageModifier->SetWidth(ALPHA_CELL_SIZE);
        imageModifier->SetHeight(ALPHA_CELL_SIZE);
        imageModifier->SetPixelMapPath(ALPHA_BG_IMAGE_PATH);
        testNode->AddModifier(imageModifier);
        ApplyAlphaPolicy(testNode, i);
        AddNodeToRoot(test, testNode);
    }
}

void AddAlphaContentTextRow(RSGraphicTest& test, int originY)
{
    auto boundsList = BuildAlphaRowBounds(ALPHA_NODE_COUNT, originY);
    for (int i = 0; i < ALPHA_NODE_COUNT; i++) {
        auto testNode = CreateAlphaCanvasNode(boundsList[i]);
        auto textModifier = std::make_shared<TextCustomModifier>();
        textModifier->SetFontSize(ALPHA_TEXT_FONT_SIZE);
        textModifier->SetPosition({ ALPHA_TEXT_POSITION_X, ALPHA_TEXT_POSITION_Y });
        textModifier->SetBrushColor(ALPHA_TEXT_COLOR);
        textModifier->SetText("CM");
        testNode->AddModifier(textModifier);
        ApplyAlphaPolicy(testNode, i);
        AddNodeToRoot(test, testNode);
    }
}

void AddAlphaChildrenRow(RSGraphicTest& test, int originY)
{
    auto boundsList = BuildAlphaRowBounds(ALPHA_NODE_COUNT, originY);
    constexpr float childSize = static_cast<float>(ALPHA_CELL_SIZE) / 2.0f;
    for (int i = 0; i < ALPHA_NODE_COUNT; i++) {
        auto parentNode = CreateAlphaCanvasNode(boundsList[i]);
        auto childNode = RSCanvasNode::Create(false, false, RSGraphicTestDirector::Instance().GetRSUIContext());
        childNode->SetBounds({ 0.0f, 0.0f, childSize, childSize });
        childNode->SetBackgroundColor(ALPHA_CHILD_COLOR);
        parentNode->AddChild(childNode);
        ApplyAlphaPolicy(parentNode, i);
        AddNodeToRoot(test, parentNode);
        test.RegisterNode(childNode);
    }
}

void AddCompareThreeNodeRow(RSGraphicTest& test)
{
    auto scaleMatrix = CreateScaleColorMatrix();
    for (int i = 0; i < COMPARE_THREE_NODE_COUNT; i++) {
        float x = static_cast<float>(COMPARE_ORIGIN_X + i * (COMPARE_NODE_SIZE + COMPARE_NODE_GAP));
        auto testNode = RSCanvasNode::Create(false, false, RSGraphicTestDirector::Instance().GetRSUIContext());
        testNode->SetBounds({ x, static_cast<float>(COMPARE_ROW_Y),
            static_cast<float>(COMPARE_NODE_SIZE), static_cast<float>(COMPARE_NODE_SIZE) });
        ApplyBorderContent(testNode);
        if (i >= 1) {
            testNode->SetAlpha(COMPARE_ALPHA);
        }
        if (i == COMPARE_THREE_NODE_COUNT - 1) {
            testNode->SetColorMatrix(scaleMatrix);
        }
        AddNodeToRoot(test, testNode);
    }
}
} // namespace

class ColorMatrixTest : public RSGraphicTest {
private:
    const int screenWidth = 1200;
    const int screenHeight = 2000;

public:
    void BeforeEach() override
    {
        SetScreenSize(screenWidth, screenHeight);
    }
};

/*
 * SetColorMatrix: single merged screenshot covering every color matrix scenario.
 *   Block 1 (top-left, y = 10..490): 3x3 grid, each node with a different color matrix.
 *   Block 2 (y = 520..1700): five alpha rows, each row holds three identical nodes left to right:
 *     node 0 is the opaque reference (alpha = 1.0, no color matrix), node 1 has alpha = 0.3 without
 *     a color matrix, node 2 has alpha = 0.3 with the RGB scale color matrix. The five rows cover
 *     background image, background color, content pixelmap, content text and a parent whose child
 *     drawable is rendered inside the parent's color filter layer.
 *   Block 3 (y = 1740..1940): three nodes with identical border/background content following the
 *     same opaque / alpha = 0.5 / alpha = 0.5 + RGB scale matrix pattern. After the double-alpha
 *     fix, node 1 and node 2 must show the same transparency.
 */
GRAPHIC_TEST(ColorMatrixTest, CONTENT_DISPLAY_TEST, ColorMatrix_Grid_3x3_Different)
{
    AddMatrixGrid(*this);
    AddAlphaBgImageRow(*this, ALPHA_ROW_BG_IMAGE_Y);
    AddAlphaBgColorRow(*this, ALPHA_ROW_BG_COLOR_Y);
    AddAlphaContentImageRow(*this, ALPHA_ROW_CONTENT_IMAGE_Y);
    AddAlphaContentTextRow(*this, ALPHA_ROW_CONTENT_TEXT_Y);
    AddAlphaChildrenRow(*this, ALPHA_ROW_CHILDREN_Y);
    AddCompareThreeNodeRow(*this);
}
} // namespace OHOS::Rosen
