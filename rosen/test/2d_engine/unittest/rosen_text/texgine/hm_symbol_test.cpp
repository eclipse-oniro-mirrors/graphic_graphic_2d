/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "rosen_text/text_style.h"
#include "convert.h"
#include "symbol_engine/hm_symbol_run.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class OHHmSymbolTest : public testing::Test {};

/*
 * @tc.name: OHHmSymbolTest001
 * @tc.desc: test for font isSymbolGlyph
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolTest, OHHmSymbolTest001, TestSize.Level1)
{
    TextStyle style;
    TextEngine::TextStyle textStyle;
    style.isSymbolGlyph = true;
    textStyle = AdapterTextEngine::Convert(style);
    EXPECT_EQ(textStyle.isSymbolGlyph, true);
}

/*
 * @tc.name: OHHmSymbolTest002
 * @tc.desc: test for symbol SetRenderMode
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolTest, OHHmSymbolTest002, TestSize.Level1)
{
    TextStyle style;
    style.isSymbolGlyph = true;
    TextEngine::TextStyle textStyle;
    style.symbol.SetRenderMode(0); // this 0 is single
    textStyle = AdapterTextEngine::Convert(style);
#ifndef USE_ROSEN_DRAWING
    EXPECT_EQ(textStyle.symbol.renderMode_, SymbolRenderingStrategy::SINGLE);
#else
    EXPECT_EQ(textStyle.symbol.renderMode_, RSSymbolRenderingStrategy::SINGLE);
#endif

    style.symbol.SetRenderMode(2); // this 2 is multiple opacity
    textStyle = AdapterTextEngine::Convert(style);
#ifndef USE_ROSEN_DRAWING
    EXPECT_EQ(textStyle.symbol.renderMode_, SymbolRenderingStrategy::MULTIPLE_OPACITY);
#else
    EXPECT_EQ(textStyle.symbol.renderMode_, RSSymbolRenderingStrategy::MULTIPLE_OPACITY);
#endif

    style.symbol.SetRenderMode(1); // this 1 is multiple color
    textStyle = AdapterTextEngine::Convert(style);
#ifndef USE_ROSEN_DRAWING
    EXPECT_EQ(textStyle.symbol.renderMode_, SymbolRenderingStrategy::MULTIPLE_COLOR);
#else
    EXPECT_EQ(textStyle.symbol.renderMode_, RSSymbolRenderingStrategy::MULTIPLE_COLOR);
#endif
}

/*
 * @tc.name: OHHmSymbolTest003
 * @tc.desc: test for symbol GetSymbolLayers
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolTest, OHHmSymbolTest003, TestSize.Level1)
{
#ifndef USE_ROSEN_DRAWING
    SkGlyphID glyphId = 0;
#else
    uint16_t glyohId = 0;
#endif
    TextEngine::TextStyle textStyle;
    SymbolLayers symbolInfo = TextEngine::HMSymbolRun::GetSymbolLayers(glyphId, textStyle.symbol);
}

} // namespace Rosen
} // namespace OHOS