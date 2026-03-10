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

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "include/core/SkTypeface.h"
#include "txt/font_asset_provider.h"
#include "txt/typeface_font_asset_provider.h"

using namespace testing;
using namespace testing::ext;

namespace txt {

class TypefaceFontAssetProviderTest : public testing::Test {};

/**
 * @tc.name: TypefaceFontAssetProvider001
 * @tc.desc: Test TypefaceFontAssetProvider registration and querying
 * @tc.type: FUNC
 */
HWTEST_F(TypefaceFontAssetProviderTest, TypefaceFontAssetProvider001, TestSize.Level0)
{
    TypefaceFontAssetProvider provider;

    // Register nullptr typeface - should not be added
    provider.RegisterTypeface(nullptr);
    EXPECT_EQ(provider.GetFamilyCount(), 0u);

    // Register with empty family name - should not be added
    auto typeface1 = SkTypeface::MakeDefault();
    provider.RegisterTypeface(std::move(typeface1), "");
    EXPECT_EQ(provider.GetFamilyCount(), 0u);

    // Register with valid typeface and family name
    auto typeface2 = SkTypeface::MakeDefault();
    provider.RegisterTypeface(std::move(typeface2), "TestFamily");
    EXPECT_EQ(provider.GetFamilyCount(), 1u);

    // GetFamilyName with valid index
    std::string name = provider.GetFamilyName(0);
    EXPECT_EQ(name, "TestFamily");

    // GetFamilyName with invalid index (negative)
    EXPECT_EQ(provider.GetFamilyName(-1), "");

    // GetFamilyName with invalid index (out of bounds)
    EXPECT_EQ(provider.GetFamilyName(100), "");

    // MatchFamily with existing family
    auto styleSet = provider.MatchFamily("TestFamily");
    EXPECT_NE(styleSet, nullptr);

    // MatchFamily with non-existing family
    EXPECT_EQ(provider.MatchFamily("NonExistent"), nullptr);
}

/**
 * @tc.name: TypefaceFontAssetProviderRegisterMultiple001
 * @tc.desc: Test registering multiple typefaces to same family
 * @tc.type: FUNC
 */
HWTEST_F(TypefaceFontAssetProviderTest, TypefaceFontAssetProviderRegisterMultiple001, TestSize.Level0)
{
    TypefaceFontAssetProvider provider;

    // Register multiple typefaces to same family - should only count as 1 family
    auto typeface1 = SkTypeface::MakeDefault();
    auto typeface2 = SkTypeface::MakeFromName("Arial", SkFontStyle());
    provider.RegisterTypeface(std::move(typeface1), "TestFamily");
    provider.RegisterTypeface(std::move(typeface2), "TestFamily");
    EXPECT_EQ(provider.GetFamilyCount(), 1u);
}

class TypefaceFontStyleSetTest : public testing::Test {};

/**
 * @tc.name: TypefaceFontStyleSet001
 * @tc.desc: Test TypefaceFontStyleSet count, register, and unregister operations
 * @tc.type: FUNC
 */
HWTEST_F(TypefaceFontStyleSetTest, TypefaceFontStyleSet001, TestSize.Level0)
{
    TypefaceFontStyleSet styleSet;

    // Count returns 0 for empty set
    EXPECT_EQ(styleSet.count(), 0);

    // Register nullptr does not add
    styleSet.registerTypeface(nullptr);
    EXPECT_EQ(styleSet.count(), 0);

    // Register valid typeface
    auto typeface1 = SkTypeface::MakeDefault();
    styleSet.registerTypeface(std::move(typeface1));
    EXPECT_EQ(styleSet.count(), 1);

    // Unregister all typefaces
    styleSet.unregisterTypefaces();
    EXPECT_EQ(styleSet.count(), 0);

    // Register multiple typefaces
    auto typeface2 = SkTypeface::MakeDefault();
    auto typeface3 = SkTypeface::MakeFromName("Arial", SkFontStyle());
    styleSet.registerTypeface(std::move(typeface2));
    styleSet.registerTypeface(std::move(typeface3));
    EXPECT_EQ(styleSet.count(), 2);
}

/**
 * @tc.name: TypefaceFontStyleSet002
 * @tc.desc: Test TypefaceFontStyleSet getStyle and createTypeface operations
 * @tc.type: FUNC
 */
HWTEST_F(TypefaceFontStyleSetTest, TypefaceFontStyleSet002, TestSize.Level0)
{
    TypefaceFontStyleSet styleSet;
    auto typeface = SkTypeface::MakeDefault();
    styleSet.registerTypeface(std::move(typeface));

    // getStyle with valid index
    SkFontStyle style;
    SkString name;
    styleSet.getStyle(0, &style, &name);
    EXPECT_NE(style.weight(), SkFontStyle::kInvisible_Weight);

    // getStyle with invalid index (out of bounds) - should return early
    styleSet.getStyle(10, &style, &name);

    // createTypeface with valid index
    auto result = styleSet.createTypeface(0);
    EXPECT_NE(result, nullptr);

    // createTypeface with invalid index
    EXPECT_EQ(styleSet.createTypeface(10), nullptr);
}

} // namespace txt
