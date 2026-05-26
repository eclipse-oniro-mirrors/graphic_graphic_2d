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

#include "gtest/gtest.h"
#include "drawable/rs_drawable.h"
#include "drawable/rs_property_drawable_background.h"
#include "drawable/rs_property_drawable_foreground.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSDrawablePrimitiveTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSDrawablePrimitiveTest::SetUpTestCase() {}
void RSDrawablePrimitiveTest::TearDownTestCase() {}
void RSDrawablePrimitiveTest::SetUp() {}
void RSDrawablePrimitiveTest::TearDown() {}

#ifdef USE_PRIMITIVE
class TestDrawableWithPrimList : public RSDrawable {
public:
    TestDrawableWithPrimList() = default;
    ~TestDrawableWithPrimList() override = default;

    void OnDraw(Drawing::Canvas* canvas, const Drawing::Rect* rect) const override {}
    void OnSync() override {}

    bool UsePrimList() const override
    {
        return true;
    }
};

class TestDrawableWithoutPrimList : public RSDrawable {
public:
    TestDrawableWithoutPrimList() = default;
    ~TestDrawableWithoutPrimList() override = default;

    void OnDraw(Drawing::Canvas* canvas, const Drawing::Rect* rect) const override {}
    void OnSync() override {}
};

HWTEST_F(RSDrawablePrimitiveTest, UsePrimListOverrideTest001, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSDynamicLightUpDrawable>(1.0f, 1.0f);
    ASSERT_NE(drawable, nullptr);
    EXPECT_TRUE(drawable->UsePrimList());
}

HWTEST_F(RSDrawablePrimitiveTest, UsePrimListOverrideTest002, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSForegroundColorDrawable>();
    ASSERT_NE(drawable, nullptr);
    EXPECT_TRUE(drawable->UsePrimList());
}

HWTEST_F(RSDrawablePrimitiveTest, UsePrimListOverrideTest003, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSBorderDrawable>();
    ASSERT_NE(drawable, nullptr);
    EXPECT_TRUE(drawable->UsePrimList());
}

HWTEST_F(RSDrawablePrimitiveTest, UsePrimListOverrideTest004, TestSize.Level1)
{
    auto drawable = std::make_shared<DrawableV2::RSOutlineDrawable>();
    ASSERT_NE(drawable, nullptr);
    EXPECT_TRUE(drawable->UsePrimList());
}

HWTEST_F(RSDrawablePrimitiveTest, UsePrimListOverrideTest005, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithPrimList>();
    ASSERT_NE(drawable, nullptr);
    EXPECT_TRUE(drawable->UsePrimList());
}

HWTEST_F(RSDrawablePrimitiveTest, UsePrimListOverrideTest006, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithoutPrimList>();
    ASSERT_NE(drawable, nullptr);
    EXPECT_FALSE(drawable->UsePrimList());
}

HWTEST_F(RSDrawablePrimitiveTest, SetDirtyTest001, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithPrimList>();
    ASSERT_NE(drawable, nullptr);
    EXPECT_TRUE(drawable->stagingIsDirty_);

    drawable->stagingIsDirty_ = false;
    drawable->SetDirty();
    EXPECT_TRUE(drawable->stagingIsDirty_);
}

HWTEST_F(RSDrawablePrimitiveTest, OnPrimitiveSyncTest001, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithPrimList>();
    ASSERT_NE(drawable, nullptr);

    drawable->stagingIsDirty_ = true;
    drawable->isDirty_ = false;

    drawable->OnPrimitiveSync();

    EXPECT_TRUE(drawable->isDirty_);
    EXPECT_FALSE(drawable->stagingIsDirty_);
}

HWTEST_F(RSDrawablePrimitiveTest, OnPrimitiveSyncTest002, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithPrimList>();
    ASSERT_NE(drawable, nullptr);

    drawable->stagingIsDirty_ = true;
    drawable->isDirty_ = true;

    drawable->OnPrimitiveSync();

    EXPECT_TRUE(drawable->isDirty_);
    EXPECT_FALSE(drawable->stagingIsDirty_);
}

HWTEST_F(RSDrawablePrimitiveTest, OnPrimitiveSyncTest003, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithPrimList>();
    ASSERT_NE(drawable, nullptr);

    drawable->stagingIsDirty_ = false;
    drawable->isDirty_ = false;

    drawable->OnPrimitiveSync();

    EXPECT_FALSE(drawable->isDirty_);
    EXPECT_FALSE(drawable->stagingIsDirty_);
}

HWTEST_F(RSDrawablePrimitiveTest, OnPrimitiveSyncTest004, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithPrimList>();
    ASSERT_NE(drawable, nullptr);

    drawable->stagingIsDirty_ = false;
    drawable->isDirty_ = true;

    drawable->OnPrimitiveSync();

    EXPECT_TRUE(drawable->isDirty_);
    EXPECT_FALSE(drawable->stagingIsDirty_);
}

HWTEST_F(RSDrawablePrimitiveTest, OnDrawPrimitiveFallbackTest001, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithoutPrimList>();
    ASSERT_NE(drawable, nullptr);

    Drawing::Canvas canvas;
    Drawing::Rect rect(0, 0, 100, 100);

    drawable->OnDrawPrimitive(&canvas, &rect);
    EXPECT_TRUE(true);
}

HWTEST_F(RSDrawablePrimitiveTest, PrimListDirtyFlagTest001, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithPrimList>();
    ASSERT_NE(drawable, nullptr);

    EXPECT_EQ(drawable->primList_, nullptr);
    EXPECT_TRUE(drawable->stagingIsDirty_);
    EXPECT_FALSE(drawable->isDirty_);
}

HWTEST_F(RSDrawablePrimitiveTest, PrimListDirtyFlagTest002, TestSize.Level1)
{
    auto drawable = std::make_shared<TestDrawableWithPrimList>();
    ASSERT_NE(drawable, nullptr);

    EXPECT_TRUE(drawable->stagingIsDirty_);
    EXPECT_FALSE(drawable->isDirty_);

    drawable->OnPrimitiveSync();

    EXPECT_TRUE(drawable->isDirty_);
    EXPECT_FALSE(drawable->stagingIsDirty_);

    drawable->stagingIsDirty_ = true;
    EXPECT_TRUE(drawable->stagingIsDirty_);

    drawable->SetDirty();
    EXPECT_TRUE(drawable->stagingIsDirty_);
}
#endif
} // namespace OHOS::Rosen
