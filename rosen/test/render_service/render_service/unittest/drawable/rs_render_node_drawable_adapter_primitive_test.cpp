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

#include "gtest/gtest.h"
#include "drawable/rs_render_node_drawable_adapter.h"
#include "drawable/rs_render_node_drawable.h"
#include "pipeline/rs_render_node.h"
#include "params/rs_render_params.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
class RSRenderNodeDrawableAdapterPrimitiveTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderNodeDrawableAdapterPrimitiveTest::SetUpTestCase() {}
void RSRenderNodeDrawableAdapterPrimitiveTest::TearDownTestCase() {}
void RSRenderNodeDrawableAdapterPrimitiveTest::SetUp() {}
void RSRenderNodeDrawableAdapterPrimitiveTest::TearDown() {}

class ConcreteRSRenderNodeDrawableAdapter : public DrawableV2::RSRenderNodeDrawableAdapter {
public:
    explicit ConcreteRSRenderNodeDrawableAdapter(std::shared_ptr<const RSRenderNode> node)
        : RSRenderNodeDrawableAdapter(std::move(node))
    {}
    void Draw(Drawing::Canvas& canvas) {}
};

HWTEST_F(RSRenderNodeDrawableAdapterPrimitiveTest, GetSelfPrimDirtyBitmapTest, TestSize.Level1)
{
    NodeId id = 0;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    auto selfBitmap = adapter->GetSelfPrimDirtyBitmap();
    ASSERT_NE(selfBitmap, nullptr);
    EXPECT_TRUE(selfBitmap->none());
}

HWTEST_F(RSRenderNodeDrawableAdapterPrimitiveTest, GetInfectiousPrimDirtyBitmapTest, TestSize.Level1)
{
    NodeId id = 0;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    auto infectiousBitmap = adapter->GetInfectiousPrimDirtyBitmap();
    ASSERT_NE(infectiousBitmap, nullptr);
    EXPECT_TRUE(infectiousBitmap->none());
}

HWTEST_F(RSRenderNodeDrawableAdapterPrimitiveTest, MergeInfectiousDirtyTypesWithNullptr, TestSize.Level1)
{
    NodeId id = 0;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    auto selfBitmap = adapter->GetSelfPrimDirtyBitmap();
    auto infectiousBitmap = adapter->GetInfectiousPrimDirtyBitmap();
    selfBitmap->set(static_cast<size_t>(PrimitiveDirtyType::REBUILD));
    infectiousBitmap->set(static_cast<size_t>(PrimitiveDirtyType::DIRTY));
    adapter->MergeInfectiousDirtyTypes(nullptr);
    EXPECT_TRUE(selfBitmap->test(static_cast<size_t>(PrimitiveDirtyType::REBUILD)));
    EXPECT_TRUE(infectiousBitmap->test(static_cast<size_t>(PrimitiveDirtyType::DIRTY)));
}

HWTEST_F(RSRenderNodeDrawableAdapterPrimitiveTest, MergeInfectiousDirtyTypesWithValidBitmap, TestSize.Level1)
{
    NodeId id = 0;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    auto selfBitmap = adapter->GetSelfPrimDirtyBitmap();
    auto infectiousBitmap = adapter->GetInfectiousPrimDirtyBitmap();
    selfBitmap->set(static_cast<size_t>(PrimitiveDirtyType::REBUILD));
    infectiousBitmap->set(static_cast<size_t>(PrimitiveDirtyType::DIRTY));
    PrimitiveDirtyBitmap mergeBitmap;
    mergeBitmap.set(static_cast<size_t>(PrimitiveDirtyType::MATRIX));
    mergeBitmap.set(static_cast<size_t>(PrimitiveDirtyType::CLIP));
    adapter->MergeInfectiousDirtyTypes(&mergeBitmap);
    EXPECT_TRUE(selfBitmap->test(static_cast<size_t>(PrimitiveDirtyType::REBUILD)));
    EXPECT_TRUE(selfBitmap->test(static_cast<size_t>(PrimitiveDirtyType::MATRIX)));
    EXPECT_TRUE(selfBitmap->test(static_cast<size_t>(PrimitiveDirtyType::CLIP)));
    EXPECT_TRUE(infectiousBitmap->test(static_cast<size_t>(PrimitiveDirtyType::DIRTY)));
    EXPECT_TRUE(infectiousBitmap->test(static_cast<size_t>(PrimitiveDirtyType::MATRIX)));
    EXPECT_TRUE(infectiousBitmap->test(static_cast<size_t>(PrimitiveDirtyType::CLIP)));
}

HWTEST_F(RSRenderNodeDrawableAdapterPrimitiveTest, MergeInfectiousDirtyTypesAllTypes, TestSize.Level1)
{
    NodeId id = 0;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    auto selfBitmap = adapter->GetSelfPrimDirtyBitmap();
    auto infectiousBitmap = adapter->GetInfectiousPrimDirtyBitmap();
    PrimitiveDirtyBitmap mergeBitmap;
    for (int i = 0; i < static_cast<int>(PrimitiveDirtyType::MAX); i++) {
        mergeBitmap.set(i);
    }
    adapter->MergeInfectiousDirtyTypes(&mergeBitmap);
    for (int i = 0; i < static_cast<int>(PrimitiveDirtyType::MAX); i++) {
        EXPECT_TRUE(selfBitmap->test(i));
        EXPECT_TRUE(infectiousBitmap->test(i));
    }
}

HWTEST_F(RSRenderNodeDrawableAdapterPrimitiveTest, ResetDirtyTypesTest, TestSize.Level1)
{
    NodeId id = 0;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    auto selfBitmap = adapter->GetSelfPrimDirtyBitmap();
    auto infectiousBitmap = adapter->GetInfectiousPrimDirtyBitmap();
    selfBitmap->set(static_cast<size_t>(PrimitiveDirtyType::REBUILD));
    selfBitmap->set(static_cast<size_t>(PrimitiveDirtyType::MATRIX));
    infectiousBitmap->set(static_cast<size_t>(PrimitiveDirtyType::DIRTY));
    infectiousBitmap->set(static_cast<size_t>(PrimitiveDirtyType::CLIP));
    adapter->ResetDirtyTypes();
    EXPECT_TRUE(selfBitmap->none());
    EXPECT_TRUE(infectiousBitmap->none());
}

HWTEST_F(RSRenderNodeDrawableAdapterPrimitiveTest, PrimitiveDirtyBitmapMultipleMerge, TestSize.Level1)
{
    NodeId id = 0;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node);
    auto selfBitmap = adapter->GetSelfPrimDirtyBitmap();
    auto infectiousBitmap = adapter->GetInfectiousPrimDirtyBitmap();
    PrimitiveDirtyBitmap mergeBitmap1;
    mergeBitmap1.set(static_cast<size_t>(PrimitiveDirtyType::REBUILD));
    adapter->MergeInfectiousDirtyTypes(&mergeBitmap1);
    PrimitiveDirtyBitmap mergeBitmap2;
    mergeBitmap2.set(static_cast<size_t>(PrimitiveDirtyType::MATRIX));
    adapter->MergeInfectiousDirtyTypes(&mergeBitmap2);
    EXPECT_TRUE(selfBitmap->test(static_cast<size_t>(PrimitiveDirtyType::REBUILD)));
    EXPECT_TRUE(selfBitmap->test(static_cast<size_t>(PrimitiveDirtyType::MATRIX)));
    EXPECT_TRUE(infectiousBitmap->test(static_cast<size_t>(PrimitiveDirtyType::REBUILD)));
    EXPECT_TRUE(infectiousBitmap->test(static_cast<size_t>(PrimitiveDirtyType::MATRIX)));
}

HWTEST_F(RSRenderNodeDrawableAdapterPrimitiveTest, GetSelfPrimDirtyBitmapMultipleAdapters, TestSize.Level1)
{
    NodeId id1 = 0;
    NodeId id2 = 1;
    auto node1 = std::make_shared<RSRenderNode>(id1);
    auto node2 = std::make_shared<RSRenderNode>(id2);
    auto adapter1 = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node1);
    auto adapter2 = std::make_shared<ConcreteRSRenderNodeDrawableAdapter>(node2);
    auto selfBitmap1 = adapter1->GetSelfPrimDirtyBitmap();
    auto selfBitmap2 = adapter2->GetSelfPrimDirtyBitmap();
    ASSERT_NE(selfBitmap1, nullptr);
    ASSERT_NE(selfBitmap2, nullptr);
    selfBitmap1->set(static_cast<size_t>(PrimitiveDirtyType::REBUILD));
    EXPECT_TRUE(selfBitmap1->test(static_cast<size_t>(PrimitiveDirtyType::REBUILD)));
    EXPECT_TRUE(selfBitmap2->none());
}
} // namespace OHOS::Rosen
