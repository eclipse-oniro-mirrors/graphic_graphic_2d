/*
 * Test Scope: Align with RSLayerCmdProperty API (Set/Get/Clone/RSRenderLayerProperty bridge)
 */

#include <gtest/gtest.h>
#include "rs_layer_cmd_property.h"

using namespace OHOS;
using namespace OHOS::Rosen;
using namespace testing;
using namespace testing::ext;
class RSLayerCmdPropertyTest : public Test {};

/*
 * Test: SetGet_And_Clone_Basic
 * Purpose: Validate Set/Get and Clone keep the same value and are independent.
 */
HWTEST(RSLayerCmdPropertyTest, SetGet_And_Clone_Basic, TestSize.Level1)
{
    RSLayerCmdProperty<int> prop(10);
    EXPECT_EQ(prop.Get(), 10);
    prop.Set(20);
    EXPECT_EQ(prop.Get(), 20);

    auto cloned = std::static_pointer_cast<RSLayerCmdProperty<int>>(prop.Clone());
    ASSERT_NE(cloned, nullptr);
    EXPECT_EQ(cloned->Get(), 20);

    prop.Set(30);
    EXPECT_EQ(prop.Get(), 30);
    // clone should not change with original
    EXPECT_EQ(cloned->Get(), 20);
}

/*
 * Test: Bridge_To_RSRenderLayerProperty_Marshalling
 * Purpose: Verify GetRSRenderLayerProperty() returns a marshallable property with same value.
 */
HWTEST(RSLayerCmdPropertyTest, Bridge_To_RSRenderLayerProperty_Marshalling, TestSize.Level1)
{
    GraphicIRect rect {1, 2, 3, 4};
    RSLayerCmdProperty<GraphicIRect> prop(rect);
    auto rsRenderPropBase = prop.GetRSRenderLayerProperty();
    ASSERT_NE(rsRenderPropBase, nullptr);

    auto rsRenderProp = std::static_pointer_cast<RSRenderLayerCmdProperty<GraphicIRect>>(rsRenderPropBase);
    ASSERT_NE(rsRenderProp, nullptr);

    MessageParcel parcel;
    ASSERT_TRUE(rsRenderProp->OnMarshalling(parcel, rsRenderProp->Get()));

    std::shared_ptr<RSRenderLayerCmdProperty<GraphicIRect>> out;
    ASSERT_TRUE(rsRenderProp->OnUnmarshalling(parcel, out));
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(out->Get().x, 1);
    EXPECT_EQ(out->Get().y, 2);
    EXPECT_EQ(out->Get().w, 3);
    EXPECT_EQ(out->Get().h, 4);
}
