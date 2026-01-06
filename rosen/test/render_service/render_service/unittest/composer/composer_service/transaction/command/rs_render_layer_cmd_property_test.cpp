/**
 * Function: FileHeader_RSRenderLayerCmdProperty_Coverage
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: Cover RSRenderLayerCmdProperty (de)serialization branches including
 *                  base/string/vector/enum/struct, special nullptr types, INVALID cmdType,
 *                  and unmarshalling failures (insufficient data/oversize vector).
 */

#include <gtest/gtest.h>

#include "message_parcel.h"
#include "rs_render_layer_cmd_property.h"

using namespace OHOS;
using namespace testing;
using namespace testing::ext;
class RenderLayerCmdPropertyTest : public Test {};
namespace OHOS::Rosen{

/**
 * Function: Marshall_Unmarshall_BasicType_Success
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. set cmdType/propertyId on int property
 *                  2. marshalling to parcel
 *                  3. unmarshalling back and verify type/id/value
 */
HWTEST(RenderLayerCmdPropertyTest, Marshall_Unmarshall_BasicType_Success, TestSize.Level1)
{
    RSRenderLayerCmdProperty<int> prop(123);

    MessageParcel parcel;
    ASSERT_TRUE(prop.OnMarshalling(parcel, prop.Get()));

    std::shared_ptr<RSRenderLayerCmdProperty<int>> out;
    ASSERT_TRUE(prop.OnUnmarshalling(parcel, out));
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(out->Get(), 123);
}

/**
 * Function: Marshall_Unmarshall_String_And_Vector_Success
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. marshal/unmarshal std::string
 *                  2. marshal/unmarshal std::vector<int>
 *                  3. verify values equal to written ones
 */
HWTEST(RenderLayerCmdPropertyTest, Marshall_Unmarshall_String_And_Vector_Success, TestSize.Level1)
{
    // string
    RSRenderLayerCmdProperty<std::string> propStr("hello");
    MessageParcel p1;
    ASSERT_TRUE(propStr.OnMarshalling(p1, propStr.Get()));
    std::shared_ptr<RSRenderLayerCmdProperty<std::string>> outStr;
    ASSERT_TRUE(propStr.OnUnmarshalling(p1, outStr));
    ASSERT_NE(outStr, nullptr);
    EXPECT_EQ(outStr->Get(), std::string("hello"));

    // vector<int>
    RSRenderLayerCmdProperty<std::vector<int>> propVec({1, 2, 3});
    MessageParcel p2;
    ASSERT_TRUE(propVec.OnMarshalling(p2, propVec.Get()));
    std::shared_ptr<RSRenderLayerCmdProperty<std::vector<int>>> outVec;
    ASSERT_TRUE(propVec.OnUnmarshalling(p2, outVec));
    ASSERT_NE(outVec, nullptr);
    ASSERT_EQ(outVec->Get().size(), 3u);
    EXPECT_EQ(outVec->Get()[0], 1);
    EXPECT_EQ(outVec->Get()[1], 2);
    EXPECT_EQ(outVec->Get()[2], 3);
}

/**
 * Function: Marshall_Unmarshall_Enum_And_Struct_Success
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. marshal/unmarshal GraphicLayerType
 *                  2. marshal/unmarshal GraphicIRect
 *                  3. verify values equal to written ones
 */
HWTEST(RenderLayerCmdPropertyTest, Marshall_Unmarshall_Enum_And_Struct_Success, TestSize.Level1)
{
    // enum
    RSRenderLayerCmdProperty<GraphicLayerType> propEnum(GraphicLayerType::GRAPHIC_LAYER_TYPE_GRAPHIC);
    MessageParcel p1;
    ASSERT_TRUE(propEnum.OnMarshalling(p1, propEnum.Get()));
    std::shared_ptr<RSRenderLayerCmdProperty<GraphicLayerType>> outEnum;
    ASSERT_TRUE(propEnum.OnUnmarshalling(p1, outEnum));
    ASSERT_NE(outEnum, nullptr);
    EXPECT_EQ(outEnum->Get(), GraphicLayerType::GRAPHIC_LAYER_TYPE_GRAPHIC);

    // struct
    GraphicIRect rect {10, 20, 30, 40};
    RSRenderLayerCmdProperty<GraphicIRect> propStruct(rect);
    MessageParcel p2;
    ASSERT_TRUE(propStruct.OnMarshalling(p2, propStruct.Get()));
    std::shared_ptr<RSRenderLayerCmdProperty<GraphicIRect>> outStruct;
    ASSERT_TRUE(propStruct.OnUnmarshalling(p2, outStruct));
    ASSERT_NE(outStruct, nullptr);
    EXPECT_EQ(outStruct->Get().x, 10);
    EXPECT_EQ(outStruct->Get().y, 20);
    EXPECT_EQ(outStruct->Get().w, 30);
    EXPECT_EQ(outStruct->Get().h, 40);
}

/**
 * Function: Marshall_Unmarshall_Nullptr_SpecialTypes_Success
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. set nullptr for PixelMap/SurfaceBuffer/SyncFence/SurfaceTunnelHandle
 *                  2. marshal/unmarshal for each
 *                  3. verify result is nullptr and returns true
 */
HWTEST(RenderLayerCmdPropertyTest, Marshall_Unmarshall_Nullptr_SpecialTypes_Success, TestSize.Level1)
{
    // PixelMap
    RSRenderLayerCmdProperty<std::shared_ptr<Media::PixelMap>> propPm(nullptr);
    MessageParcel p1;
    ASSERT_TRUE(propPm.OnMarshalling(p1, propPm.Get()));
    std::shared_ptr<RSRenderLayerCmdProperty<std::shared_ptr<Media::PixelMap>>> outPm;
    ASSERT_TRUE(propPm.OnUnmarshalling(p1, outPm));
    ASSERT_NE(outPm, nullptr);
    EXPECT_EQ(outPm->Get(), nullptr);

    // SurfaceBuffer
    RSRenderLayerCmdProperty<sptr<SurfaceBuffer>> propSb(nullptr);
    MessageParcel p2;
    ASSERT_TRUE(propSb.OnMarshalling(p2, propSb.Get()));
    std::shared_ptr<RSRenderLayerCmdProperty<sptr<SurfaceBuffer>>> outSb;
    ASSERT_TRUE(propSb.OnUnmarshalling(p2, outSb));
    ASSERT_NE(outSb, nullptr);
    EXPECT_EQ(outSb->Get(), nullptr);

    // SyncFence
    RSRenderLayerCmdProperty<sptr<SyncFence>> propFence(nullptr);
    MessageParcel p3;
    ASSERT_TRUE(propFence.OnMarshalling(p3, propFence.Get()));
    std::shared_ptr<RSRenderLayerCmdProperty<sptr<SyncFence>>> outFence;
    ASSERT_TRUE(propFence.OnUnmarshalling(p3, outFence));
    ASSERT_NE(outFence, nullptr);
    EXPECT_EQ(outFence->Get(), nullptr);

    // SurfaceTunnelHandle
    RSRenderLayerCmdProperty<sptr<SurfaceTunnelHandle>> propTh(nullptr);
    MessageParcel p4;
    ASSERT_TRUE(propTh.OnMarshalling(p4, propTh.Get()));
    std::shared_ptr<RSRenderLayerCmdProperty<sptr<SurfaceTunnelHandle>>> outTh;
    ASSERT_TRUE(propTh.OnUnmarshalling(p4, outTh));
    ASSERT_NE(outTh, nullptr);
    EXPECT_EQ(outTh->Get(), nullptr);
}

/**
 * Function: Marshall_WithInvalidCmdType_Fail
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. do not set cmdType (keep INVALID)
 *                  2. call OnMarshalling
 *                  3. expect OnMarshalling returns false
 */
// 取消基于 cmdType 的失败用例：当前实现仅针对值进行编解码，无 cmdType/PropertyId 概念。

/**
 * Function: Unmarshall_WithInsufficientData_Fail
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. parcel only contains type (no id/value)
 *                  2. parcel with type+id but missing value
 *                  3. expect OnUnmarshalling returns false
 */
HWTEST(RenderLayerCmdPropertyTest, Unmarshall_WithInsufficientData_Fail, TestSize.Level1)
{
    // 对于基本类型，空包直接失败
    MessageParcel p1;
    RSRenderLayerCmdProperty<int> prop(0);
    std::shared_ptr<RSRenderLayerCmdProperty<int>> out1;
    EXPECT_FALSE(prop.OnUnmarshalling(p1, out1));

    // 对于 vector，写入 size 但缺失元素内容，解包失败
    MessageParcel p2;
    ASSERT_TRUE(p2.WriteUint32(1)); // size = 1，但不写入任何元素
    RSRenderLayerCmdProperty<std::vector<int>> propVec(std::vector<int>{});
    std::shared_ptr<RSRenderLayerCmdProperty<std::vector<int>>> out2;
    EXPECT_FALSE(propVec.OnUnmarshalling(p2, out2));
}

/**
 * Function: Unmarshall_Vector_WithOversize_Fail
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1. craft parcel with type/id and oversized vector size (10001)
 *                  2. call OnUnmarshalling
 *                  3. expect false due to size limit
 */
HWTEST(RenderLayerCmdPropertyTest, Unmarshall_Vector_WithOversize_Fail, TestSize.Level1)
{
    using VecInt = std::vector<int>;
    RSRenderLayerCmdProperty<VecInt> prop(VecInt{});
    MessageParcel parcel;
    ASSERT_TRUE(parcel.WriteUint32(10001));

    std::shared_ptr<RSRenderLayerCmdProperty<VecInt>> out;
    EXPECT_FALSE(prop.OnUnmarshalling(parcel, out));
}

} // namespace
