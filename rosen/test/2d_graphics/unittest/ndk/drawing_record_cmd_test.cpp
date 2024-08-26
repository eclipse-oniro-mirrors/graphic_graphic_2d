/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gtest/gtest.h"

#include "drawing_bitmap.h"
#include "drawing_brush.h"
#include "drawing_canvas.h"
#include "drawing_color.h"
#include "drawing_color_filter.h"
#include "drawing_error_code.h"
#include "drawing_filter.h"
#include "drawing_font.h"
#include "drawing_image.h"
#include "drawing_image_filter.h"
#include "drawing_mask_filter.h"
#include "drawing_matrix.h"
#include "drawing_path.h"
#include "drawing_pen.h"
#include "drawing_pixel_map.h"
#include "drawing_point.h"
#include "drawing_rect.h"
#include "drawing_region.h"
#include "drawing_round_rect.h"
#include "drawing_sampling_options.h"
#include "drawing_shader_effect.h"
#include "drawing_text_blob.h"
#include "drawing_typeface.h"
#include "drawing_memory_stream.h"
#include "effect/color_filter.h"
#include "effect/filter.h"
#include "recording/recording_canvas.h"
#include "drawing_record_cmd.h"
#include "image/pixelmap_native.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class NativeDrawingRecordCmdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
protected:
    OH_Drawing_Canvas *canvas_ = nullptr;
    OH_Drawing_Brush *brush_ = nullptr;
};

void NativeDrawingRecordCmdTest::SetUpTestCase() {}
void NativeDrawingRecordCmdTest::TearDownTestCase() {}
void NativeDrawingRecordCmdTest::SetUp()
{
    canvas_ = OH_Drawing_CanvasCreate();
    ASSERT_NE(nullptr, canvas_);
    OH_Drawing_CanvasClear(canvas_, OH_Drawing_ColorSetArgb(0xFF, 0xFF, 0xFF, 0xFF));
    brush_ = OH_Drawing_BrushCreate();
    EXPECT_NE(brush_, nullptr);
    OH_Drawing_BrushSetColor(brush_, 0xffff0000);
    OH_Drawing_CanvasAttachBrush(canvas_, brush_);
}

void NativeDrawingRecordCmdTest::TearDown()
{
    if (canvas_ != nullptr) {
        OH_Drawing_CanvasDetachBrush(canvas_);
        OH_Drawing_BrushDestroy(brush_);
        brush_ = nullptr;
        OH_Drawing_CanvasDestroy(canvas_);
        canvas_ = nullptr;
    }
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsCreate
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsCreate, TestSize.Level1)
{
    OH_Drawing_RecordCmdUtils* recordCmdUtils = OH_Drawing_RecordCmdUtilsCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
    recordCmdUtils = nullptr;
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsBeginRecording001
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsBeginRecording001, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = 10;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = nullptr;
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsBeginRecording002
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsBeginRecording002, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = 10;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = OH_Drawing_RecordCmdUtilsCreate();
    OH_Drawing_Canvas** canvas = nullptr;
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, canvas);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsBeginRecording003
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsBeginRecording003, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = 10;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = nullptr;
    OH_Drawing_Canvas** canvas = nullptr;
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, canvas);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsBeginRecording004
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsBeginRecording004, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = 10;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = OH_Drawing_RecordCmdUtilsCreate();
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsBeginRecording005
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsBeginRecording005, TestSize.Level1)
{
    int32_t width = -1;
    int32_t height = 10;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = OH_Drawing_RecordCmdUtilsCreate();
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsBeginRecording006
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsBeginRecording006, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = -1;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = OH_Drawing_RecordCmdUtilsCreate();
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsBeginRecording007
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsBeginRecording007, TestSize.Level1)
{
    int32_t width = -1;
    int32_t height = -1;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = OH_Drawing_RecordCmdUtilsCreate();
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsFinishRecording001
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsFinishRecording001, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = 10;
    OH_Drawing_RecordCmd** recordCmd = nullptr;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = OH_Drawing_RecordCmdUtilsCreate();
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    code = OH_Drawing_RecordCmdUtilsFinishRecording(recordCmdUtils, recordCmd);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsFinishRecording002
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsFinishRecording002, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = 10;
    OH_Drawing_RecordCmd* recordCmd = nullptr;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = nullptr;
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    code = OH_Drawing_RecordCmdUtilsFinishRecording(recordCmdUtils, &recordCmd);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    code = OH_Drawing_RecordCmdDestroy(recordCmd);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsFinishRecording003
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsFinishRecording003, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = 10;
    OH_Drawing_RecordCmd** recordCmd = nullptr;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = nullptr;
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    code = OH_Drawing_RecordCmdUtilsFinishRecording(recordCmdUtils, recordCmd);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    EXPECT_EQ(code, OH_DRAWING_ERROR_INVALID_PARAMETER);
}

/*
 * @tc.name: NativeRecordCmdTest_RecordCmdUtilsFinishRecording004
 * @tc.desc: test for OH_Drawing_Record.
 * @tc.type: FUNC
 * @tc.require: AR000GTO5R
 */
HWTEST_F(NativeDrawingRecordCmdTest, NativeRecordCmdTest_RecordCmdUtilsFinishRecording004, TestSize.Level1)
{
    int32_t width = 10;
    int32_t height = 10;
    OH_Drawing_RecordCmd* recordCmd = nullptr;
    OH_Drawing_RecordCmdUtils* recordCmdUtils = OH_Drawing_RecordCmdUtilsCreate();
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_ErrorCode code = OH_Drawing_RecordCmdUtilsBeginRecording(recordCmdUtils, width, height, &canvas);
    code = OH_Drawing_RecordCmdUtilsFinishRecording(recordCmdUtils, &recordCmd);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
    code = OH_Drawing_RecordCmdUtilsDestroy(recordCmdUtils);
    code = OH_Drawing_RecordCmdDestroy(recordCmd);
    EXPECT_EQ(code, OH_DRAWING_SUCCESS);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
