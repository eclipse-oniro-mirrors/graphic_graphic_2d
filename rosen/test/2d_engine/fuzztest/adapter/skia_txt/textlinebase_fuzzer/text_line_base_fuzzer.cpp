/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "text_line_base_fuzzer.h"
#include <cstddef>
#include "get_object.h"
#include "text_line_base.h"
#include "typography.h"
#include "typography_create.h"
namespace OHOS {
namespace Rosen {
namespace Drawing {
void OHTextLineBaseFuzz1(const uint8_t* data, size_t size)
{
    TypographyStyle typographyStyle;
    typographyStyle.maxLines = GetObject<int>();
    std::shared_ptr<OHOS::Rosen::FontCollection> fontCollection =
        OHOS::Rosen::FontCollection::From(std::make_shared<txt::FontCollection>());
    std::shared_ptr<TypographyCreate> typographyCreate = TypographyCreate::Create(typographyStyle, fontCollection);
    typographyCreate->AppendText(u"Hello World!");
    std::unique_ptr<Typography> typography_ = typographyCreate->CreateTypography();
    typography_->Layout(GetObject<int>());
    std::vector<std::unique_ptr<TextLineBase>> textLine_ = typography_->GetTextLines();

    textLine_.at(0)->GetGlyphCount();
    textLine_.at(0)->GetTextRange();
    Drawing::Canvas canvas;
    textLine_.at(0)->Paint(&canvas, GetObject<double>(), GetObject<double>());
    textLine_.at(0)->GetGlyphRuns();
    std::string ellipsisStr;
    EllipsisModal myEllipsisModal = OHOS::Rosen::EllipsisModal(GetObject<int>() % DATA_MAX_ENUM_SIZE1);
    textLine_.at(0)->CreateTruncatedLine(GetObject<double>(), static_cast<OHOS::Rosen::EllipsisModal>(-1), ellipsisStr);
    textLine_.at(0)->CreateTruncatedLine(GetObject<double>(), myEllipsisModal, ellipsisStr);
    double ascent = GetObject<double>();
    double descent = GetObject<double>();
    double leading = GetObject<double>();
    textLine_.at(0)->GetTypographicBounds(&ascent, &descent, &leading);
    textLine_.at(0)->GetImageBounds();
    textLine_.at(0)->GetTrailingSpaceWidth();
    textLine_.at(0)->GetImageBounds();
    bool isHardBreak = GetObject<bool>();
    textLine_.at(0)->GetIndexAndOffsets(isHardBreak);
    textLine_.at(0)->GetOffsetForStringIndex(GetObject<int32_t>());

    typography_.reset();
    textLine_.clear();
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Rosen::Drawing::OHTextLineBaseFuzz1(data, size);
    return 0;
}
