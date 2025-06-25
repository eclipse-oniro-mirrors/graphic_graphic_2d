/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.. All rights reserved.
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

#ifndef ROSEN_TEXT_ADAPTER_TXT_RUN_IMPL_H
#define ROSEN_TEXT_ADAPTER_TXT_RUN_IMPL_H

#include "rosen_text/run.h"
#include "txt/run.h"
#include "typography_types.h"

namespace OHOS {
namespace Rosen {
namespace AdapterTxt {
class RunImpl : public ::OHOS::Rosen::Run {
public:
    explicit RunImpl(std::unique_ptr<SPText::Run> run = nullptr);

    Drawing::Font GetFont() const override;
    size_t GetGlyphCount() const override;
    std::vector<uint16_t> GetGlyphs() const override;
    std::vector<Drawing::Point> GetPositions() override;
    std::vector<Drawing::Point> GetOffsets() override;
    std::vector<uint16_t> GetGlyphs(int64_t start, int64_t length) const override;
    std::vector<Drawing::Point> GetPositions(int64_t start, int64_t length) const override;
    std::vector<Drawing::Point> GetAdvances(uint32_t start, uint32_t length) const override;
    TextDirection GetTextDirection() const override;
    void GetStringRange(uint64_t* location, uint64_t* length) const override;
    std::vector<uint64_t> GetStringIndices(int64_t start, int64_t length) const override;
    Drawing::Rect GetImageBounds() const override;
    float GetTypographicBounds(float* ascent, float* descent, float* leading) const override;
    void Paint(Drawing::Canvas *canvas, double x, double y) override;

    void SetSpRunBase(std::unique_ptr<SPText::Run>& run) { run_ = std::move(run); }

private:
    std::unique_ptr<SPText::Run> run_ = nullptr;
};
} // namespace AdapterTxt
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_TEXT_ADAPTER_TXT_RUN_IMPL_H
