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
#ifndef ROSEN_MODULES_SPTEXT_PARAGRAPH_IMPL_H
#define ROSEN_MODULES_SPTEXT_PARAGRAPH_IMPL_H

#include <memory>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <vector>

#include "modules/skparagraph/include/Paragraph.h"
#include "modules/skparagraph/include/DartTypes.h"
#include "symbol_engine/hm_symbol_run.h"
#include "txt/paint_record.h"
#include "txt/paragraph.h"
#include "txt/paragraph_style.h"
#include "txt/text_style.h"

#ifdef USE_M133_SKIA
#include "include/private/base/SkTArray.h"
#else
#include "include/private/SkTArray.h"
#endif

namespace OHOS {
namespace Rosen {
namespace SPText {
namespace skt = skia::textlayout;
class ParagraphImpl : public Paragraph {
public:
    ParagraphImpl(std::unique_ptr<skt::Paragraph> paragraph, std::vector<PaintRecord>&& paints);

    virtual ~ParagraphImpl() = default;

    double GetMaxWidth() override;

    double GetHeight() override;

    double GetLongestLine() override;

    double GetLongestLineWithIndent() override;

    double GetMinIntrinsicWidth() override;

    double GetMaxIntrinsicWidth() override;

    double GetAlphabeticBaseline() override;

    double GetIdeographicBaseline() override;

    double GetGlyphsBoundsTop() override;

    double GetGlyphsBoundsBottom() override;

    double GetGlyphsBoundsLeft() override;

    double GetGlyphsBoundsRight() override;

    bool DidExceedMaxLines() override;

    size_t GetLineCount() const override;

    void SetIndents(const std::vector<float>& indents) override;

    void MarkDirty() override;

    int32_t GetUnresolvedGlyphsCount() override;

    void UpdateFontSize(size_t from, size_t to, float fontSize) override;

    float DetectIndents(size_t index) override;

    void Layout(double width) override;

    void Paint(SkCanvas* canvas, double x, double y) override;

    void Paint(Drawing::Canvas* canvas, double x, double y) override;

    void Paint(Drawing::Canvas* canvas, Drawing::Path* path, double hOffset, double vOffset) override;

    std::vector<TextBox> GetRectsForRange(size_t start, size_t end,
        RectHeightStyle rectHeightStyle, RectWidthStyle rectWidthStyle) override;

    std::vector<TextBox> GetRectsForPlaceholders() override;

    PositionWithAffinity GetGlyphPositionAtCoordinate(double dx, double dy) override;

    Range<size_t> GetWordBoundary(size_t offset) override;

    Range<size_t> GetActualTextRange(int lineNumber, bool includeSpaces) override;

    Range<size_t> GetEllipsisTextRange() override;

    std::vector<skt::LineMetrics> GetLineMetrics() override;

    bool GetLineMetricsAt(int lineNumber, skt::LineMetrics* lineMetrics) const override;

    void SetAnimation(
        std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)>& animationFunc
    ) override
    {
        if (animationFunc != nullptr) {
            animationFunc_ = animationFunc;
        }
    }
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> GetAnimation() override
    {
        return animationFunc_;
    }

    void SetParagraghId(uint32_t id) override
    {
        id_ = id;
    }

    Drawing::FontMetrics MeasureText() override;

    Drawing::FontMetrics GetFontMetricsResult(const SPText::TextStyle& textStyle) override;

    bool GetLineFontMetrics(const size_t lineNumber, size_t& charNumber,
        std::vector<Drawing::FontMetrics>& fontMetrics) override;
    std::vector<std::unique_ptr<SPText::TextLineBase>> GetTextLines() const override;
    std::unique_ptr<Paragraph> CloneSelf() override;
    TextStyle SkStyleToTextStyle(const skt::TextStyle& skStyle) override;
    void UpdateColor(size_t from, size_t to, const RSColor& color,
        skia::textlayout::UtfEncodeType encodeType) override;
    Drawing::RectI GeneratePaintRegion(double x, double y) override;
    void UpdateForegroundBrush(const TextStyle& spTextStyle) override;

    void Relayout(double width, const ParagraphStyle& paragraphStyle,
        const std::vector<OHOS::Rosen::SPText::TextStyle>& textStyles) override;

    bool IsLayoutDone() override;

    void SetLayoutState(size_t state) override;

    void ApplyTextStyleChanges(const std::vector<OHOS::Rosen::SPText::TextStyle>& textStyles) override;

    std::vector<TextBlobRecordInfo> GetTextBlobRecordInfo() const override;

    bool HasSkipTextBlobDrawing() const override;

    void SetSkipTextBlobDrawing(bool state) override;

    bool isRunCombinated() { return paragraph_->isRunCombinated(); }

    bool CanPaintAllText() const override;

    std::string_view GetDumpInfo() override;

private:
    void ParagraphStyleUpdater(skt::Paragraph& skiaParagraph, const ParagraphStyle& spParagraphStyle,
        skt::InternalState& state);

    void TextStyleUpdater(skt::Block& skiaBlock, const TextStyle& spTextStyle, skt::InternalState& state);

    void SymbolStyleUpdater(const HMSymbolTxt& symbolStyle, std::vector<std::shared_ptr<HMSymbolRun>>& hmSymbolRuns,
        skt::InternalState& state);

    void GetExtraTextStyleAttributes(const skt::TextStyle& skStyle, TextStyle& txt);

    void ApplyParagraphStyleChanges(const ParagraphStyle& style);
#ifdef USE_M133_SKIA
    void UpdateForegroundBrushWithValidData(skia_private::TArray<skt::Block, true>& skiaTextStyles,
        const std::optional<RSBrush>& brush);
    void UpdateForegroundBrushWithNullopt(skia_private::TArray<skt::Block, true>& skiaTextStyles);
#else
    void UpdateForegroundBrushWithValidData(SkTArray<skt::Block, true>& skiaTextStyles,
        const std::optional<RSBrush>& brush);
    void UpdateForegroundBrushWithNullopt(SkTArray<skt::Block, true>& skiaTextStyles);
#endif
    void UpdatePaintsBySkiaBlock(skt::Block& skiaBlock, const std::optional<RSBrush>& brush);

    void RecordDifferentPthreadCall(const char* caller) const;

    void InitSymbolRuns();

    void UpdateSymbolRun(const HMSymbolTxt& symbolStyle, std::shared_ptr<HMSymbolRun>& hmSymbolRun,
        skt::InternalState& state, size_t index);

    std::unique_ptr<skt::Paragraph> paragraph_;
    std::vector<PaintRecord> paints_;
    std::optional<std::vector<LineMetrics>> lineMetrics_;
    std::vector<TextStyle> lineMetricsStyles_;
    std::function<bool(
        const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)> animationFunc_ = nullptr;
    uint32_t id_ = 0;
    mutable pthread_t threadId_;
    std::vector<std::shared_ptr<HMSymbolRun>> hmSymbols_;
    std::once_flag initSymbolRunsFlag_;
};
} // namespace SPText
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_MODULES_SPTEXT_PARAGRAPH_IMPL_H
