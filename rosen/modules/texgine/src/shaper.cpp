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

#include "shaper.h"

#include <queue>
#include <variant>

#include "bidi_processer.h"
#include "line_breaker.h"
#include "measurer.h"
#include "texgine/any_span.h"
#include "texgine_exception.h"
#include "texgine/utils/exlog.h"
#ifdef LOGGER_ENABLE_SCOPE
#include "texgine/utils/trace.h"
#endif
#include "text_breaker.h"
#include "text_merger.h"
#include "text_reverser.h"
#include "text_shaper.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
#define MAXWIDTH 1e9
namespace {
void DumpLineMetrics(const std::vector<LineMetrics> &lineMetrics)
{
    LOGSCOPED(sl, LOGEX_FUNC_LINE_DEBUG(), "DumpLineMetrics");
    for (const auto &metric : lineMetrics) {
        for (const auto &span : metric.lineSpans) {
            span.Dump();
        }
    }
}
} // namespace

bool Shaper::DidExceedMaxLines() const
{
    return didExceedMaxLines_;
}

double Shaper::GetMinIntrinsicWidth() const
{
    return minIntrinsicWidth_;
}

double Shaper::GetMaxIntrinsicWidth() const
{
    return maxIntrinsicWidth_;
}

void Shaper::SetIndents(const std::vector<float> &indents)
{
    indents_ = indents;
}

std::vector<LineMetrics> Shaper::CreateEllipsisSpan(const TypographyStyle &ys, const TextStyle &textStyle,
    const std::shared_ptr<FontProviders> &fontProviders)
{
    if (ys.ellipsis.empty()) {
        return {};
    }

    TextStyle xs;
    xs.fontSize = textStyle.fontSize;
    xs.fontFamilies = textStyle.fontFamilies;

    std::vector<VariantSpan> spans = {TextSpan::MakeFromText(ys.ellipsis)};
    for (auto &span : spans) {
        span.SetTextStyle(xs);
    }
    auto ys2 = ys;
    ys2.wordBreakType = WordBreakType::BREAK_ALL;
    ys2.breakStrategy = BreakStrategy::GREEDY;
    return DoShapeBeforeEllipsis(spans, ys2, fontProviders, MAXWIDTH);
}

void Shaper::ConsiderEllipsis(const TypographyStyle &tstyle,
    const std::shared_ptr<FontProviders> &fontProviders, const double widthLimit)
{
    didExceedMaxLines_ = false;
    auto maxLines = tstyle.maxLines;
    if (maxLines < 0) {
        maxLines = 1;
    }

    if (lineMetrics_.size() <= maxLines) {
        return;
    }

    auto &textStyle = lineMetrics_.back().lineSpans.back().GetTextStyle();
    std::vector<LineMetrics> ellipsisMertics = CreateEllipsisSpan(tstyle, textStyle, fontProviders);
    double ellipsisWidth = 0.0;
    std::vector<VariantSpan> ellipsisSpans;
    for (auto &metric : ellipsisMertics) {
        for (auto &es : metric.lineSpans) {
            ellipsisWidth += es.GetWidth();
            ellipsisSpans.push_back(es);
        }
    }

    EllipsisParams params{ellipsisSpans, ellipsisWidth, maxLines, widthLimit};
    if (maxLines == 1) { // single line
        switch (tstyle.ellipsisModal) {
            case EllipsisModal::HEAD:
                params.widthLimit -= lineMetrics_.front().indent;
                ConsiderHeadEllipsis(tstyle, fontProviders, params);
                break;
            case EllipsisModal::MIDDLE:
                params.widthLimit -= lineMetrics_.front().indent;
                ConsiderMiddleEllipsis(tstyle, fontProviders, params);
                break;
            case EllipsisModal::TAIL:
            default:
                ConsiderTailEllipsis(tstyle, fontProviders, params);
                break;
        }
    } else if (maxLines > 1) { // multi line
        if (tstyle.ellipsisModal == EllipsisModal::TAIL) {
            ConsiderTailEllipsis(tstyle, fontProviders, params);
        } else if (maxLines < lineMetrics_.size()) {
            lineMetrics_.erase(lineMetrics_.begin() + maxLines, lineMetrics_.end());
        }
    }
    didExceedMaxLines_ = true;
}

void Shaper::ComputeIntrinsicWidth(const size_t maxLines)
{
    maxIntrinsicWidth_ = 0.0;
    minIntrinsicWidth_ = 0.0;
    double lastInvisibleWidth = 0;
    for (const auto &line : lineMetrics_) {
        for (const auto &span : line.lineSpans) {
            if (span == nullptr) {
                continue;
            }

            auto width = span.GetWidth();
            auto visibleWidth = span.GetVisibleWidth();
            maxIntrinsicWidth_ += width;
            minIntrinsicWidth_ = std::max(visibleWidth, minIntrinsicWidth_);
            lastInvisibleWidth = width - visibleWidth;
        }
    }

    maxIntrinsicWidth_ -= lastInvisibleWidth;
    if (maxLines > 1) {
        minIntrinsicWidth_ = std::min(maxIntrinsicWidth_, minIntrinsicWidth_);
    } else {
        minIntrinsicWidth_ = maxIntrinsicWidth_;
    }
}

std::vector<LineMetrics> Shaper::DoShapeBeforeEllipsis(std::vector<VariantSpan> spans, const TypographyStyle &tstyle,
    const std::shared_ptr<FontProviders> &fontProviders, const double widthLimit)
{
    TextBreaker tb;
    tb.SetWidthLimit(widthLimit);
    tb.SetIndents(indents_);
    auto ret = tb.WordBreak(spans, tstyle, fontProviders);
    if (ret) {
        LOGEX_FUNC_LINE(ERROR) << "word break failed";
        return {};
    }

    BidiProcesser bp;
    auto newSpans = bp.ProcessBidiText(spans, tstyle.direction);
    if (newSpans.empty()) {
        LOGEX_FUNC_LINE(ERROR) << "Process BidiText failed";
        return {};
    }

    LineBreaker lb;
    return lb.BreakLines(newSpans, tstyle, widthLimit, indents_);
}

std::vector<LineMetrics> Shaper::DoShape(std::vector<VariantSpan> spans, const TypographyStyle &tstyle,
    const std::shared_ptr<FontProviders> &fontProviders, const double widthLimit)
{
#ifdef LOGGER_ENABLE_SCOPE
    ScopedTrace scope("Shaper::DoShape");
#endif

    lineMetrics_= DoShapeBeforeEllipsis(spans, tstyle, fontProviders, widthLimit);
    ComputeIntrinsicWidth(tstyle.maxLines);
    ConsiderEllipsis(tstyle, fontProviders, widthLimit);

    TextMerger tm;
    for (auto &metric : lineMetrics_) {
        auto res = tm.MergeSpans(metric.lineSpans);
        std::swap(res, metric.lineSpans);
    }

    TextReverser tr;
    for (auto &metric : lineMetrics_) {
        tr.ReverseRTLText(metric.lineSpans);
        tr.ProcessTypoDirection(metric.lineSpans, tstyle.direction);
    }

    TextShaper textShaper;
    for (const auto &metric : lineMetrics_) {
        for (const auto &span : metric.lineSpans) {
            textShaper.Shape(span, tstyle, fontProviders);
        }
    }
    DumpLineMetrics(lineMetrics_);
    return lineMetrics_;
}

void Shaper::ConsiderHeadEllipsis(const TypographyStyle &ys, const std::shared_ptr<FontProviders> &fontProviders,
    EllipsisParams params)
{
    bool isErase = false;
    auto &lastLine = lineMetrics_.back();
    double lastLineWidth = lastLine.GetAllSpanWidth();
    if (params.maxLines < lineMetrics_.size()) {
        if (params.ellipsisWidth > 0) {
            while (lastLineWidth + params.ellipsisWidth < params.widthLimit) {
                // lineMetrics_.size() - 2 is the index of second to last
                auto lastSpan = lineMetrics_[lineMetrics_.size() - 2].lineSpans.back();
                // lineMetrics_.size() - 2 is the index of second to last
                lineMetrics_[lineMetrics_.size() - 2].lineSpans.pop_back();
                lastLine.lineSpans.insert(lastLine.lineSpans.begin(), lastSpan);
                lastLineWidth = lastLine.GetAllSpanWidth();
            }
            lineMetrics_.erase(lineMetrics_.begin(), lineMetrics_.end() - params.maxLines);
            isErase = true;
        } else {
            lineMetrics_.erase(lineMetrics_.begin() + params.maxLines, lineMetrics_.end());
        }
    }

    if (params.ellipsisSpans.empty() || (!isErase && lastLineWidth <= params.widthLimit)) {
        return;
    }

    std::vector<VariantSpan> &lastLineSpans = lineMetrics_.back().lineSpans;
    auto ts = lastLineSpans.front().TryToTextSpan();
    if (ts == nullptr) {
        if (lastLineWidth + params.ellipsisWidth > params.widthLimit) {
            lastLineSpans.erase(lastLineSpans.begin());
            lastLineSpans.insert(lastLineSpans.begin(), params.ellipsisSpans.begin(), params.ellipsisSpans.end());
        } else if (isErase) {
            lastLineSpans.insert(lastLineSpans.begin(), params.ellipsisSpans.begin(), params.ellipsisSpans.end());
        }
    } else {
        if (lastLineWidth + params.ellipsisWidth > params.widthLimit) {
            double exceedWidth = lastLineWidth + params.ellipsisWidth - params.widthLimit;
            auto firstSpan = lastLineSpans.front();
            lastLineSpans.erase(lastLineSpans.begin());
            std::vector<LineMetrics> partlySpan = CreatePartlySpan(false, ys, fontProviders, firstSpan, exceedWidth);
            if (!partlySpan.empty()) {
                std::vector<VariantSpan> partlyLineSpans = partlySpan.front().lineSpans;
                lastLineSpans.insert(lastLineSpans.begin(), partlyLineSpans.begin(), partlyLineSpans.end());
            }
            lastLineSpans.insert(lastLineSpans.begin(), params.ellipsisSpans.begin(), params.ellipsisSpans.end());
        } else if (isErase) {
            lastLineSpans.insert(lastLineSpans.begin(), params.ellipsisSpans.begin(), params.ellipsisSpans.end());
        }
    }
}

void Shaper::ConsiderLastLine(const TypographyStyle &style, const std::shared_ptr<FontProviders> &fontProviders,
    EllipsisParams params, const bool isErase)
{
    // maxLines - 1 is the index of last LineMetrics
    auto &lastLine = params.maxLines < lineMetrics_.size() ? lineMetrics_[params.maxLines - 1] : lineMetrics_.back();
    double lastLineWidth = lastLine.GetAllSpanWidth();
    bool isExceed = (static_cast<int>(lastLineWidth + params.ellipsisWidth) > static_cast<int>(params.widthLimit));
    if (isExceed) {
        while ((!lastLine.lineSpans.empty()) && isExceed) {
            auto lastSpan = lastLine.lineSpans.back();
            lastLine.lineSpans.pop_back();
            double exceedWidth = lastLineWidth + params.ellipsisWidth - params.widthLimit;
            std::vector<LineMetrics> partlySpan = CreatePartlySpan(true, style, fontProviders, lastSpan, exceedWidth);
            if (!partlySpan.empty()) {
                std::vector<VariantSpan> partlyLineSpans = partlySpan.front().lineSpans;
                lastLine.lineSpans.insert(lastLine.lineSpans.end(), partlyLineSpans.begin(),
                    partlyLineSpans.end());
            }
            lastLineWidth = lastLine.GetAllSpanWidth();
            isExceed = (static_cast<int>(lastLineWidth + params.ellipsisWidth) > static_cast<int>(params.widthLimit));
        }
        lastLine.lineSpans.insert(lastLine.lineSpans.end(), params.ellipsisSpans.begin(),
            params.ellipsisSpans.end());
    } else if (isErase) {
        lastLine.lineSpans.insert(lastLine.lineSpans.end(), params.ellipsisSpans.begin(),
            params.ellipsisSpans.end());
    }
}

void Shaper::ConsiderTailEllipsis(const TypographyStyle &style, const std::shared_ptr<FontProviders> &fontProviders,
    EllipsisParams params)
{
    bool isErase = false;
    // maxLines - 1 is the index of last LineMetrics
    auto &lastLine = params.maxLines < lineMetrics_.size() ? lineMetrics_[params.maxLines - 1] : lineMetrics_.back();
    double lastLineWidth = lastLine.GetAllSpanWidth();
    params.widthLimit -= lastLine.indent;
    if (params.maxLines < lineMetrics_.size()) {
        if (params.ellipsisWidth > 0 && lastLineWidth + params.ellipsisWidth < params.widthLimit) {
            lastLine.lineSpans.push_back(lineMetrics_[params.maxLines].lineSpans.front());
            lastLineWidth = lastLine.GetAllSpanWidth();
        }
        lineMetrics_.erase(lineMetrics_.begin() + params.maxLines, lineMetrics_.end());
        isErase = true;
    }

    if (params.ellipsisSpans.empty() || (!isErase && lastLineWidth <= params.widthLimit)) {
        return;
    }

    auto ts = lastLine.lineSpans.back().TryToTextSpan();
    if (ts == nullptr) {
        if (lastLineWidth + params.ellipsisWidth > params.widthLimit) {
            lastLine.lineSpans.pop_back();
            lastLine.lineSpans.insert(lastLine.lineSpans.end(), params.ellipsisSpans.begin(),
                params.ellipsisSpans.end());
        } else if (isErase) {
            lastLine.lineSpans.insert(lastLine.lineSpans.end(), params.ellipsisSpans.begin(),
                params.ellipsisSpans.end());
        }
    } else {
        ConsiderLastLine(style, fontProviders, params, isErase);
    }
}

std::vector<LineMetrics> Shaper::CreatePartlySpan(const bool cutRight, const TypographyStyle &ys,
    const std::shared_ptr<FontProviders> &fontProviders, const VariantSpan &span, const double exceedWidth)
{
    auto textSpan = span.TryToTextSpan();
    if (textSpan == nullptr) {
        return {};
    }

    size_t startIndex = static_cast<size_t>(textSpan->cgs_.GetRange().start);
    size_t endIndex = static_cast<size_t>(textSpan->cgs_.GetRange().end);
    double deletedWidth = 0.0;
    while (startIndex < endIndex && deletedWidth < exceedWidth) {
        if (cutRight) {
            endIndex--;
            deletedWidth += textSpan->cgs_.GetCharWidth(endIndex);
        } else {
            deletedWidth += textSpan->cgs_.GetCharWidth(startIndex);
            startIndex++;
        }
    }

    if (startIndex < endIndex) {
        // endIndex - 1 is the index of end
        std::vector<uint16_t> chars = textSpan->cgs_.GetCharsToU16(startIndex, endIndex - 1, cutRight);
        VariantSpan partlySpan(TextSpan::MakeFromText(chars));
        partlySpan.SetTextStyle(span.GetTextStyle());
        std::vector<VariantSpan> spans = {partlySpan};
        return DoShapeBeforeEllipsis(spans, ys, fontProviders, MAXWIDTH);
    } else {
        return {};
    }
}

bool Shaper::CalcCharsIndex(const std::shared_ptr<TextSpan> textSpan, size_t &leftIndex,
    size_t &rightIndex, size_t &maxIndex, const int avalibleWidth) const
{
    if (textSpan == nullptr) {
        return false;
    }
    leftIndex = 0;
    maxIndex = textSpan->cgs_.GetSize();
    rightIndex = maxIndex;

    double leftCharsWidth = 0.0;
    double rightCharsWidth = 0.0;
    bool isLeft = true;
    bool isNormal = true;
    int charsWidth = static_cast<int>(leftCharsWidth + rightCharsWidth);
    while (charsWidth <= avalibleWidth) {
        if (isLeft) {
            leftCharsWidth += textSpan->cgs_.GetCharWidth(leftIndex);
            charsWidth = static_cast<int>(leftCharsWidth + rightCharsWidth);
            if (charsWidth > avalibleWidth) {
                leftIndex--;
                break;
            }
            isLeft = false;
        } else {
            rightIndex--;
            rightCharsWidth += textSpan->cgs_.GetCharWidth(rightIndex);
            charsWidth = static_cast<int>(leftCharsWidth + rightCharsWidth);
            if (charsWidth > avalibleWidth) {
                rightIndex++;
                break;
            }
            leftIndex++;
            isLeft = true;
        }
        if (leftIndex > rightIndex) {
            isNormal = false;
            break;
        }
    }
    return isNormal;
}

void Shaper::SplitJointLeftSpans(const EllipsisParams &params, const size_t leftIndex,
    const TypographyStyle &style, const std::shared_ptr<FontProviders> &fontProviders, const VariantSpan &span)
{
    std::shared_ptr<TextSpan> textSpan = span.TryToTextSpan();
    if (textSpan == nullptr) {
        return;
    }

    // 0 means the first index of the array,true means handles spaces at the end of the left index of the array
    std::vector<uint16_t> leftGroups = textSpan->cgs_.GetCharsToU16(0, leftIndex, true);
    VariantSpan leftSpan(TextSpan::MakeFromText(leftGroups));
    leftSpan.SetTextStyle(span.GetTextStyle());
    std::vector<VariantSpan> leftVariantSpans = {leftSpan};
    lineMetrics_ = DoShapeBeforeEllipsis(leftVariantSpans, style, fontProviders, params.widthLimit);
    lineMetrics_.back().lineSpans.insert(lineMetrics_.back().lineSpans.end(),
        params.ellipsisSpans.begin(), params.ellipsisSpans.end());
}

void Shaper::SplitJointRightSpans(const EllipsisParams &params, const size_t rightIndex,
    const TypographyStyle &style, const std::shared_ptr<FontProviders> &fontProviders, const VariantSpan &span)
{
    std::shared_ptr<TextSpan> textSpan = span.TryToTextSpan();
    if (textSpan == nullptr) {
        return;
    }
    size_t maxIndex = textSpan->cgs_.GetSize();
    // maxIndex - 1 means last index of the array,false means handles spaces at the end of the right index of the array
    std::vector<uint16_t> rightGroups = textSpan->cgs_.GetCharsToU16(rightIndex, maxIndex - 1, false);
    VariantSpan rightSpan(TextSpan::MakeFromText(rightGroups));
    rightSpan.SetTextStyle(span.GetTextStyle());
    std::vector<VariantSpan> rightVariantSpans = {rightSpan};
    if (style.ellipsisModal == EllipsisModal::HEAD) {
        lineMetrics_ = DoShapeBeforeEllipsis(rightVariantSpans, style, fontProviders, params.widthLimit);
        lineMetrics_.front().lineSpans.insert(lineMetrics_.front().lineSpans.begin(),
            params.ellipsisSpans.begin(), params.ellipsisSpans.end());
    } else if (style.ellipsisModal == EllipsisModal::MIDDLE) {
        std::vector<LineMetrics> rightLineMetrics = DoShapeBeforeEllipsis(rightVariantSpans,
            style, fontProviders, params.widthLimit);
        lineMetrics_.back().lineSpans.insert(lineMetrics_.back().lineSpans.end(),
            rightLineMetrics.front().lineSpans.begin(), rightLineMetrics.front().lineSpans.end());
    }
}

bool Shaper::CalcMidSpanIndex(const std::vector<VariantSpan> &spans, size_t &leftIndex, size_t &rightIndex,
    struct SpansWidth &spansWidth, const int avalibleWidth)
{
    double leftSpansWidth = 0.0;
    double rightSpansWidth = 0.0;
    bool isLeft = true;
    bool isNormal = true;
    int curSpansWidth = static_cast<int>(leftSpansWidth + rightSpansWidth);
    while (curSpansWidth <= avalibleWidth) {
        if (isLeft) {
            leftSpansWidth += spans.at(leftIndex).GetWidth();
            curSpansWidth = static_cast<int>(leftSpansWidth + rightSpansWidth);
            if (curSpansWidth > avalibleWidth) {
                break;
            }
            isLeft = false;
        } else {
            rightIndex--;
            rightSpansWidth += spans.at(rightIndex).GetWidth();
            curSpansWidth = static_cast<int>(leftSpansWidth + rightSpansWidth);
            if (curSpansWidth > avalibleWidth) {
                break;
            }
            leftIndex++;
            isLeft = true;
        }
        if (leftIndex >= rightIndex) {
            isNormal = false;
            break;
        }
    }
    spansWidth.leftWidth = leftSpansWidth;
    spansWidth.rightWidth = rightSpansWidth;
    return isNormal;
}

void Shaper::ConsideMidSpanEllipsis(const TypographyStyle &style, const std::shared_ptr<FontProviders> &fontProviders,
    const EllipsisParams &params, const std::vector<VariantSpan> &spans)
{
    struct SpansWidth spansWidth;
    size_t leftIndex = 0;
    size_t rightIndex = spans.size();
    int avalibleWidth = static_cast<int>(params.widthLimit - params.ellipsisWidth);
    auto &firstLineSpans = lineMetrics_.front().lineSpans;
    if (!CalcMidSpanIndex(spans, leftIndex, rightIndex, spansWidth, avalibleWidth)) {
        firstLineSpans = params.ellipsisSpans;
        lineMetrics_.erase(lineMetrics_.begin() + params.maxLines, lineMetrics_.end());
        return;
    }
    std::shared_ptr<TextSpan> textSpan = spans.front().TryToTextSpan();
    double exceedWidth = spansWidth.leftWidth + spansWidth.rightWidth + params.ellipsisWidth - params.widthLimit;
    std::vector<LineMetrics> partlySpan;
    bool isLeft = static_cast<int>(spansWidth.leftWidth) > static_cast<int>(spansWidth.rightWidth);
    if (isLeft) {
        if (leftIndex >= spans.size()) {
            firstLineSpans = params.ellipsisSpans;
            lineMetrics_.erase(lineMetrics_.begin() + params.maxLines, lineMetrics_.end());
            return;
        }
        partlySpan = CreatePartlySpan(true, style, fontProviders, spans.at(leftIndex), exceedWidth);
        leftIndex--;
    } else {
        if (rightIndex < spans.size()) {
            partlySpan = CreatePartlySpan(false, style, fontProviders, spans.at(rightIndex), exceedWidth);
            rightIndex++;
        }
    }

    firstLineSpans = params.ellipsisSpans;
    lineMetrics_.erase(lineMetrics_.begin() + params.maxLines, lineMetrics_.end());

    if (leftIndex < spans.size()) {
        firstLineSpans.insert(firstLineSpans.begin(), spans.begin(), spans.begin() + leftIndex + 1);
    }
    if (isLeft) {
        if (!partlySpan.empty()) {
            std::vector<VariantSpan> partlyLineSpans = partlySpan.front().lineSpans;
            firstLineSpans.insert(firstLineSpans.end() - params.ellipsisSpans.size(),
                partlyLineSpans.begin(), partlyLineSpans.end());
        }
    } else {
        if (!partlySpan.empty()) {
            std::vector<VariantSpan> partlyLineSpans = partlySpan.front().lineSpans;
            firstLineSpans.insert(firstLineSpans.end(), partlyLineSpans.begin(), partlyLineSpans.end());
        }
    }
    if (rightIndex < spans.size()) {
        firstLineSpans.insert(firstLineSpans.end(), spans.begin() + rightIndex, spans.end());
    }
}

void Shaper::ConsiderMiddleEllipsis(const TypographyStyle &style, const std::shared_ptr<FontProviders> &fontProviders,
    EllipsisParams params)
{
    if (params.maxLines >= lineMetrics_.size() || params.ellipsisSpans.empty()) {
        return;
    }
    std::vector<VariantSpan> spans;
    for (auto metric : lineMetrics_) {
        for (auto span : metric.lineSpans) {
            spans.push_back(span);
        }
    }
    int avalibleWidth = static_cast<int>(params.widthLimit - params.ellipsisWidth);
    if (avalibleWidth < 0) {
        lineMetrics_.front().lineSpans = params.ellipsisSpans;
        lineMetrics_.erase(lineMetrics_.begin() + params.maxLines, lineMetrics_.end());
        return;
    }
    bool isExceed = static_cast<int>(spans.front().GetWidth() + spans.back().GetWidth()) > avalibleWidth;
    if (isExceed) {
        size_t leftIndex = 0;
        size_t rightIndex = 0;
        size_t maxIndex = 0;
        auto &filstSpan = spans.front();
        if (CalcCharsIndex(filstSpan.TryToTextSpan(), leftIndex, rightIndex, maxIndex, avalibleWidth)) {
            if (leftIndex < maxIndex) {
                SplitJointLeftSpans(params, leftIndex, style, fontProviders, spans.front());
            } else {
                lineMetrics_.front().lineSpans = params.ellipsisSpans;
                lineMetrics_.erase(lineMetrics_.begin() + params.maxLines, lineMetrics_.end());
                return;
            }
            if (rightIndex < maxIndex) {
                SplitJointRightSpans(params, rightIndex, style, fontProviders, spans.back());
            }
        } else {
            lineMetrics_.front().lineSpans = params.ellipsisSpans;
            lineMetrics_.erase(lineMetrics_.begin() + params.maxLines, lineMetrics_.end());
        }
    } else {
        ConsideMidSpanEllipsis(style, fontProviders, params, spans);
    }
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
