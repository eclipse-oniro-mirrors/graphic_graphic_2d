
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

#include "drawing_text_line.h"

#include <string>

#include "drawing_rect.h"
#include "array_mgr.h"
#include "skia_txt/run_impl.h"
#include "skia_txt/text_line_base.h"
#include "skia_txt/txt/paragraph.h"

using namespace OHOS::Rosen;

typedef OHOS::Rosen::AdapterTxt::TextLineBaseImpl LineImpl;
typedef OHOS::Rosen::AdapterTxt::RunImpl RunImpl;

OH_Drawing_Array* OH_Drawing_TypographyGetTextLines(OH_Drawing_Typography* typography)
{
    if (typography == nullptr) {
        return nullptr;
    }

    auto paragraph = reinterpret_cast<Typography*>(typography)->GetParagraph();
    if (paragraph == nullptr) {
        return nullptr;
    }

    auto textLines = reinterpret_cast<SPText::Paragraph*>(paragraph)->GetTextLines();
    if (textLines.size() == 0) {
        return nullptr;
    }

    LineObject* lineObjectArr = new (std::nothrow) LineObject[textLines.size()];
    if (lineObjectArr == nullptr) {
        return nullptr;
    }
    for (size_t i = 0; i < textLines.size(); ++i) {
        auto textLine = new (std::nothrow) LineImpl(std::move(textLines[i]));
        if (textLine == nullptr) {
            delete[] lineObjectArr;
            return nullptr;
        }

        lineObjectArr[i].line = reinterpret_cast<void*>(textLine);
        lineObjectArr[i].isArray = true;
    }

    ObjectArray* array = new (std::nothrow) ObjectArray();
    if (array == nullptr) {
        for (size_t i = 0; i < textLines.size(); ++i) {
            delete reinterpret_cast<LineImpl*>(lineObjectArr[i].line);
        }
        delete[] lineObjectArr;
        return nullptr;
    }
    array->addr = lineObjectArr;
    array->num = textLines.size();
    array->type = TEXT_LINE;

    return reinterpret_cast<OH_Drawing_Array*>(array);
}

void OH_Drawing_DestroyTextLines(OH_Drawing_Array* lines)
{
    if (lines == nullptr) {
        return;
    }

    auto arrayLines = reinterpret_cast<ObjectArray*>(lines);
    if (arrayLines != nullptr && arrayLines->type == TEXT_LINE && arrayLines->num > 0) {
        LineObject* lineObjectArr = reinterpret_cast<LineObject*>(arrayLines->addr);
        if (lineObjectArr != nullptr) {
            for (size_t i = 0; i < arrayLines->num; ++i) {
                delete reinterpret_cast<LineImpl*>(lineObjectArr[i].line);
                lineObjectArr[i].line = nullptr;
            }
            delete[] lineObjectArr;
            arrayLines->addr = nullptr;
        }
        arrayLines->num = 0;
        arrayLines->type = INVALID;
        delete arrayLines;
    }
}

void OH_Drawing_DestroyTextLine(OH_Drawing_TextLine* line)
{
    if (line == nullptr) {
        return;
    }

    LineObject* lineObject = reinterpret_cast<LineObject*>(line);
    if (!lineObject->isArray) {
        delete reinterpret_cast<LineImpl*>(lineObject->line);
        lineObject->line = nullptr;
        delete lineObject;
    }
}

OH_Drawing_TextLine* OH_Drawing_GetTextLineByIndex(OH_Drawing_Array* lines, size_t index)
{
    if (lines == nullptr) {
        return nullptr;
    }

    auto arrayLines = reinterpret_cast<ObjectArray*>(lines);
    if (arrayLines != nullptr &&  arrayLines->addr != nullptr &&
        arrayLines->type == TEXT_LINE && index < arrayLines->num) {
        LineObject* lineObjectArr = reinterpret_cast<LineObject*>(arrayLines->addr);
        return reinterpret_cast<OH_Drawing_TextLine*>(&lineObjectArr[index]);
    }

    return nullptr;
}

double OH_Drawing_TextLineGetGlyphCount(OH_Drawing_TextLine* line)
{
    if (line == nullptr) {
        return 0.0;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return 0.0;
    }

    return lineImpl->GetGlyphCount();
}

void OH_Drawing_TextLineGetTextRange(OH_Drawing_TextLine* line, size_t* start, size_t* end)
{
    if (line == nullptr || start == nullptr || end == nullptr) {
        return;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return;
    }

    Boundary range = lineImpl->GetTextRange();
    *start = range.leftIndex;
    *end = range.rightIndex;
}

OH_Drawing_Array* OH_Drawing_TextLineGetGlyphRuns(OH_Drawing_TextLine* line)
{
    if (line == nullptr) {
        return nullptr;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return nullptr;
    }

    auto spTextLines = lineImpl->GetSpTextLineBase();
    if (spTextLines == nullptr) {
        return nullptr;
    }

    auto runs = reinterpret_cast<SPText::TextLineBase*>(spTextLines)->GetGlyphRuns();
    if (runs.size() == 0) {
        return nullptr;
    }

    RunImpl* runsArr = new (std::nothrow) RunImpl[runs.size()];
    if (runsArr == nullptr) {
        return nullptr;
    }
    for (size_t i = 0; i < runs.size(); ++i) {
        runsArr[i].SetSpRunBase(runs[i]);
    }

    ObjectArray* array = new (std::nothrow) ObjectArray();
    if (array == nullptr) {
        delete[] runsArr;
        return nullptr;
    }
    array->addr = runsArr;
    array->num = runs.size();
    array->type = TEXT_RUN;

    return reinterpret_cast<OH_Drawing_Array*>(array);
}

void OH_Drawing_DestroyRuns(OH_Drawing_Array* runs)
{
    if (runs == nullptr) {
        return;
    }

    auto arrayRuns = reinterpret_cast<ObjectArray*>(runs);
    if (arrayRuns != nullptr && arrayRuns->type == TEXT_RUN && arrayRuns->num > 0) {
        RunImpl* runsArr = reinterpret_cast<RunImpl*>(arrayRuns->addr);
        if (runsArr != nullptr) {
            delete[] runsArr;
            arrayRuns->addr = nullptr;
        }
        arrayRuns->num = 0;
        arrayRuns->type = INVALID;
        delete arrayRuns;
    }
}

OH_Drawing_Run* OH_Drawing_GetRunByIndex(OH_Drawing_Array* runs, size_t index)
{
    if (runs == nullptr) {
        return nullptr;
    }

    auto arrayRuns = reinterpret_cast<ObjectArray*>(runs);
    if (arrayRuns != nullptr &&  arrayRuns->addr != nullptr &&
        arrayRuns->type == TEXT_RUN && index < arrayRuns->num) {
        RunImpl* run = reinterpret_cast<RunImpl*>(arrayRuns->addr);
        return reinterpret_cast<OH_Drawing_Run*>(&run[index]);
    }

    return nullptr;
}

void OH_Drawing_TextLinePaint(OH_Drawing_TextLine* line, OH_Drawing_Canvas* canvas, double x, double y)
{
    if (line == nullptr || canvas == nullptr) {
        return;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return;
    }

    lineImpl->Paint(reinterpret_cast<OHOS::Rosen::Drawing::Canvas*>(canvas), x, y);
}

OH_Drawing_TextLine* OH_Drawing_TextLineCreateTruncatedLine(OH_Drawing_TextLine* line, double width, int mode,
    const char* ellipsis)
{
    if (line == nullptr || ellipsis == nullptr) {
        return nullptr;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return nullptr;
    }

    auto spTextLines = lineImpl->GetSpTextLineBase();
    if (spTextLines == nullptr) {
        return nullptr;
    }

    std::string ellipsisStr(ellipsis);
    auto truncatedTextLine = reinterpret_cast<SPText::TextLineBase*>(spTextLines)->CreateTruncatedLine(
        width, static_cast<EllipsisModal>(mode), ellipsisStr);
    if (truncatedTextLine == nullptr) {
        return nullptr;
    }

    auto truncatedLine = new (std::nothrow) LineImpl(std::move(truncatedTextLine));
    if (truncatedLine == nullptr) {
        return nullptr;
    }

    LineObject* lineObject = new (std::nothrow) LineObject();
    if (lineObject == nullptr) {
        delete truncatedLine;
        return nullptr;
    }

    lineObject->line = reinterpret_cast<void*>(truncatedLine);
    lineObject->isArray = false;

    return reinterpret_cast<OH_Drawing_TextLine*>(lineObject);
}

double OH_Drawing_TextLineGetTypographicBounds(OH_Drawing_TextLine* line, double* ascent, double* descent,
    double* leading)
{
    if (line == nullptr || ascent == nullptr || descent == nullptr || leading == nullptr) {
        return 0.0;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return 0.0;
    }

    return lineImpl->GetTypographicBounds(ascent, descent, leading);
}

OH_Drawing_Rect* OH_Drawing_TextLineGetImageBounds(OH_Drawing_TextLine* line)
{
    if (line == nullptr) {
        return nullptr;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return nullptr;
    }

    auto skRect = lineImpl->GetImageBounds();
    return OH_Drawing_RectCreate(skRect.GetLeft(), skRect.GetTop(), skRect.GetRight(), skRect.GetBottom());
}

double OH_Drawing_TextLineGetTrailingSpaceWidth(OH_Drawing_TextLine* line)
{
    if (line == nullptr) {
        return 0.0;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return 0.0;
    }

    return lineImpl->GetTrailingSpaceWidth();
}

int32_t OH_Drawing_TextLineGetStringIndexForPosition(OH_Drawing_TextLine* line, OH_Drawing_Point* point)
{
    if (line == nullptr || point == nullptr) {
        return 0;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return 0;
    }

    return lineImpl->GetStringIndexForPosition(*reinterpret_cast<SkPoint*>(point));
}

double OH_Drawing_TextLineGetOffsetForStringIndex(OH_Drawing_TextLine* line, int32_t index)
{
    if (line == nullptr) {
        return 0.0;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return 0.0;
    }

    return lineImpl->GetOffsetForStringIndex(index);
}

void OH_Drawing_TextLineEnumerateCaretOffsets(OH_Drawing_TextLine* line, CustomCallback callback)
{
    if (line == nullptr || callback == nullptr) {
        return;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return;
    }

    bool isHardBreak = false;
    std::map<int32_t, double> offsetMap = lineImpl->GetIndexAndOffsets(isHardBreak);
    double leftOffset = 0.0;
    const size_t twoNum = 2;
    for (auto it = offsetMap.begin(); it != offsetMap.end(); ++it) {
        for (size_t i = 0; i < twoNum; i++) {
            double offset = (i == 0) ? leftOffset: it->second;
            bool leadingEdge = (i == 0) ? true : false;
            if (callback(offset, it->first, leadingEdge)) {
                return;
            }
        }
        leftOffset = it->second;
    }
    if (isHardBreak && offsetMap.size() > 0) {
        if (!callback(leftOffset, offsetMap.rbegin()->first + 1, true)) {
            callback(leftOffset, offsetMap.rbegin()->first + 1, false);
        }
    }
}

double OH_Drawing_TextLineGetAlignmentOffset(OH_Drawing_TextLine* line, double alignmentFactor, double alignmentWidth)
{
    if (line == nullptr) {
        return 0.0;
    }

    auto lineImpl = reinterpret_cast<LineImpl*>(reinterpret_cast<LineObject*>(line)->line);
    if (lineImpl == nullptr) {
        return 0.0;
    }

    return lineImpl->GetAlignmentOffset(alignmentFactor, alignmentWidth);
}