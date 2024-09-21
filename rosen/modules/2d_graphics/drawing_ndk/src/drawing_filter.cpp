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

#include "drawing_filter.h"

#include "drawing_canvas_utils.h"

#include "effect/filter.h"

using namespace OHOS;
using namespace Rosen;
using namespace Drawing;

static Filter* CastToFilter(OH_Drawing_Filter* cFilter)
{
    return reinterpret_cast<Filter*>(cFilter);
}

static ImageFilter* CastToImageFilter(OH_Drawing_ImageFilter* cImageFilter)
{
    return reinterpret_cast<ImageFilter*>(cImageFilter);
}

static MaskFilter* CastToMaskFilter(OH_Drawing_MaskFilter* cMaskFilter)
{
    return reinterpret_cast<MaskFilter*>(cMaskFilter);
}

static ColorFilter* CastToColorFilter(OH_Drawing_ColorFilter* cColorFilter)
{
    return reinterpret_cast<ColorFilter*>(cColorFilter);
}

OH_Drawing_Filter* OH_Drawing_FilterCreate()
{
    return (OH_Drawing_Filter*)new Filter();
}

void OH_Drawing_FilterSetImageFilter(OH_Drawing_Filter* cFliter, OH_Drawing_ImageFilter* cImageFilter)
{
    Filter* filter = CastToFilter(cFliter);
    if (filter == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cImageFilter == nullptr) {
        filter->SetImageFilter(nullptr);
        return;
    }
    filter->SetImageFilter(std::shared_ptr<ImageFilter>{CastToImageFilter(cImageFilter), [](auto p) {}});
}

void OH_Drawing_FilterSetMaskFilter(OH_Drawing_Filter* cFliter, OH_Drawing_MaskFilter* cMaskFilter)
{
    Filter* filter = CastToFilter(cFliter);
    if (filter == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cMaskFilter == nullptr) {
        filter->SetMaskFilter(nullptr);
        return;
    }
    filter->SetMaskFilter(std::shared_ptr<MaskFilter>{CastToMaskFilter(cMaskFilter), [](auto p) {}});
}

void OH_Drawing_FilterSetColorFilter(OH_Drawing_Filter* cFliter, OH_Drawing_ColorFilter* cColorFilter)
{
    Filter* filter = CastToFilter(cFliter);
    if (filter == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cColorFilter == nullptr) {
        filter->SetColorFilter(nullptr);
        return;
    }
    filter->SetColorFilter(std::shared_ptr<ColorFilter>{CastToColorFilter(cColorFilter), [](auto p) {}});
}

void OH_Drawing_FilterGetColorFilter(OH_Drawing_Filter* cFliter, OH_Drawing_ColorFilter* cColorFilter)
{
    Filter* filter = CastToFilter(cFliter);
    if (filter == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    ColorFilter* colorFilter = CastToColorFilter(cColorFilter);
    if (colorFilter == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    std::shared_ptr<ColorFilter> colorFilterPtr = filter->GetColorFilter();
    if (colorFilterPtr == nullptr) {
        *colorFilter = ColorFilter(ColorFilter::FilterType::NO_TYPE);
        return;
    }
    *colorFilter = *(colorFilterPtr.get());
}

void OH_Drawing_FilterDestroy(OH_Drawing_Filter* cFilter)
{
    if (!cFilter) {
        return;
    }
    delete CastToFilter(cFilter);
}
