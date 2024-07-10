/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "js_enum.h"

#include <map>
#include <vector>

#include "native_value.h"
#include "draw/blend_mode.h"
#include "draw/clip.h"
#include "draw/core_canvas.h"
#include "draw/path.h"
#include "draw/pen.h"
#include "effect/mask_filter.h"
#include "text/font_types.h"
#include "utils/region.h"
#include "utils/sampling_options.h"

#include "js_drawing_utils.h"

#ifdef WINDOWS_PLATFORM
#ifdef DIFFERENCE
#undef DIFFERENCE
#endif
#endif

namespace OHOS::Rosen {
namespace Drawing {
struct JsEnumInt {
    std::string_view enumName;
    int32_t enumInt;
};

static const std::vector<struct JsEnumInt> g_blendMode = {
    { "CLEAR", static_cast<int32_t>(BlendMode::CLEAR) },
    { "SRC", static_cast<int32_t>(BlendMode::SRC) },
    { "DST", static_cast<int32_t>(BlendMode::DST) },
    { "SRC_OVER", static_cast<int32_t>(BlendMode::SRC_OVER) },
    { "DST_OVER", static_cast<int32_t>(BlendMode::DST_OVER) },
    { "SRC_IN", static_cast<int32_t>(BlendMode::SRC_IN) },
    { "DST_IN", static_cast<int32_t>(BlendMode::DST_IN) },
    { "SRC_OUT", static_cast<int32_t>(BlendMode::SRC_OUT) },
    { "DST_OUT", static_cast<int32_t>(BlendMode::DST_OUT) },
    { "SRC_ATOP", static_cast<int32_t>(BlendMode::SRC_ATOP) },
    { "DST_ATOP", static_cast<int32_t>(BlendMode::DST_ATOP) },
    { "XOR", static_cast<int32_t>(BlendMode::XOR) },
    { "PLUS", static_cast<int32_t>(BlendMode::PLUS) },
    { "MODULATE", static_cast<int32_t>(BlendMode::MODULATE) },
    { "SCREEN", static_cast<int32_t>(BlendMode::SCREEN) },
    { "OVERLAY", static_cast<int32_t>(BlendMode::OVERLAY) },
    { "DARKEN", static_cast<int32_t>(BlendMode::DARKEN) },
    { "LIGHTEN", static_cast<int32_t>(BlendMode::LIGHTEN) },
    { "COLOR_DODGE", static_cast<int32_t>(BlendMode::COLOR_DODGE) },
    { "COLOR_BURN", static_cast<int32_t>(BlendMode::COLOR_BURN) },
    { "HARD_LIGHT", static_cast<int32_t>(BlendMode::HARD_LIGHT) },
    { "SOFT_LIGHT", static_cast<int32_t>(BlendMode::SOFT_LIGHT) },
    { "DIFFERENCE", static_cast<int32_t>(BlendMode::DIFFERENCE) },
    { "EXCLUSION", static_cast<int32_t>(BlendMode::EXCLUSION) },
    { "MULTIPLY", static_cast<int32_t>(BlendMode::MULTIPLY) },
    { "HUE", static_cast<int32_t>(BlendMode::HUE) },
    { "SATURATION", static_cast<int32_t>(BlendMode::STATURATION) },
    { "COLOR", static_cast<int32_t>(BlendMode::COLOR_MODE) },
    { "LUMINOSITY", static_cast<int32_t>(BlendMode::LUMINOSITY) },
};

static const std::vector<struct JsEnumInt> g_textEncoding = {
    { "TEXT_ENCODING_UTF8", static_cast<int32_t>(TextEncoding::UTF8) },
    { "TEXT_ENCODING_UTF16", static_cast<int32_t>(TextEncoding::UTF16) },
    { "TEXT_ENCODING_UTF32", static_cast<int32_t>(TextEncoding::UTF32) },
    { "TEXT_ENCODING_GLYPH_ID", static_cast<int32_t>(TextEncoding::GLYPH_ID) },
};

static const std::vector<struct JsEnumInt> g_filterMode = {
    { "FILTER_MODE_NEAREST", static_cast<int32_t>(FilterMode::NEAREST) },
    { "FILTER_MODE_LINEAR", static_cast<int32_t>(FilterMode::LINEAR) },
};

static const std::vector<struct JsEnumInt> g_regionOp = {
    { "DIFFERENCE", static_cast<int32_t>(RegionOp::DIFFERENCE) },
    { "INTERSECT", static_cast<int32_t>(RegionOp::INTERSECT) },
    { "UNION", static_cast<int32_t>(RegionOp::UNION) },
    { "XOR", static_cast<int32_t>(RegionOp::XOR) },
    { "REVERSE_DIFFERENCE", static_cast<int32_t>(RegionOp::REVERSE_DIFFERENCE) },
    { "REPLACE", static_cast<int32_t>(RegionOp::REPLACE) },
};

static const std::vector<struct JsEnumInt> g_clipOp = {
    { "DIFFERENCE", static_cast<int32_t>(ClipOp::DIFFERENCE) },
    { "INTERSECT", static_cast<int32_t>(ClipOp::INTERSECT) },
};

static const std::vector<struct JsEnumInt> g_joinStyle = {
    { "MITER_JOIN", static_cast<int32_t>(Pen::JoinStyle::MITER_JOIN) },
    { "ROUND_JOIN", static_cast<int32_t>(Pen::JoinStyle::ROUND_JOIN) },
    { "BEVEL_JOIN", static_cast<int32_t>(Pen::JoinStyle::BEVEL_JOIN) },
};

static const std::vector<struct JsEnumInt> g_capStyle = {
    { "FLAT_CAP", 0 }, // 0: CapStyle::FLAT_CAP
    { "SQUARE_CAP", 1 }, // 1: CapStyle::SQUARE_CAP
    { "ROUND_CAP", 2 }, // 2: CapStyle::ROUND_CAP
};

static const std::vector<struct JsEnumInt> g_blurType = {
    { "NORMAL", static_cast<int32_t>(BlurType::NORMAL) },
    { "SOLID", static_cast<int32_t>(BlurType::SOLID) },
    { "OUTER", static_cast<int32_t>(BlurType::OUTER) },
    { "INNER", static_cast<int32_t>(BlurType::INNER) },
};

#undef TRANSPARENT
static const std::vector<struct JsEnumInt> g_rectType = {
    { "DEFAULT", static_cast<int32_t>(Lattice::RectType::DEFAULT) },
    { "TRANSPARENT", static_cast<int32_t>(Lattice::RectType::TRANSPARENT) },
    { "FIXEDCOLOR", static_cast<int32_t>(Lattice::RectType::FIXEDCOLOR) },
};

static const std::vector<struct JsEnumInt> g_fontMetricsFlags = {
    { "UNDERLINE_THICKNESS_VALID", static_cast<int32_t>(
        Drawing::FontMetrics::FontMetricsFlags::UNDERLINE_THICKNESS_IS_VALID_FLAG) },
    { "UNDERLINE_POSITION_VALID", static_cast<int32_t>(
        Drawing::FontMetrics::FontMetricsFlags::UNDERLINE_POSITION_IS_VALID_FLAG) },
    { "STRIKETHROUGH_THICKNESS_VALID", static_cast<int32_t>(
        Drawing::FontMetrics::FontMetricsFlags::STRIKEOUT_THICKNESS_IS_VALID_FLAG) },
    { "STRIKETHROUGH_POSITION_VALID", static_cast<int32_t>(
        Drawing::FontMetrics::FontMetricsFlags::STRIKEOUT_POSITION_IS_VALID_FLAG) },
    { "BOUNDS_INVALID", static_cast<int32_t>(Drawing::FontMetrics::FontMetricsFlags::BOUNDS_INVALID_FLAG) },
};

static const std::vector<struct JsEnumInt> g_fontEdging = {
    { "FONT_EDGING_ALIAS", static_cast<int32_t>(FontEdging::ALIAS) },
    { "FONT_EDGING_ANTI_ALIAS", static_cast<int32_t>(FontEdging::ANTI_ALIAS) },
    { "FONT_EDGING_SUBPIXEL_ANTI_ALIAS", static_cast<int32_t>(FontEdging::SUBPIXEL_ANTI_ALIAS) },
};

static const std::vector<struct JsEnumInt> g_fontHinting = {
    { "FONT_HINTING_NONE", static_cast<int32_t>(FontHinting::NONE) },
    { "FONT_HINTING_SLIGHT", static_cast<int32_t>(FontHinting::SLIGHT) },
    { "FONT_HINTING_NORMAL", static_cast<int32_t>(FontHinting::NORMAL) },
    { "FONT_HINTING_FULL", static_cast<int32_t>(FontHinting::FULL) },
};

static const std::vector<struct JsEnumInt> g_pointMode = {
    { "POINT_MODE_POINTS", static_cast<int32_t>(PointMode::POINTS_POINTMODE) },
    { "POINT_MODE_LINES", static_cast<int32_t>(PointMode::LINES_POINTMODE) },
    { "POINT_MODE_POLYGON", static_cast<int32_t>(PointMode::POLYGON_POINTMODE) },
};

static const std::vector<struct JsEnumInt> g_pathDirection = {
    { "PATH_DIRECTION_CW", static_cast<int32_t>(PathDirection::CW_DIRECTION) },
    { "PATH_DIRECTION_CCW", static_cast<int32_t>(PathDirection::CCW_DIRECTION) },
};

static const std::vector<struct JsEnumInt> g_pathFillType = {
    { "PATH_FILL_TYPE_WINDING", 0 }, // 0: PathFillType::WINDING, conflict with define WINDING
    { "PATH_FILL_TYPE_EVEN_ODD", static_cast<int32_t>(PathFillType::EVENTODD) },
    { "PATH_FILL_TYPE_INVERSE_WINDING", static_cast<int32_t>(PathFillType::INVERSE_WINDING) },
    { "PATH_FILL_TYPE_INVERSE_EVEN_ODD", static_cast<int32_t>(PathFillType::INVERSE_EVENTODD) },
};

static const std::map<std::string_view, const std::vector<struct JsEnumInt>&> g_intEnumClassMap = {
    { "BlendMode", g_blendMode },
    { "TextEncoding", g_textEncoding },
    { "FilterMode", g_filterMode },
    { "RegionOp", g_regionOp },
    { "ClipOp", g_clipOp },
    { "JoinStyle", g_joinStyle },
    { "CapStyle", g_capStyle },
    { "BlurType", g_blurType },
    { "RectType", g_rectType },
    { "FontMetricsFlags", g_fontMetricsFlags },
    { "FontEdging", g_fontEdging },
    { "FontHinting", g_fontHinting },
    { "PointMode", g_pointMode },
    { "PathDirection", g_pathDirection },
    { "PathFillType", g_pathFillType },
};

napi_value JsEnum::JsEnumIntInit(napi_env env, napi_value exports)
{
    for (auto it = g_intEnumClassMap.begin(); it != g_intEnumClassMap.end(); it++) {
        auto &enumClassName = it->first;
        auto &enumItemVec = it->second;
        auto vecSize = enumItemVec.size();
        std::vector<napi_value> value;
        value.resize(vecSize);
        for (size_t index = 0; index < vecSize; ++index) {
            napi_create_int32(env, enumItemVec[index].enumInt, &value[index]);
        }

        std::vector<napi_property_descriptor> property;
        property.resize(vecSize);
        for (size_t index = 0; index < vecSize; ++index) {
            property[index] = napi_property_descriptor DECLARE_NAPI_STATIC_PROPERTY(
                enumItemVec[index].enumName.data(), value[index]);
        }

        auto napiConstructor = [](napi_env env, napi_callback_info info) {
            napi_value jsThis = nullptr;
            napi_get_cb_info(env, info, nullptr, nullptr, &jsThis, nullptr);
            return jsThis;
        };

        napi_value result = nullptr;
        napi_status napiStatus = napi_define_class(env, enumClassName.data(), NAPI_AUTO_LENGTH, napiConstructor,
            nullptr, property.size(), property.data(), &result);
        if (napiStatus != napi_ok) {
            ROSEN_LOGE("[NAPI] Failed to define enum");
            return nullptr;
        }

        napiStatus = napi_set_named_property(env, exports, enumClassName.data(), result);
        if (napiStatus != napi_ok) {
            ROSEN_LOGE("[NAPI] Failed to set result");
            return nullptr;
        }
    }
    return exports;
}

napi_value JsEnum::Init(napi_env env, napi_value exports)
{
    JsEnumIntInit(env, exports);
    return exports;
}
} // namespace Drawing
} // namespace OHOS::Rosen