/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

/**
 * @addtogroup Drawing
 * @{
 *
 * @brief Provides the global text capability.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 *
 * @since 20
 * @version 1.0
 */

/**
 * @file drawing_text_global.h
 *
 * @brief Declares functions related to <b>run</b> in the drawing module.
 *
 * @kit ArkGraphics2D
 * @library libnative_drawing.so
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @since 20
 * @version 1.0
 */

#ifndef DRAWING_TEXT_GLOBAL_H
#define DRAWING_TEXT_GLOBAL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Defines text rendering high contrast mode to enhance readability.
 * @since 20
 * @version 1.0
 */
typedef enum {
    /** Follow system's high contrast settings for text rendering */
    TEXT_FOLLOW_SYSTEM_HIGH_CONTRAST,
    /** Disable high contrast rendering regardless of system settings */
    TEXT_APP_DISABLE_HIGH_CONTRAST,
    /** Enable high contrast rendering regardless of system settings */
    TEXT_APP_ENABLE_HIGH_CONTRAST
} OH_Drawing_TextHighContrast;

/**
 * @brief Visual representations for undefined (.notdef) glyphs.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @since 20
 */
typedef enum {
    /** Uses the glyph defined in the font file, which could be an empty box, blank space, or custom symbol etc. */
    TEXT_UNDEFINED_GLYPH_USE_DEFAULT = 0,
    /** Always render tofu blocks for missing glyphs. */
    TEXT_UNDEFINED_GLYPH_USE_TOFU
} OH_Drawing_TextUndefinedGlyphDisplay;

/**
 * @brief Sets high contrast mode of text rendering.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param action <b>OH_Drawing_TextHighContrast</b> object.
 * @since 20
 */
void OH_Drawing_SetTextHighContrast(OH_Drawing_TextHighContrast action);

/**
 * @brief Controls how undefined glyphs are visually presented, affects all text rendered after this call.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param undefinedGlyphDisplay Indicates a <b>OH_Drawing_TextUndefinedGlyphDisplay</b> to be set.
 * @since 20
 * @version 1.0
 */
void OH_Drawing_SetTextUndefinedGlyphDisplay(OH_Drawing_TextUndefinedGlyphDisplay undefinedGlyphDisplay);
#ifdef __cplusplus
}
#endif
#endif // DRAWING_TEXT_GLOBAL_H

/** @} */