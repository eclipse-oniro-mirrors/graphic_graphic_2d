/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef C_INCLUDE_DRAWING_TEXT_CONVERTOR_H
#define C_INCLUDE_DRAWING_TEXT_CONVERTOR_H

#include "drawing_text_declaration.h"
#include "rosen_text/ui/font_collection.h"
#include "rosen_text/ui/typography.h"
#include "rosen_text/ui/typography_create.h"

/**
 * @brief convert OH_Drawing_FontCollection to rosen::FontCollection.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param OH_Drawing_FontCollection a pointer to OH_Drawing_FontCollection object
 * @return rosen::FontCollection a pointer to rosen::FontCollection
 */
rosen::FontCollection* ConvertToOriginalText(OH_Drawing_FontCollection* fontCollection);

/**
 * @brief convert rosen::FontCollection to OH_Drawing_FontCollection.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param rosen::FontCollection a pointer to rosen::FontCollection object
 * @return OH_Drawing_FontCollection a pointer to OH_Drawing_FontCollection
 */
OH_Drawing_FontCollection* ConvertToNDKText(rosen::FontCollection* fontCollection);

/**
 * @brief convert OH_Drawing_TypographyStyle to rosen::TypographyStyle.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param OH_Drawing_TypographyStyle a pointer to OH_Drawing_TypographyStyle object
 * @return rosen::TypographyStyle a pointer to rosen::TypographyStyle
 */
rosen::TypographyStyle* ConvertToOriginalText(OH_Drawing_TypographyStyle* style);

/**
 * @brief convert rosen::TypographyStyle to OH_Drawing_TypographyStyle.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param rosen::TypographyStyle a pointer to rosen::TypographyStyle object
 * @return OH_Drawing_TypographyStyle a pointer to OH_Drawing_TypographyStyle
 */
OH_Drawing_TypographyStyle* ConvertToNDKText(rosen::TypographyStyle* style);

/**
 * @brief convert OH_Drawing_TypographyCreate to rosen::TypographyCreate.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param OH_Drawing_TypographyCreate a pointer to OH_Drawing_TypographyCreate object
 * @return rosen::TypographyCreate a pointer to rosen::TypographyCreate
 */
rosen::TypographyCreate* ConvertToOriginalText(OH_Drawing_TypographyCreate* handler);

/**
 * @brief convert rosen::TypographyCreate to OH_Drawing_TypographyCreate.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param rosen::TypographyCreate a pointer to rosen::TypographyCreate object
 * @return OH_Drawing_TypographyCreate a pointer to rOH_Drawing_TypographyCreate
 */
OH_Drawing_TypographyCreate* ConvertToNDKText(rosen::TypographyCreate* handler);

/**
 * @brief convert OH_Drawing_TextStyle to rosen::TextStyle.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param OH_Drawing_TextStyle a pointer to OH_Drawing_TextStyle object
 * @return rosen::TextStyle a pointer to rosen::TextStyle
 */
rosen::TextStyle* ConvertToOriginalText(OH_Drawing_TextStyle* style);

/**
 * @brief convert OH_Drawing_Typography to osen::Typography.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param OH_Drawing_Typography a pointer to OH_Drawing_Typography object
 * @return rosen::Typography a pointer to rosen::Typography
 */
rosen::Typography* ConvertToOriginalText(OH_Drawing_Typography* typography);

/**
 * @brief convert rosen::Typography to OH_Drawing_Typography.
 *
 * @syscap SystemCapability.Graphic.Graphic2D.NativeDrawing
 * @param rosen::Typography a pointer to rosen::Typography object
 * @return OH_Drawing_Typography a pointer to OH_Drawing_Typography
 */
OH_Drawing_Typography* ConvertToNDKText(rosen::Typography* typography);

#endif

