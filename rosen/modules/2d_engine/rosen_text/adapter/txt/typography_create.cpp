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

#include "typography_create.h"

#include "convert.h"
#include "typography.h"

namespace OHOS {
namespace Rosen {
std::unique_ptr<TypographyCreate> TypographyCreate::Create(const TypographyStyle& style,
    std::shared_ptr<FontCollection> collection)
{
    return std::make_unique<AdapterTxt::TypographyCreate>(style, collection);
}

namespace AdapterTxt {
TypographyCreate::TypographyCreate(const TypographyStyle& style,
    std::shared_ptr<OHOS::Rosen::FontCollection> collection)
{
    auto paragraphStyle = Convert(style);
    auto txtFontCollection = Convert(collection)->Get();
    builder_ = txt::ParagraphBuilder::CreateTxtBuilder(paragraphStyle, txtFontCollection);
}

void TypographyCreate::PushStyle(const TextStyle& style)
{
    auto txtTextStyle = Convert(style);
    builder_->PushStyle(txtTextStyle);
}

void TypographyCreate::PopStyle()
{
    builder_->Pop();
}

void TypographyCreate::AppendText(const std::u16string& text)
{
    builder_->AddText(text);
}

void TypographyCreate::AppendSymbol(const uint32_t& symbolId)
{
    builder_->AddSymbol(symbolId);
}

void TypographyCreate::AppendPlaceholder(const PlaceholderSpan& span)
{
    auto txtPlaceholderRun = Convert(span);
    builder_->AddPlaceholder(txtPlaceholderRun);
}

std::unique_ptr<OHOS::Rosen::Typography> TypographyCreate::CreateTypography()
{
    auto paragraph = builder_->Build();
    return std::make_unique<Typography>(std::move(paragraph));
}
} // namespace AdapterTxt
} // namespace Rosen
} // namespace OHOS
