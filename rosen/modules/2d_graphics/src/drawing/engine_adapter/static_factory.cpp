/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.. All rights reserved.
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

#include "static_factory.h"

#include "skia_adapter/skia_static_factory.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
using EngineStaticFactory = SkiaStaticFactory;

std::shared_ptr<TextBlob> StaticFactory::MakeFromText(const void* text, size_t byteLength,
    const Font& font, TextEncoding encoding)
{
    return EngineStaticFactory::MakeFromText(text, byteLength, font, encoding);
}

std::shared_ptr<TextBlob> StaticFactory::MakeFromRSXform(const void* text, size_t byteLength,
    const RSXform xform[], const Font& font, TextEncoding encoding)
{
    return EngineStaticFactory::MakeFromRSXform(text, byteLength, xform, font, encoding);
}

std::shared_ptr<Typeface> StaticFactory::MakeFromFile(const char path[])
{
    return EngineStaticFactory::MakeFromFile(path);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS