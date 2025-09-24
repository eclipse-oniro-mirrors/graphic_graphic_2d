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

#include "skia_memory_stream.h"

#include "include/core/SkStream.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
SkiaMemoryStream::SkiaMemoryStream() : skMemoryStream_(std::make_unique<SkMemoryStream>()) {}

SkiaMemoryStream::SkiaMemoryStream(const void* data, size_t length, bool copyData)
    : skMemoryStream_(std::make_unique<SkMemoryStream>(data, length, copyData)) {}

SkiaMemoryStream::SkiaMemoryStream(const void* data, size_t length, void (*proc)(const void*, void*), void* context)
    : skMemoryStream_(std::make_unique<SkMemoryStream>(SkData::MakeWithProc(data, length, proc, context)))
{}

std::unique_ptr<SkMemoryStream> SkiaMemoryStream::GetSkMemoryStream()
{
    return std::move(skMemoryStream_);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS