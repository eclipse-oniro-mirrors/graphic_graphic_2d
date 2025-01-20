/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "skia_serial_procs.h"

#include "utils/data.h"
#include "utils/log.h"
#include "skia_data.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
SkiaSerialProcs::SkiaSerialProcs() noexcept : skSerialProcs_(new SkSerialProcs()) {}

SkSerialProcs* SkiaSerialProcs::GetSkSerialProcs() const
{
    return skSerialProcs_;
}

void SkiaSerialProcs::SetHasTypefaceProc(bool flag)
{
    hasTypefaceProcs_ = flag;
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS