/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.. All rights reserved.
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
#include "placeholder_run.h"

namespace OHOS {
namespace Rosen {
namespace SPText {
PlaceholderRun::PlaceholderRun() {}

PlaceholderRun::PlaceholderRun(
    double width, double height, PlaceholderAlignment alignment, TextBaseline baseline, double baselineOffset)
    : width(width), height(height), alignment(alignment), baseline(baseline), baselineOffset(baselineOffset)
{}
} // namespace SPText
} // namespace Rosen
} // namespace OHOS
