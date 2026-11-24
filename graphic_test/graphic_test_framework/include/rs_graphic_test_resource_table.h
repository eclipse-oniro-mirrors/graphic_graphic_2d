/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef RS_GRAPHIC_TEST_RESOURCE_TABLE_H
#define RS_GRAPHIC_TEST_RESOURCE_TABLE_H

#include <vector>

#include "rs_graphic_test_resource.h"

namespace OHOS {
namespace Rosen {

// The compiled-in resource table: device path, required flag, and optional expected size.
// size == 0 means presence-only checking on the device.
const std::vector<ResourceEntry>& BuiltinResourceEntries();

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_RESOURCE_TABLE_H
