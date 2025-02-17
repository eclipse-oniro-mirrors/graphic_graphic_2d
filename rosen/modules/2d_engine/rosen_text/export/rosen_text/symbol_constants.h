/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.. All rights reserved.
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

#ifndef SYMBOL_CONSTANTS_H
#define SYMBOL_CONSTANTS_H

#include <cstddef>
#include <cstdint>

namespace OHOS {
namespace Rosen {

enum class LoadSymbolErrorCode {
    SUCCESS = 0,
    JSON_ERROR,
    LOAD_FAILED,
};

enum class SymbolType {
    SYSTEM = 0,
    CUSTOM,
};

} // namespace Rosen
} // namespace OHOS

#endif // SYMBOL_CONSTANTS_H