
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ARRAY_MGR_H
#define ARRAY_MGR_H

namespace OHOS {
namespace Rosen {
enum ObjectType {
    INVALID = -1,
    STRING = 0,
    TEXT_LINE = 1,
    TEXT_RUN = 2,
    DRAWING_RECT = 3,
};

struct ObjectArray {
    void* addr = nullptr;
    size_t num = 0;
    ObjectType type = ObjectType::INVALID;
};
} // namespace Rosen
} // namespace OHOS
#endif // ARRAY_MGR_H