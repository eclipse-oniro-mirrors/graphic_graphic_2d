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

#ifndef OBJECT_MGR_H
#define OBJECT_MGR_H

#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "text/typeface.h"

namespace OHOS {
namespace Rosen {
class FontCollection;
}
} // namespace OHOS

namespace OHOS {
namespace Rosen {
namespace Drawing {
class ObjectMgr {
public:
    static std::shared_ptr<ObjectMgr> GetInstance() noexcept(true);
    void AddObject(void* obj);
    bool HasObject(void* obj);
    bool RemoveObject(void* obj);
    size_t ObjectCount();

private:
    static inline std::shared_ptr<ObjectMgr> objectMgr = nullptr;
    std::vector<void*> vector_;
    std::mutex mutex_;
};

class TypefaceMgr {
public:
    TypefaceMgr(const TypefaceMgr&) = delete;
    TypefaceMgr& operator=(const TypefaceMgr&) = delete;

    static TypefaceMgr& GetInstance();

    void Insert(void* key, std::shared_ptr<Typeface> typeface);
    std::shared_ptr<Typeface> Find(void* key);
    bool Remove(void* key);

private:
    TypefaceMgr() {}

    std::unordered_map<void*, std::shared_ptr<Typeface>> typeface_;
    std::mutex mutex_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif
