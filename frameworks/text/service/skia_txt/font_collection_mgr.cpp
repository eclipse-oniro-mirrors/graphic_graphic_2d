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

#include "rosen_text/font_collection_mgr.h"

namespace OHOS::Rosen {
FontCollectionMgr& FontCollectionMgr::GetInstance()
{
    static FontCollectionMgr instance;
    return instance;
}

void FontCollectionMgr::InsertSharedFontColleciton(void* key, std::shared_ptr<FontCollection> fontCollection)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    sharedCollections_.insert({key, std::move(fontCollection)});
}

std::shared_ptr<FontCollection> FontCollectionMgr::FindSharedFontColleciton(void* key)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto iter = sharedCollections_.find(key);
    if (iter == sharedCollections_.end()) {
        return nullptr;
    }
    return iter->second;
}

bool FontCollectionMgr::RemoveSharedFontColleciton(void* key)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto iter = sharedCollections_.find(key);
    if (iter == sharedCollections_.end()) {
        return false;
    }
    sharedCollections_.erase(iter);
    return true;
}

void FontCollectionMgr::InsertLocalInstance(uint64_t envId, std::shared_ptr<FontCollection> fontCollection)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    localCollections_.insert({envId, fontCollection});
}

std::shared_ptr<FontCollection> FontCollectionMgr::GetLocalInstance(uint64_t envId)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto iter = localCollections_.find(envId);
    if (iter == localCollections_.end()) {
        return nullptr;
    }
    return iter->second;
}

void FontCollectionMgr::DestroyLocalInstance(uint64_t envId)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    localCollections_.erase(envId);
}

bool FontCollectionMgr::CheckInstanceIsValid(uint64_t envId, std::shared_ptr<FontCollection> fontCollection)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto iter = localCollections_.find(envId);
    // Do not check when ID is not found in the table
    if (iter == localCollections_.end()) {
        return true;
    }
    return iter->second == fontCollection;
}

uint64_t FontCollectionMgr::GetEnvByFontCollection(std::shared_ptr<FontCollection> fontCollection)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (auto iter = localCollections_.begin(); iter != localCollections_.end(); iter++) {
        if (iter->second == fontCollection) {
            return iter->first;
        }
    }
    return 0;
}
} // namespace OHOS::Rosen