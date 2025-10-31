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

#include "dirty_region/rs_filter_dirty_collector.h"

namespace OHOS {
namespace Rosen {
std::unordered_set<NodeId> RSFilterDirtyCollector::validOcclusionFilterCache_ = {};
bool RSFilterDirtyCollector::enablePartialRender_ = true;

void RSFilterDirtyCollector::CollectFilterDirtyRegionInfo(const FilterDirtyRegionInfo& filterInfo, bool syncToRT)
{
    auto& list = syncToRT ? pureCleanFilters_ : filtersWithBelowDirty_;
    list.emplace_back(filterInfo);
}

FilterDirtyRegionInfoList& RSFilterDirtyCollector::GetFilterDirtyRegionInfoList(bool syncToRT)
{
    return syncToRT ? pureCleanFilters_ : filtersWithBelowDirty_;
}

void RSFilterDirtyCollector::OnSync(RSFilterDirtyCollector& target) const
{
    target.pureCleanFilters_ = pureCleanFilters_;
}

void RSFilterDirtyCollector::Clear()
{
    filtersWithBelowDirty_.clear();
    pureCleanFilters_.clear();
    pendingPurgeFilterRegion_.Reset();
}

void RSFilterDirtyCollector::AddPendingPurgeFilterRegion(const Occlusion::Region& region)
{
    pendingPurgeFilterRegion_.OrSelf(region);
}

const Occlusion::Region& RSFilterDirtyCollector::GetPendingPurgeFilterRegion() const
{
    return pendingPurgeFilterRegion_;
}

void RSFilterDirtyCollector::ClearPendingPurgeFilterRegion()
{
    pendingPurgeFilterRegion_.Reset();
}
} // namespace Rosen
} // namespace OHOS
