/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "transaction/rs_occlusion_data.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
RSOcclusionData::~RSOcclusionData() noexcept
{
}

RSOcclusionData* RSOcclusionData::Unmarshalling(Parcel& parcel)
{
    auto data = new RSOcclusionData();
    uint32_t size{0};
    if (!parcel.ReadUint32(size)) {
        ROSEN_LOGE("RSOcclusionData::Unmarshalling Read size failed");
        delete data;
        return nullptr;
    }
    size_t readableSize = parcel.GetReadableBytes() / (sizeof(uint64_t) + sizeof(uint32_t));
    size_t len = static_cast<size_t>(size);
    if (len > readableSize || len > data->visibleData_.max_size()) {
        RS_LOGE("RSOcclusionData Unmarshalling Failed read vector, size:%{public}zu, readableSize:%{public}zu",
            len, readableSize);
        return data;
    }
    for (uint32_t i = 0; i < size; i++) {
        uint64_t id{0};
        uint32_t visibelLevel{0};
        if (!parcel.ReadUint64(id) || !parcel.ReadUint32(visibelLevel)) {
            ROSEN_LOGE("RSOcclusionData::Unmarshalling Read parcel failed");
            delete data;
            return nullptr;
        }
        data->visibleData_.emplace_back(std::make_pair(id, (WINDOW_LAYER_INFO_TYPE)visibelLevel));
    }
    return data;
}

bool RSOcclusionData::Marshalling(Parcel& parcel) const
{
    parcel.WriteUint32(visibleData_.size());
    for (auto& data : visibleData_) {
        if (!parcel.WriteUint64(data.first)) {
            RS_LOGE("RSOcclusionData::Marshalling WriteUint64 first failed");
            return false;
        }
        if (!parcel.WriteUint32(data.second)) {
            RS_LOGE("RSOcclusionData::Marshalling WriteUint32 second failed");
            return false;
        }
    }

    return true;
}
} // namespace Rosen
} // namespace OHOS
