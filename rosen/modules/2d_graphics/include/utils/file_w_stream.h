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

#ifndef FILE_W_STREAM_H
#define FILE_W_STREAM_H

#include "impl_interface/file_w_stream_impl.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

class FileWStream {
public:
    FileWStream(const char path[]) noexcept;
    virtual ~FileWStream() {}

    template <typename T>
    T *GetImpl() const
    {
        return fileWStreamImplPtr_->DowncastingTo<T>();
    }
    bool IsValid();

private:
    std::shared_ptr<FileWStreamImpl> fileWStreamImplPtr_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif