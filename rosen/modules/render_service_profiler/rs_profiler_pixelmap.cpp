/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "rs_profiler_pixelmap.h"

#include <securec.h>
#include <surface.h>
#include <sys/mman.h>

#include "ipc_file_descriptor.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "rs_profiler_base.h"

namespace OHOS::Media {

// This class has to be 'reimplemented' here to get access to the PixelMap's private functions.
// It works ONLY thanks to the 'friend class ImageSource' in PixelMap.
class ImageSource {
public:
    // See PixelMap::Unmarshalling
    // foundation/multimedia/image_framework/frameworks/innerkitsimpl/common/src/pixel_map.cpp
    static PixelMap* Unmarshalling(uint64_t id, Parcel& parcel);

private:
    // See foundation/multimedia/image_framework/frameworks/innerkitsimpl/utils/include/image_utils.h
    static int32_t SurfaceBufferReference(void* buffer);
    static int32_t GetPixelBytes(const PixelFormat& pixelFormat);
};

int32_t ImageSource::GetPixelBytes(const PixelFormat& pixelFormat)
{
    constexpr int32_t alphA8Bytes = 1;
    constexpr int32_t rgB565Bytes = 2;
    constexpr int32_t rgB888Bytes = 3;
    constexpr int32_t argB8888Bytes = 4;
    constexpr uint8_t rgbaF16Bytes = 8;
    constexpr int32_t astc4X4Bytes = 1;
    constexpr int32_t nV21Bytes = 2; // Each pixel is sorted on 3/2 bytes.

    int pixelBytes = 0;
    switch (pixelFormat) {
        case PixelFormat::ARGB_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGBA_8888:
        case PixelFormat::CMYK:
            pixelBytes = argB8888Bytes;
            break;
        case PixelFormat::ALPHA_8:
            pixelBytes = alphA8Bytes;
            break;
        case PixelFormat::RGB_888:
            pixelBytes = rgB888Bytes;
            break;
        case PixelFormat::RGB_565:
            pixelBytes = rgB565Bytes;
            break;
        case PixelFormat::RGBA_F16:
            pixelBytes = rgbaF16Bytes;
            break;
        case PixelFormat::NV21:
        case PixelFormat::NV12:
            pixelBytes = nV21Bytes; // perl pixel 1.5 Bytes but return int so return 2
            break;
        case PixelFormat::ASTC_4x4:
        case PixelFormat::ASTC_6x6:
        case PixelFormat::ASTC_8x8:
            pixelBytes = astc4X4Bytes;
            break;
        default:
            break;
    }
    return pixelBytes;
}

int32_t ImageSource::SurfaceBufferReference(void* buffer)
{
    if (buffer == nullptr) {
        return ERR_SURFACEBUFFER_REFERENCE_FAILED;
    }
    auto* ref = reinterpret_cast<OHOS::RefBase*>(buffer);
    ref->IncStrongRef(ref);
    return SUCCESS;
}

PixelMap* ImageSource::Unmarshalling(uint64_t id, Parcel& parcel)
{
    auto* pixelMap = new PixelMap();
    if (!pixelMap) {
        return nullptr;
    }

    ImageInfo imgInfo;
    if (!pixelMap->ReadImageInfo(parcel, imgInfo)) {
        delete pixelMap;
        return nullptr;
    }

    pixelMap->SetEditable(parcel.ReadBool());

    const bool isAstc = parcel.ReadBool();
    pixelMap->SetAstc(isAstc);

    auto allocType = static_cast<AllocatorType>(parcel.ReadInt32());
    /*int32_t csm =*/parcel.ReadInt32();
    int32_t rowDataSize = parcel.ReadInt32();
    int32_t bufferSize = parcel.ReadInt32();
    int32_t bytesPerPixel = GetPixelBytes(imgInfo.pixelFormat);
    if (bytesPerPixel == 0) {
        delete pixelMap;
        return nullptr;
    }
    if ((!isAstc) && bufferSize != rowDataSize * imgInfo.size.height) {
        delete pixelMap;
        return nullptr;
    }
    uint8_t* base = nullptr;
    void* context = nullptr;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
    constexpr int headerLength = 24;
    if (allocType == AllocatorType::SHARE_MEM_ALLOC) {
        int fd = pixelMap->ReadFileDescriptor(parcel);
        if (fd < 0) {
            Rosen::ReplayImageCacheRecord* ptr = Rosen::RSProfilerBase::ReplayImageGet(id);

            if (ptr != nullptr && static_cast<uint32_t>(bufferSize) == ptr->imageSize) {
                // get image from file
                base = static_cast<uint8_t*>(malloc(bufferSize));
                memmove(base, ptr->image.get(), bufferSize);
                context = nullptr;

                parcel.SkipBytes(headerLength);
            } else {
                delete pixelMap;
                return nullptr;
            }
        } else {
            void* ptr = ::mmap(nullptr, bufferSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (ptr == MAP_FAILED) { // NOLINT
                ptr = ::mmap(nullptr, bufferSize, PROT_READ, MAP_SHARED, fd, 0);
                if (ptr == MAP_FAILED) { // NOLINT
                    ::close(fd);
                    delete pixelMap;
                    return nullptr;
                }
            }

            Rosen::RSProfilerBase::ReplayImageAdd(id, ptr, bufferSize, headerLength);

            context = new int32_t();
            if (context == nullptr) {
                ::munmap(ptr, bufferSize);
                ::close(fd);
                delete pixelMap;
                return nullptr;
            }
            *static_cast<int32_t*>(context) = fd;
            base = static_cast<uint8_t*>(ptr);
        }
    } else if (allocType == AllocatorType::DMA_ALLOC) {
        Rosen::ReplayImageCacheRecord* ptr = Rosen::RSProfilerBase::ReplayImageGet(id);

        if (ptr == nullptr) {
            const size_t size1 = parcel.GetReadableBytes();

            // original code
            sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
            surfaceBuffer->ReadFromMessageParcel(static_cast<MessageParcel&>(parcel));
            auto* virAddr = static_cast<uint8_t*>(surfaceBuffer->GetVirAddr());
            void* nativeBuffer = surfaceBuffer.GetRefPtr();
            SurfaceBufferReference(nativeBuffer);
            base = virAddr;
            context = nativeBuffer;

            const size_t size2 = parcel.GetReadableBytes();

            Rosen::RSProfilerBase::ReplayImageAdd(id, virAddr, bufferSize, size1 - size2);

        } else {
            allocType = Media::AllocatorType::SHARE_MEM_ALLOC;

            parcel.SkipBytes(ptr->skipBytes);

            base = static_cast<uint8_t*>(malloc(bufferSize));
            memmove(base, ptr->image.get(), bufferSize);
            context = nullptr;
        }

    } else {
        base = pixelMap->ReadImageData(parcel, bufferSize);
        if (base == nullptr) {
            delete pixelMap;
            return nullptr;
        }
    }
#else
    base = ReadImageData(parcel, bufferSize);
    if (base == nullptr) {
        delete pixelMap;
        return nullptr;
    }
#endif

    uint32_t ret = pixelMap->SetImageInfo(imgInfo);
    if (ret != SUCCESS) {
        if (pixelMap->freePixelMapProc_ != nullptr) {
            pixelMap->freePixelMapProc_(base, context, bufferSize);
        }
        pixelMap->ReleaseMemory(allocType, base, context, bufferSize);
        if (allocType == AllocatorType::SHARE_MEM_ALLOC && context != nullptr) {
            delete static_cast<int32_t*>(context);
        }
        delete pixelMap;
        return nullptr;
    }
    pixelMap->SetPixelsAddr(base, context, bufferSize, allocType, nullptr);
    if (!pixelMap->ReadTransformData(parcel, pixelMap)) {
        delete pixelMap;
        return nullptr;
    }
    if (!pixelMap->ReadAstcRealSize(parcel, pixelMap)) {
        delete pixelMap;
        return nullptr;
    }
    return pixelMap;
}

} // namespace OHOS::Media

namespace OHOS::Rosen {

using PixelMapHelper = OHOS::Media::ImageSource;

OHOS::Media::PixelMap* RSProfilerPixelMap::Unmarshalling(Parcel& parcel)
{
    constexpr uint32_t bits32 = 32u;

    const uint32_t high = parcel.ReadInt32();
    const uint32_t low = parcel.ReadInt32();
    const uint64_t id = (static_cast<uint64_t>(high) << bits32) | low;

    return PixelMapHelper::Unmarshalling(id, parcel);
}

} // namespace OHOS::Rosen