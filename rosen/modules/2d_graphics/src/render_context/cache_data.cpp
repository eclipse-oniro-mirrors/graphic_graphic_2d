/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cache_data.h"
#include <cerrno>
#include <chrono>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cstring>
#include <securec.h>
#include "render_context_log.h"
#ifdef PRELOAD_SHADER_CACHE
#include "shader_cache_utils.h"
#endif

namespace OHOS {
const char* RS_CACHE_MAGIC_HEAD = "OHRS";
const int RS_CACHE_MAGIC_HEAD_LEN = 4;
const int RS_CACHE_HEAD_LEN = 8;
const int RS_BYTE_SIZE = 8;
const int SHADER_CACHE_CLEAR_LEVEL = 2;
const int CHECK_FRAME_FREQUENCY = 10;
namespace Rosen {
CacheData::CacheData(const size_t maxKeySize, const size_t maxValueSize,
    const size_t maxTotalSize, const std::string& fileName)
    : maxKeySize_(maxKeySize),
    maxValueSize_(maxValueSize),
    maxTotalSize_(maxTotalSize),
    cacheDir_(fileName)
{
    softLimit_ = static_cast<size_t>(SHADER_CACHE_SOFT_LIMIT * maxTotalSize);
}

CacheData::~CacheData() {}

uint32_t CacheData::CrcGen(const uint8_t *buffer, size_t bufferSize)
{
    const uint32_t polynoimal = 0xEDB88320;
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < bufferSize ; ++i) {
        crc ^= (static_cast<uint32_t>(buffer[i]));
        for (size_t j = 0; j < RS_BYTE_SIZE; ++j) {
            if (crc & 0x01) {
                crc = (crc >> 1) ^ polynoimal;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFF;
}

bool CacheData::IsValidFile(uint8_t *buffer, size_t bufferSize)
{
    if (memcmp(buffer, RS_CACHE_MAGIC_HEAD, RS_CACHE_MAGIC_HEAD_LEN) != 0) {
        LOGE("abandon, because of mismatched RS_CACHE_MAGIC_HEAD");
        return false;
    }

    uint32_t* storedCrc = reinterpret_cast<uint32_t*>(buffer + RS_CACHE_MAGIC_HEAD_LEN);
    uint32_t computedCrc = CrcGen(buffer + RS_CACHE_HEAD_LEN, bufferSize - RS_CACHE_HEAD_LEN);
    if (computedCrc != *storedCrc) {
        LOGE("abandon, because of mismatched crc code");
        DumpAbnormalCacheToFile(buffer, bufferSize);
        return false;
    }

    return true;
}

void CacheData::DumpAbnormalCacheToFile(uint8_t *buffer, size_t bufferSize)
{
    if (cacheDir_.length() <= 0) {
        LOGE("dump abnormal cache failed, because of empty filename");
        return;
    }
    char canonicalPath[PATH_MAX] = {0};
    if (realpath(cacheDir_.c_str(), canonicalPath) == nullptr) {
        LOGE("dump abnormal cache failed, because of realpath check");
        return;
    }
    std::string abnormalCacheDir = canonicalPath;
    abnormalCacheDir = abnormalCacheDir + "_abnormal";
    int fd = open(abnormalCacheDir.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == ERR_NUMBER) {
        if (errno == EEXIST) {
            if (unlink(abnormalCacheDir.c_str()) == ERR_NUMBER) {
                LOGE("dump abnormal cache failed, because unlinking the existing file fails");
                return;
            }
            fd = open(abnormalCacheDir.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
        }
        if (fd == ERR_NUMBER) {
            LOGE("dump abnormal cache failed, because the file creation fails");
            return;
        }
    }
    fdsan_exchange_owner_tag(fd, 0, LOG_DOMAIN);

    std::time_t curTime = time(nullptr);
    char timestamp[TIME_MAX_LEN] = {0};
    std::strftime(timestamp, TIME_MAX_LEN, "%Y-%m-%d %H:%M:%S", std::localtime(&curTime));
    if (write(fd, timestamp, TIME_MAX_LEN) == ERR_NUMBER) {
        LOGE("dump abnormal cache failed, because fail to write timestamp to disk");
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        unlink(abnormalCacheDir.c_str());
        return;
    }

    if (write(fd, buffer, bufferSize) == ERR_NUMBER) {
        LOGE("dump abnormal cache failed, because fail to write data to disk");
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        unlink(abnormalCacheDir.c_str());
        return;
    }
    fchmod(fd, S_IRUSR);
    fdsan_close_with_tag(fd, LOG_DOMAIN);
    return;
}

void CacheData::CacheReadFromFile(const std::string filePath)
{
    if (filePath.length() <= 0) {
        LOGD("abandon, because of empty filename.");
        return;
    }

    int fd = open(filePath.c_str(), O_RDONLY, 0);
    if (fd == ERR_NUMBER) {
        if (errno != ENOENT) {
            LOGD("abandon, because fail to open file");
        }
        return;
    }
    fdsan_exchange_owner_tag(fd, 0, LOG_DOMAIN);
    struct stat statBuf;
    if (fstat(fd, &statBuf) == ERR_NUMBER) {
        LOGD("abandon, because fail to get the file status");
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return;
    }
    if (statBuf.st_size < 0) {
        LOGD("abandon, negative file size");
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return;
    }

    size_t fileSize = static_cast<size_t>(statBuf.st_size);
    if (fileSize < RS_CACHE_HEAD_LEN || fileSize > maxTotalSize_ * maxMultipleSize_ + RS_CACHE_HEAD_LEN) {
        LOGE("abandon, illegal file size");
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return;
    }
    uint8_t *buffer = reinterpret_cast<uint8_t*>(mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0));
    if (buffer == MAP_FAILED) {
        LOGD("abandon, because of mmap failure:");
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return;
    }

    if (!IsValidFile(buffer, fileSize)) {
        LOGE("abandon, invalid file");
        munmap(buffer, fileSize);
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return;
    }

    uint8_t *shaderBuffer = reinterpret_cast<uint8_t*>(buffer + RS_CACHE_HEAD_LEN);
    if (DeSerialize(shaderBuffer, fileSize - RS_CACHE_HEAD_LEN) < 0) {
        LOGE("abandon, because fail to read file contents");
    }
    munmap(buffer, fileSize);
    fdsan_close_with_tag(fd, LOG_DOMAIN);
}

void CacheData::ReadFromFile()
{
#ifdef PRELOAD_SHADER_CACHE
    // read cache from preload cache dir
    CacheReadFromFile(ShaderCacheUtils::GetPreloadCacheDir());
#endif
    // read cache from user data dir
    CacheReadFromFile(cacheDir_);
}

void CacheData::WriteToFile()
{
    if (cacheDir_.length() <= 0) {
        LOGD("abandon, because of empty filename.");
        return;
    }
    int fd = open(cacheDir_.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == ERR_NUMBER) {
        if (errno == EEXIST) {
            if (unlink(cacheDir_.c_str()) == ERR_NUMBER) {
                LOGD("abandon, because unlinking the existing file fails");
                return;
            }
            fd = open(cacheDir_.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
        }
        if (fd == ERR_NUMBER) {
            LOGD("abandon, because the file creation fails");
            return;
        }
    }
    fdsan_exchange_owner_tag(fd, 0, LOG_DOMAIN);
    size_t cacheSize = SerializedSize();
    if (cacheSize <= 0) {
        LOGD("abandon, illegal serialized size");
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return;
    }
    size_t bufferSize = cacheSize + RS_CACHE_HEAD_LEN;
    uint8_t *buffer = new uint8_t[bufferSize];
    if (!buffer) {
        LOGD("abandon, because fail to allocate buffer for cache content");
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        unlink(cacheDir_.c_str());
        return;
    }
    if (Serialize(buffer + RS_CACHE_HEAD_LEN, cacheSize) < 0) {
        LOGD("abandon, because fail to serialize the CacheData:");
        delete[] buffer;
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        unlink(cacheDir_.c_str());
        return;
    }

    // Write the file rs magic head and CRC code
    if (memcpy_s(buffer, bufferSize, RS_CACHE_MAGIC_HEAD, RS_CACHE_MAGIC_HEAD_LEN) != 0) {
        delete[] buffer;
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        return;
    }
    uint32_t *crc = reinterpret_cast<uint32_t*>(buffer + RS_CACHE_MAGIC_HEAD_LEN);
    *crc = CrcGen(buffer + RS_CACHE_HEAD_LEN, cacheSize);

    if (write(fd, buffer, bufferSize) == ERR_NUMBER) {
        LOGD("abandon, because fail to write to disk");
        delete[] buffer;
        fdsan_close_with_tag(fd, LOG_DOMAIN);
        unlink(cacheDir_.c_str());
        return;
    }
    delete[] buffer;
    fchmod(fd, S_IRUSR);
    fdsan_close_with_tag(fd, LOG_DOMAIN);
}

void CacheData::Rewrite(const void *key, const size_t keySize, const void *value, const size_t valueSize)
{
    if (maxKeySize_ < keySize || maxValueSize_ < valueSize ||
        maxTotalSize_ < keySize + valueSize || keySize == 0 || valueSize <= 0) {
        LOGD("abandon, because of illegal content size");
        return;
    }
    std::shared_ptr<DataPointer> fakeDataPointer(std::make_shared<DataPointer>(key, keySize, false));
    ShaderPointer fakeShaderPointer(fakeDataPointer, nullptr);
    bool isShaderFound = false;
    size_t newTotalSize = 0;
    while (!isShaderFound) {
        auto index = std::lower_bound(shaderPointers_.begin(), shaderPointers_.end(), fakeShaderPointer);
        if (index == shaderPointers_.end() || fakeShaderPointer < *index) {
            std::shared_ptr<DataPointer> keyPointer(std::make_shared<DataPointer>(key, keySize, true));
            std::shared_ptr<DataPointer> valuePointer(std::make_shared<DataPointer>(value, valueSize, true));
            newTotalSize = totalSize_ + keySize + valueSize;
            if (IfSizeValidate(newTotalSize, keySize + valueSize)) {
                shaderPointers_.insert(index, ShaderPointer(keyPointer, valuePointer));
                totalSize_ = newTotalSize;
                break;
            }
            if (IfSkipClean(keySize + valueSize)) {
                break;
            }
            if (IfCleanFinished()) {
                continue;
            }
            break;
        } else {
            std::shared_ptr<DataPointer> valuePointer(std::make_shared<DataPointer>(value, valueSize, true));
            std::shared_ptr<DataPointer> oldValuePointer(index->GetValuePointer());
            newTotalSize = totalSize_ + valueSize - oldValuePointer->GetSize();
            size_t addedSize = (valueSize > oldValuePointer->GetSize()) ? valueSize - oldValuePointer->GetSize() : 0;
            if (IfSizeValidate(newTotalSize, addedSize)) {
                index->SetValue(valuePointer);
                totalSize_ = newTotalSize;
                break;
            }
            if (IfSkipClean(addedSize)) {
                break;
            }
            if (IfCleanFinished()) {
                continue;
            }
            break;
        }
        isShaderFound = true;
    }
    cleanThreshold_ = 0;
}

std::tuple<CacheData::ErrorCode, size_t> CacheData::Get(const void *key, const size_t keySize,
    void *value, const size_t valueSize)
{
    if (maxKeySize_ < keySize) {
        LOGD("abandon, because the key is too large");
        return {ErrorCode::VALUE_SIZE_OVER_MAX_SIZE, 0};
    }
    std::shared_ptr<DataPointer> fakeDataPointer(std::make_shared<DataPointer>(key, keySize, false));
    ShaderPointer fakeShaderPointer(fakeDataPointer, nullptr);
    auto index = std::lower_bound(shaderPointers_.begin(), shaderPointers_.end(), fakeShaderPointer);
    if (index == shaderPointers_.end() || fakeShaderPointer < *index) {
        LOGD("abandon, because no key is found");
        return {ErrorCode::KEY_NOT_FOUND, 0};
    }
    std::shared_ptr <DataPointer> valuePointer(index->GetValuePointer());
    size_t valuePointerSize = valuePointer->GetSize();
    if (valuePointerSize > valueSize) {
        LOGD("abandon, because of insufficient buffer space");
        return {ErrorCode::VALUE_SIZE_TOO_SAMLL, valuePointerSize};
    }
    if (memcpy_s(value, valueSize, valuePointer->GetData(), valuePointerSize)) {
        LOGD("abandon, failed to copy content");
        return {ErrorCode::COPY_FAILED, 0};
    }
    return {ErrorCode::NO_ERR, valuePointerSize};
}

size_t CacheData::SerializedSize() const
{
    size_t size = Align4(sizeof(Header));
    for (const ShaderPointer &p: shaderPointers_) {
        std::shared_ptr <DataPointer> const &keyPointer = p.GetKeyPointer();
        std::shared_ptr <DataPointer> const &valuePointer = p.GetValuePointer();
        size += Align4(sizeof(ShaderData) + keyPointer->GetSize() + valuePointer->GetSize());
    }
    return size;
}

int CacheData::Serialize(uint8_t *buffer, const size_t size) const
{
    if (size < sizeof(Header)) {
        LOGD("abandon because of insufficient buffer space.");
        return -EINVAL;
    }
    Header *header = reinterpret_cast<Header *>(buffer);
    header->numShaders_ = shaderPointers_.size();
    size_t byteOffset = Align4(sizeof(Header));
    size_t headSize = sizeof(ShaderData);

    uint8_t *byteBuffer = reinterpret_cast<uint8_t *>(buffer);
    for (const ShaderPointer &p: shaderPointers_) {
        std::shared_ptr<DataPointer> const &keyPointer = p.GetKeyPointer();
        std::shared_ptr<DataPointer> const &valuePointer = p.GetValuePointer();
        size_t keySize = keyPointer->GetSize();
        size_t valueSize = valuePointer->GetSize();
        size_t pairSize = sizeof(ShaderData) + keySize + valueSize;
        size_t alignedSize = Align4(pairSize);
        if (byteOffset + alignedSize > size) {
            LOGD("abandon because of insufficient buffer space.");
            return -EINVAL;
        }

        ShaderData *shaderBuffer = reinterpret_cast<ShaderData *>(&byteBuffer[byteOffset]);
        shaderBuffer->keySize_ = keySize;
        shaderBuffer->valueSize_ = valueSize;
        size_t sizeLeft = size - byteOffset - headSize;
        if (memcpy_s(shaderBuffer->data_, sizeLeft, keyPointer->GetData(), keySize)) {
            LOGD("abandon, failed to copy key");
            return -EINVAL;
        }
        if (memcpy_s(shaderBuffer->data_ + keySize, sizeLeft - keySize, valuePointer->GetData(), valueSize)) {
            LOGD("abandon, failed to copy value");
            return -EINVAL;
        }
        if (alignedSize > pairSize) {
            auto ret = memset_s(shaderBuffer->data_ + keySize + valueSize, alignedSize - pairSize, 0,
                alignedSize - pairSize);
            if (ret != EOK) {
                LOGD("abandon, failed to memset_s");
                return -EINVAL;
            }
        }
        byteOffset += alignedSize;
    }
    return 0;
}

int CacheData::DeSerialize(uint8_t const *buffer, const size_t size)
{
    shaderPointers_.clear();
    if (size < sizeof(Header)) {
        LOGD("abandon, not enough room for cache header");
    }

    if (buffer == nullptr) {
        LOGD("abandon, buffer is null");
        return -EINVAL;
    }
    const Header *header = reinterpret_cast<const Header *>(buffer);
    size_t numShaders = header->numShaders_;
    size_t byteOffset = Align4(sizeof(Header));

    const uint8_t *byteBuffer = reinterpret_cast<const uint8_t *>(buffer);
    for (size_t i = 0; i < numShaders; i++) {
        if (byteOffset + sizeof(ShaderData) > size) {
            shaderPointers_.clear();
            LOGD("abandon because of insufficient buffer space");
            return -EINVAL;
        }
        const ShaderData *shaderBuffer = reinterpret_cast<const ShaderData *>(&byteBuffer[byteOffset]);
        size_t keySize = shaderBuffer->keySize_;
        size_t valueSize = shaderBuffer->valueSize_;
        size_t pairSize = sizeof(ShaderData) + keySize + valueSize;
        size_t alignedSize = Align4(pairSize);
        if (byteOffset + alignedSize > size) {
            shaderPointers_.clear();
            LOGD("abandon, not enough room for cache headers");
            return -EINVAL;
        }

        const uint8_t *data = shaderBuffer->data_;
        Rewrite(data, keySize, data + keySize, valueSize);
        byteOffset += alignedSize;
    }
    return 0;
}

bool CacheData::IfSizeValidate(const size_t newSize, const size_t addedSize) const
{
    // check if size is ok and we don't neet to clean the shaders
    if (newSize <= maxTotalSize_ || addedSize == 0) {
        return true;
    }
    return false;
}

bool CacheData::IfSkipClean(const size_t addedSize) const
{
    // check if the new shader is still too large after cleaning
    size_t maxPermittedSize = maxTotalSize_ - maxTotalSize_ / cleanLevel_;
    if (addedSize > maxPermittedSize) {
        LOGD("new shader is too large, abandon insert");
        return true;
    }
    return false;
}

bool CacheData::IfCleanFinished()
{
    if (!cleanThreshold_) {
        RandClean(maxTotalSize_ / cleanLevel_);
        return true;
    } else {
        LOGD("abandon, failed to clean the shaders");
        return false;
    }
}

void CacheData::RandClean(const size_t cleanThreshold)
{
    if (cleanThreshold == 0) {
        LOGD("CleanThreshold must be > 0");
        return;
    }
    if (cleanThreshold_ == 0) {
        if (!CleanInit()) {
            return;
        }
    }
    cleanThreshold_ = cleanThreshold;

    while (totalSize_ > cleanThreshold_) {
        if (!StepClean()) {
            break;
        }
    }
}

bool CacheData::CleanInit()
{
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    if (now < 0) {
        LOGD("abandon, illegal negative now value");
        return false;
    }
    unsigned long currentTime = static_cast<unsigned long>(now);
    for (int indexRand = 0; indexRand < randLength_; ++indexRand) {
        cleanInit_[indexRand] = (currentTime >> (indexRand * randShift_)) & 0xFFFF;
    }
    return true;
}

bool CacheData::StepClean()
{
    long int randIndex = nrand48(cleanInit_);
    if (randIndex < 0) {
        LOGD("abandon, illegal negative randIndex value");
        return false;
    }
    size_t sizeRandIndex = static_cast<size_t>(randIndex);
    size_t currentSize = shaderPointers_.size();
    if (currentSize == 0) {
        LOGD("abandon, shader is empty, nothing to clean");
        return false;
    }
    size_t removeIndex = sizeRandIndex % (currentSize);
    if (!Clean(removeIndex)) {
        LOGD("abandon, cleaned nothing");
        return false;
    }
    return true;
}

size_t CacheData::Clean(const size_t removeIndex)
{
    if (removeIndex >= shaderPointers_.size()) {
        LOGD("illegal shader index, abandon cleaning");
        return 0;
    }
    const ShaderPointer &shader(shaderPointers_[removeIndex]);
    size_t reducedSize = shader.GetKeyPointer()->GetSize() + shader.GetValuePointer()->GetSize();
    totalSize_ -= reducedSize;
    shaderPointers_.erase(shaderPointers_.begin() + removeIndex);
    return reducedSize;
}

bool CacheData::CheckShaderCacheOverSoftLimit() const
{
    return totalSize_ >= softLimit_;
}

void CacheData::PurgeShaderCacheAfterAnimate(const std::function<bool(void)>& nextFrameHasArrived)
{
    if (!CleanInit()) {
        return;
    }
    if (!nextFrameHasArrived) {
        LOGD("nextFrame Func is Empty");
        return;
    }
    const size_t cleanTarget = maxTotalSize_ / SHADER_CACHE_CLEAR_LEVEL;
    int cleanTimes = 0;
    while (totalSize_ > cleanTarget && (cleanTimes % CHECK_FRAME_FREQUENCY != 0 || !nextFrameHasArrived())) {
        if (!StepClean()) {
            break;
        }
        cleanTimes++;
    }
}

CacheData::DataPointer::DataPointer(const void *data, size_t size, bool ifOccupy)
    : pointer_(nullptr),
    size_(size),
    toFree_(ifOccupy)
{
    if (ifOccupy) {
        pointer_ = malloc(size);
    } else {
        pointer_ = data;
    }

    if (data != nullptr && ifOccupy) {
        if (memcpy_s(const_cast<void *>(pointer_), size, data, size)) {
            LOGD("abandon: failed to copy data");
            return;
        }
    }
}

CacheData::DataPointer::~DataPointer()
{
    if (toFree_) {
        free(const_cast<void *>(pointer_));
        pointer_ = nullptr;
    }
}

CacheData::ShaderPointer::ShaderPointer() {}

CacheData::ShaderPointer::ShaderPointer(const std::shared_ptr <DataPointer> &key,
                                        const std::shared_ptr <DataPointer> &value)
    : keyPointer_(key),
    valuePointer_(value) {}

CacheData::ShaderPointer::ShaderPointer(const ShaderPointer &sp)
    : keyPointer_(sp.keyPointer_),
    valuePointer_(sp.valuePointer_) {}
}   // namespace Rosen
}   // namespace OHOS