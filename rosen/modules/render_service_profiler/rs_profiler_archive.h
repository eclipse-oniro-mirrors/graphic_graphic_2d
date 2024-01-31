#pragma once

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace OHOS::Rosen {

class Archive {
public:
    virtual bool IsReading() const
    {
        return true;
    }

    void Serialize(float& value);
    void Serialize(double& value);
    void Serialize(int32_t& value);
    void Serialize(uint32_t& value);
    void Serialize(size_t& value);
    void Serialize(std::string& value);

    template<typename T>
    void Serialize(std::vector<T>& vector)
    {
        SerializeVectorBase(vector);
        for (T& value : vector)
            Serialize(value);
    }

    template<typename T>
    void Serialize(std::vector<T>& vector, void (*serializer)(Archive&, T&))
    {
        SerializeVectorBase(vector);
        for (T& value : vector)
            serializer(*this, value);
    }

    template<typename T>
    void SerializeNonFlat(std::vector<T>& vector)
    {
        SerializeVectorBase(vector);
        for (T& value : vector)
            value.Serialize(*this);
    }

    virtual void Serialize(void* data, size_t size) = 0;

protected:
    Archive() = default;
    virtual ~Archive() = default;

    template<typename T>
    void SerializeVectorBase(std::vector<T>& vector)
    {
        size_t size = vector.size();
        Serialize(size);

        if (IsReading())
            vector.resize(size);
    }
};

// Data archives

class DataArchive : public Archive {
public:
    DataArchive(size_t offset = 0) : offset_(offset) {}

    virtual ~DataArchive() = default;

protected:
    size_t offset_ = 0;
};

class DataReader final : public DataArchive {
public:
    DataReader(const std::vector<char>& data, size_t offset = 0) : DataArchive(offset), data_(data) {}

    virtual void Serialize(void* data, size_t size) override
    {
        if (data && (size > 0) && (offset_ + size <= data_.size())) {
            std::memmove(data, data_.data() + offset_, size);
            offset_ += size;
        }
    }

protected:
    const std::vector<char>& data_;
};

class DataWriter final : public DataArchive {
public:
    DataWriter(std::vector<char>& data, size_t offset = 0) : DataArchive(offset), data_(data) {}

    virtual bool IsReading() const override
    {
        return false;
    }

    virtual void Serialize(void* data, size_t size) override
    {
        if (data && (size > 0)) {
            data_.resize(data_.size() + size);
            std::memmove(data_.data() + offset_, data, size);
            offset_ += size;
        }
    }

protected:
    std::vector<char>& data_;
};

// File archives

template<bool Reader = true>
class FileArchive : public Archive {
public:
    FileArchive(FILE* file) : file_(file), external_(true) {}

    FileArchive(const std::string& path) : file_(fopen(path.data(), Reader ? "rb" : "wb")), external_(false) {}

    virtual ~FileArchive()
    {
        if (file_ && !external_)
            fclose(file_);
    }

    virtual bool IsReading() const
    {
        return Reader;
    }

    virtual void Serialize(void* data, size_t size) override
    {
        if (file_ && data && (size > 0)) {
            if (IsReading())
                fread(data, size, 1, file_);
            else
                fwrite(data, size, 1, file_);
        }
    }

protected:
    FILE* file_ = nullptr;
    bool external_ = false;
};

using FileReader = FileArchive<true>;
using FileWriter = FileArchive<false>;

} // namespace OHOS::Rosen