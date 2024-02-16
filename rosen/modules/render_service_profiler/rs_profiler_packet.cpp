#include "rs_profiler_packet.h"

namespace OHOS::Rosen {

Packet::Packet(PacketType type)
{
    InitData(type);
}

bool Packet::IsBinary() const
{
    return (GetType() == BINARY);
}

bool Packet::IsCommand() const
{
    return (GetType() == COMMAND_ACKNOWLEDGED) || (GetType() == COMMAND);
}

char* Packet::Begin()
{
    return data_.data();
}

char* Packet::End()
{
    return data_.data() + data_.size();
}

Packet::PacketType Packet::GetType() const
{
    return *GetHeaderFieldPtr<PacketType, Header::TYPE>();
}

void Packet::SetType(Packet::PacketType type)
{
    *GetHeaderFieldPtr<PacketType, Header::TYPE>() = type;
}

uint32_t Packet::GetLength() const
{
    return *GetHeaderFieldPtr<uint32_t, Header::LENGTH>();
}

uint32_t Packet::GetPayloadLength() const
{
    return GetLength() - Packet::headerSize;
}

std::vector<char> Packet::Release() {
    auto res = std::move(data_);
    InitData(UNKNOWN);
    return res;
}

void Packet::SetLength(uint32_t length)
{
    *GetHeaderFieldPtr<uint32_t, Header::LENGTH>() = length;
}

void Packet::InitData(PacketType type)
{
    data_.resize(headerSize);
    SetType(type);
    SetLength(headerSize);
    readPointer_ = headerSize;
    writePointer_ = headerSize;
}

} // namespace OHOS::Rosen