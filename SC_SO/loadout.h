#pragma once
#include <cstdint>

bool ReadLiveWeapons(const uint64_t* peer_ids, int count, uint32_t* weapon_ids_out);

const char* GetLoadoutStatus();
