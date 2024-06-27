// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// CoverFilter is PC hash set that can be placed in shared memory.
//
// The set can cover up to 4 distinct 1GB regions of PCs.
// This restriction allows for efficient, simple and shared memory compatible representation,
// but should be enough to cover any reasonable combination of kernel/modules mapping.
//
// Low 3 bits of PCs are discarded. This reduces memory consumption 8x, but allows for some false positives.
// However, in practice false positives should be very rare. A typical coverage call instruction is 4/5 bytes,
// and there must be at least 1 other instruction in between them to make them different basic blocks,
// so it's practically impossible to place 2 of them in the same 8-byte region.
// For signal with hashed low 12 bits the probability is also low b/c overall density of coverage callbacks
// is relatively low, a KASAN Linux kernel contains 1 callback per 88 bytes of code on average.
// So even if we discard low 3 bits, average densitiy is still 1/11.
// For gVisor with dense coverage IDs special care must be taken to avoid collisions.
//
// The set is organized as a 3 level table.
// The top "region" level is linear lookup, but contains at most 4 entries, each covering 1GB.
// Most likely the first entry is the right one. This level allows to cover unconnected regions of PCs.
// The next "L1" level splits 1GB chunks into 1MB chunks, and allows to allocate memory only
// for a subset of these 1MB chunks.
// The last "L2" level covers 1MB chunks with 16KB bitmaps (1MB divided by 8 for 3 discarded PC bits,
// and divided by 8 again for 8 bits in a byte).
class CoverFilter
{
public:
	CoverFilter()
	    : shmem_(kMemSize),
	      tab_(static_cast<Table*>(shmem_.Mem()))
	{
	}

	CoverFilter(int fd, void* preferred = nullptr)
	    : shmem_(fd, preferred, kMemSize, false),
	      tab_(static_cast<Table*>(shmem_.Mem()))
	{
	}

	void Insert(uint64 pc)
	{
		auto [byte, bit] = FindByte(pc, true);
		byte |= bit;
	}

	bool Contains(uint64 pc)
	{
		auto [byte, bit] = FindByte(pc, false);
		return byte & bit;
	}

	// Prevents any future modifications to the filter.
	void Seal()
	{
		shmem_.Seal();
	}

	int FD() const
	{
		return shmem_.FD();
	}

private:
	static constexpr size_t kNumRegions = 4;
	static constexpr size_t kL1Size = 1 << 30;
	static constexpr size_t kL2Size = 1 << 20;
	static constexpr size_t kPCDivider = 8;
	static constexpr size_t kByteBits = 8;
	// Approximately how much .text we can cover (2GB of PCs require 32MB shmem region).
	static constexpr size_t kMaxCovered = 2ull << 30;
	static constexpr size_t kCompression = kPCDivider * kByteBits;
	static constexpr size_t kMemSize = kMaxCovered / kCompression;
	static constexpr size_t kNoRegion = static_cast<size_t>(-1);

	struct Table {
		uint64 regions[kNumRegions];
		uint16 l1[kNumRegions][kL1Size / kL2Size];
		uint8 l2[][kL2Size / kCompression];
	};

	ShmemFile shmem_;
	Table* tab_ = nullptr;
	uint16 alloc_ = 0;

	std::pair<uint8&, uint8> FindByte(uint64 pc, bool add = false)
	{
		static const uint8 empty = 0;
		size_t reg = FindRegion(pc, add);
		if (reg == kNoRegion)
			return {const_cast<uint8&>(empty), 0};
		size_t l1 = (pc % kL1Size) / kL2Size;
		size_t l2 = tab_->l1[reg][l1];
		if (l2 == 0) {
			if (!add)
				return {const_cast<uint8&>(empty), 0};
			l2 = ++alloc_;
			tab_->l1[reg][l1] = l2;
			if ((tab_->l2[l2 - 1] + 1) > reinterpret_cast<uint8*>(tab_) + kMemSize)
				Overflow(pc);
		}
		size_t off = (pc % kL2Size) / kCompression;
		size_t shift = (pc / kPCDivider) % kByteBits;
		return {tab_->l2[l2 - 1][off], 1 << shift};
	}

	size_t FindRegion(uint64 pc, bool add = false)
	{
		const uint64 reg = pc | (kL1Size - 1);
		for (size_t r = 0; r < kNumRegions; r++) {
			if (tab_->regions[r] == reg)
				return r;
		}
		if (!add)
			return kNoRegion;
		for (size_t r = 0; r < kNumRegions; r++) {
			if (tab_->regions[r] == 0) {
				tab_->regions[r] = reg;
				return r;
			}
		}
		Overflow(pc);
	}

	NORETURN void Overflow(uint64 pc)
	{
		failmsg("coverage filter is full", "pc=0x%llx regions=[0x%llx 0x%llx 0x%llx 0x%llx] alloc=%u",
			pc, tab_->regions[0], tab_->regions[1], tab_->regions[2], tab_->regions[3], alloc_);
	}

	CoverFilter(const CoverFilter&) = delete;
	CoverFilter& operator=(const CoverFilter&) = delete;
};
