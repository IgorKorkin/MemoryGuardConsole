

#include <iostream>     // std::cout, std::endl
#include <iomanip>      // std::setfill, std::setw
#include "map"
#include "vector"

using namespace std;

namespace memory_guard {

#define PRINT_BYTE( VALUE )   std:: uppercase << int( static_cast<unsigned char>( VALUE ) ) 

	struct AddressRangeEntry {
		void* start_address;
		void* end_address;
	};

	const int drivername_sz = 0x20;
	struct _DRIVER_MEMORY {
		char drivername[drivername_sz];
		std::vector<AddressRangeEntry> src_ranges;
		std::vector<AddressRangeEntry> dst_ranges;
	};

	vector <_DRIVER_MEMORY> MemoryMapPolicy;

	void add_driver_file(const char *driverName, const AddressRangeEntry & driverFileRange) {
		// via TestpLoadImageNotifyRoutine
		_DRIVER_MEMORY driver_mem;
		memset(&driver_mem, 0, sizeof _DRIVER_MEMORY);
		strncpy_s(driver_mem.drivername, driverName, drivername_sz);
		driver_mem.src_ranges.push_back(driverFileRange);
		driver_mem.dst_ranges.push_back(driverFileRange);
		MemoryMapPolicy.push_back(driver_mem);
		cout << driver_mem.drivername << " has been loaded ";
		cout << driverFileRange.start_address << " - " << driverFileRange.end_address << endl;
	}

	void* allocate_buffer(const void* allocSrcAddr, const size_t bufSize) {
		// via trapping ExAllocatePoolWithTag
		// allocSourceAddr -- memory address with the instruction - [call ExAllocatePoolWithTag]
		// bufSize -- size of allocated buffer
		void* buf = malloc(bufSize);
		if (buf) {
			for (vector <_DRIVER_MEMORY> ::iterator it_mem = MemoryMapPolicy.begin();
				it_mem != MemoryMapPolicy.end(); it_mem++) {

				for (std::vector<AddressRangeEntry> ::iterator it_src = it_mem->src_ranges.begin();
					it_src != it_mem->src_ranges.end(); it_src++) {

					if ((it_src->start_address <= allocSrcAddr) && (allocSrcAddr <= it_src->end_address)) {

						AddressRangeEntry dst_range = { buf , (void*)((char*)buf + bufSize) };
						it_mem->dst_ranges.push_back(dst_range);
						cout << it_mem->drivername << " allocates a buffer ";
						cout << dst_range.start_address << " - " << dst_range.end_address << endl;
						break;
					}
				}
			}
		}
		return buf;
	}

	

	void write_byte(const void* writeSrcAddr, const void* position, const char value) {
		// We intercept write access via EPT configuration
		// writeSourceAddr - address of instruction, which writes memory
		// position - address of memory, which is will be updated with 'value'
		// E.g. mov EAX, value
		//      mov byte ptr [position], EAX
		for (vector <_DRIVER_MEMORY> ::iterator it_mem = MemoryMapPolicy.begin();
			it_mem != MemoryMapPolicy.end(); it_mem++) {

			for (std::vector<AddressRangeEntry> ::iterator it_src = it_mem->src_ranges.begin();
				it_src != it_mem->src_ranges.end(); it_src++) {

				if ((it_src->start_address <= writeSrcAddr) && 
					(writeSrcAddr <= it_src->end_address)) {

					for (std::vector<AddressRangeEntry> ::iterator it_dst = it_mem->dst_ranges.begin();
						it_dst != it_mem->dst_ranges.end(); it_dst++) {

						if ((it_dst->start_address <= position) && (position <= it_dst->end_address)) {
							
							cout << it_mem->drivername <<
								" writes to address 0x" << position <<
								" value " <<
								" [" << PRINT_BYTE(*(char*)position) << "] -> [" << PRINT_BYTE(value) << "]" << endl;

							*(char*)position = value;
							return;
						}
					}
					cout << "Unauthorized driver " << it_mem->drivername <<
						" tries to write to 0x" << position << endl;
					return;
				}
			}
		}
		cout << "Unauthorized code from 0x" << writeSrcAddr <<
			" tries to write to the 0x" << position << 
			" value [" << PRINT_BYTE(value) << "]" << endl;
	}

	char read_byte(const void* readSrcAddr, const void* position) {
		// We intercept read access via EPT configuration
		// readSourceAddr - address of instruction, which reads memory
		// position - address of memory, which is acquired
		// E.g. mov EAX, byte ptr [position]
		char value = 0;
		for (vector <_DRIVER_MEMORY> ::iterator it_mem = MemoryMapPolicy.begin();
			it_mem != MemoryMapPolicy.end(); it_mem++) {

			for (std::vector<AddressRangeEntry> ::iterator it_src = it_mem->src_ranges.begin();
				it_src != it_mem->src_ranges.end(); it_src++) {

				if ((it_src->start_address <= readSrcAddr) && (readSrcAddr <= it_src->end_address)) {

					for (std::vector<AddressRangeEntry> ::iterator it_dst = it_mem->dst_ranges.begin();
						it_dst != it_mem->dst_ranges.end(); it_dst++) {

						if ((it_dst->start_address <= position) && (position <= it_dst->end_address)) {
							value = *(char*)position;
							cout << it_mem->drivername << 
								" reads from address 0x" << position << 
								" value " <<
								"[" << PRINT_BYTE(value) << "]" <<endl;
							return value;
						}
					}
					cout << "Unauthorized driver " << it_mem->drivername <<
						" tries to read from 0x" << position << endl;
					return value;
				} // if ((it_src->start_address <= readSourceAddr) && (readSourceAddr <= it_src->end_address))
			}
		}
		cout << "Unauthorized code from 0x" << readSrcAddr <<
			" tries to read from 0x" << position << endl;

		return value;
	}

	void free_buffer(const void* freeSrcAddr, void* bufForFree) {
		// via trapping ExFreePoolWithTag
		// freeSourceAddr -- memory address with the instruction - [call ExFreePoolWithTag]
		// bufForFree -- address buffer, which will be freed
		if (bufForFree) {
			for (vector <_DRIVER_MEMORY> ::iterator it_mem = MemoryMapPolicy.begin();
				it_mem != MemoryMapPolicy.end(); it_mem++) {

				for (std::vector<AddressRangeEntry> ::iterator it_src = it_mem->src_ranges.begin();
					it_src != it_mem->src_ranges.end(); it_src++) {

					if ((it_src->start_address <= freeSrcAddr) && (freeSrcAddr <= it_src->end_address)) {

						for (std::vector<AddressRangeEntry> ::iterator it_dst = it_mem->dst_ranges.begin();
							it_dst != it_mem->dst_ranges.end(); it_dst++) {

							if ((it_dst->start_address == bufForFree)) {

								cout << it_mem->drivername << " frees "
									"his buffer 0x" << bufForFree << endl;

								memset(it_dst->start_address, 0, 
									((char*)it_dst->end_address - (char*)it_dst->start_address));
								free(bufForFree);
								it_mem->dst_ranges.erase(it_dst);
								return;
							}
						}
						cout << "Unauthorized driver " << it_mem->drivername <<
							" tries to free buffer 0x" << bufForFree << endl;
						return;
					}
				}
			}
		}
		cout << "Unauthorized code from 0x" << freeSrcAddr <<
			" tries to free buffer 0x" << bufForFree << endl;
		return;
	}

	void print_memory_policies() {
		// Print table with memory policies
		if (MemoryMapPolicy.size() == 0){
			cout << "Memory policies are absent " << endl;
			return;
		}

		cout << endl << "/ Memory Map Table Begin \\" << endl;
		for (vector <_DRIVER_MEMORY> ::iterator it_mem = MemoryMapPolicy.begin();
			it_mem != MemoryMapPolicy.end(); it_mem++) {
			cout << it_mem->drivername << endl;
			
			if (it_mem->src_ranges.size() == 0)	{
				cout << "   Source range is absent " << endl;
			}
			else{
				for (std::vector<AddressRangeEntry> ::iterator it_src = it_mem->src_ranges.begin();
					it_src != it_mem->src_ranges.end(); it_src++) {
					cout << "   Source range " << std::hex <<
						it_src->start_address << " - " << std::hex << it_src->end_address << endl;
				}
			}
			
			if (it_mem->src_ranges.size() == 0) {
				cout << "   Destination range is absent " << endl;
			}
			else {
				for (std::vector<AddressRangeEntry> ::iterator it_dst = it_mem->dst_ranges.begin();
					it_dst != it_mem->dst_ranges.end(); it_dst++) {
					cout << "   Destination range " << std::hex <<
						it_dst->start_address << " - " << std::hex << it_dst->end_address << endl;
				}
			}
		}
		cout << "\\ Memory Map Table End /" << endl << endl;
	}

	void free_memory_policies() {
		// in driver Unload-routine
		for (vector <_DRIVER_MEMORY> ::iterator it_mem = MemoryMapPolicy.begin();
			it_mem != MemoryMapPolicy.end(); it_mem++) {
			it_mem->src_ranges.clear();
			it_mem->dst_ranges.clear();
		}
		MemoryMapPolicy.clear();
		cout << "Memory Map Policy has been freed, bye" << endl << endl;
	}

}


void test_simple() {
	/* The test includes the following 7 steps:
		1. DriverA.sys has been loaded into memory 0xA1000000-0xA1008000
		2. (DriverA.sys+0x50) allocates buffer with size 0x90 via calling ExAllocatePoolWithTag
		3. (DriverA.sys+0x55) reads 5-th byte from the allocated buffer
		4. (DriverA.sys+0x60) writes the 0x5A value in the 5-th byte of the allocated buffer
		5. (DriverA.sys+0x70) reads 5-th byte from the allocated buffer
		6. (DriverA.sys+0x80) frees the allocated buffer via calling ExFreePoolWithTag
		7. Free memory policy
	*/

	// Step 1. DriverA.sys has been loaded into memory 0xA1000000-0xA1008000
	char drvA_name[] = "DriverA.sys";
	memory_guard::AddressRangeEntry drvA_file_range =
	{ (void*)0xA1000000/*ImageBase*/, (void*)0xA1008000/*ImageBase+ImageSize*/};
	memory_guard::add_driver_file(drvA_name, drvA_file_range);

	// Step 2. (DriverA.sys+0x50) allocates buffer with size 0x90 via calling ExAllocatePoolWithTag 
	int bufsz_drvA = 0x90;
	void* drvA_addr_alloc = (void*)((int*)(drvA_file_range.start_address) + 0x50);
	char *data_for_driverA = (char*)memory_guard::allocate_buffer(drvA_addr_alloc, bufsz_drvA);

	memory_guard::print_memory_policies();

	// Step 3. (DriverA.sys+0x55) reads 5-th byte from the allocated buffer
	char value = 0;
	void* drvA_addr_read = (void*)((int*)(drvA_file_range.start_address) + 0x55);
	value = memory_guard::read_byte(drvA_addr_read, (data_for_driverA + 5));

	// Step 4. (DriverA.sys+0x60) writes the 0x5A value in the 5-th byte of the allocated buffer
	char byte_value = 0x5A;
	void* drvA_addr_write = (void*)((int*)(drvA_file_range.start_address) + 0x60);
	memory_guard::write_byte(drvA_addr_write, (data_for_driverA + 5), byte_value);

	// Step 5. (DriverA.sys+0x70) reads 5-th byte from the allocated buffer
	value = 0;
	drvA_addr_read = (void*)((int*)(drvA_file_range.start_address) + 0x70);
	value = memory_guard::read_byte(drvA_addr_read, (data_for_driverA + 5));

	// Step 6. (DriverA.sys+0x80) frees the allocated buffer via calling ExFreePoolWithTag
	void* drvA_addr_free = (void*)((int*)(drvA_file_range.start_address) + 0x80);
	memory_guard::free_buffer(drvA_addr_free, data_for_driverA);

	// Step 7. Free memory policy
	memory_guard::free_memory_policies();
}

void test_prevent_unauth_driver_read_write() {
	/* The test  includes the following 9 steps:
		1. DriverA.sys has been loaded into memory 0xA1000000-0xA1008000
		2. (DriverA.sys+0x50) allocates buffer with size 0x90 via calling ExAllocatePoolWithTag
		3. (DriverA.sys+0x60) writes the 0xFA value in the 5-th byte of the allocated buffer
		4. (DriverA.sys+0x70) reads 5-th byte from the allocated buffer
		5*. ThirdDriver.sys has been loaded into memory 0xB1000000-0xB1008000
		6*. (ThirdDriver.sys+0x10) writes the 0xBB value in the 1-st byte of the DriverA.sys file
		7*. (ThirdDriver.sys+0x20) writes the 0xCC value in the 1-st byte of the allocated buffer from DriverA.sys
		8*. (ThirdDriver.sys+0x30) reads 5-th byte from the allocated buffer from DriverA.sys
		9. (DriverA.sys+0x80) frees the allocated buffer via calling ExFreePoolWithTag
	*/

	// Step 1. DriverA.sys has been loaded into memory 0xA1000000-0xA1008000
	char drvA_name[] = "DriverA.sys";
	memory_guard::AddressRangeEntry driverA_file_range =
	{ (void*)0xA1000000 /*ImageBase*/, (void*)0xA1008000 /*ImageBase+ImageSize*/ };
	memory_guard::add_driver_file(drvA_name, driverA_file_range);

	// Step 2. (DriverA.sys+0x50) allocates buffer with size 0x90 via calling ExAllocatePoolWithTag
	int bufsz_drvA = 0x90;
	void* drvA_addr_alloc = (void*)((int*)(driverA_file_range.start_address) + 0x50);
	char *data_for_driverA = (char*)memory_guard::allocate_buffer(drvA_addr_alloc, bufsz_drvA);

	// Step 3. (DriverA.sys+0x60) writes the 0xFA value in the 5-th byte of the allocated buffer
	char byte_value = (char)0xFA;
	void* drvA_addr_write = (void*)((int*)(driverA_file_range.start_address) + 0x60);
	memory_guard::write_byte(drvA_addr_write, (data_for_driverA + 5), byte_value);

	// Step 4. (DriverA.sys+0x70) reads 5-th byte from the allocated buffer
	char value = 0;
	void* drvA_addr_read = (void*)((int*)(driverA_file_range.start_address) + 0x70);
	value = memory_guard::read_byte(drvA_addr_read, (data_for_driverA + 5));

	// Step 5*. Rootkit.sys has been loaded into memory 0xB1000000-0xB1008000
	char thirddrv_name[] = "ThirdDriver.sys";
	memory_guard::AddressRangeEntry thirddrv_file_range =
	{ (void*)0xB1000000 /*DllBase*/, (void*)0xB1008000 /*DllBase+SizeOfImage*/ };
	memory_guard::add_driver_file(thirddrv_name, thirddrv_file_range);

	memory_guard::print_memory_policies();

	// Step 6*. (Rootkit.sys+0x10) writes the 0xBB value in the 1-st byte of the DriverA.sys file
	char thirddrv_byte_value = (char)0xBB;
	void* thirddrv_addr_write = (void*)((int*)(thirddrv_file_range.start_address) + 0x10);
	memory_guard::write_byte(thirddrv_addr_write, driverA_file_range.start_address, thirddrv_byte_value);
	
	// Step 7*. (Rootkit.sys+0x20) writes the 0xCC value in the 1-st byte of the allocated buffer from DriverA.sys
	thirddrv_byte_value = (char)0xCC;
	thirddrv_addr_write = (void*)((int*)(thirddrv_file_range.start_address) + 0x20);
	memory_guard::write_byte(thirddrv_addr_write, data_for_driverA, thirddrv_byte_value);

	// Step 8*. (Rootkit.sys+0x30) reads 5-th byte from the allocated buffer from DriverA.sys
	thirddrv_byte_value = 0;
	void* thirddrv_addr_read = (void*)((int*)(thirddrv_file_range.start_address) + 0x30);
	thirddrv_byte_value = memory_guard::read_byte(thirddrv_addr_read, (data_for_driverA + 5));

	// Step 9. (DriverA.sys+0x80) frees the allocated buffer via calling ExFreePoolWithTag
	void* drvA_addr_free = (void*)((int*)(driverA_file_range.start_address) + 0x80);
	memory_guard::free_buffer(drvA_addr_free, data_for_driverA);

	memory_guard::free_memory_policies();
}

void test_prevent_unauth_code_read_write() {
	/* The test includes the following 5 steps:
		1. DriverA.sys has been loaded into memory 0xA1000000-0xA1008000
		2. UnknownDriver.sys is in memory 0xF1000000-0xF1008000
		3*. (UnknownDriver.sys+0x10) writes the 0xBB value in the 1-st byte of the DriverA.sys file
		4*. (UnknownDriver.sys+0x30) reads 5-th byte of the DriverA.sys file
		5*. (UnknownDriver.sys+0x80) tries to free the buffer via calling ExFreePoolWithTag
	*/

	// Step 1. DriverA.sys has been loaded into memory 0xA1000000-0xA1008000
	char drvA_name[] = "DriverA.sys";
	memory_guard::AddressRangeEntry drvA_file_range =
	{ (void*)0xA1000000 /*ImageBase*/, (void*)0xA1008000 /*ImageBase+ImageSize*/ };
	memory_guard::add_driver_file(drvA_name, drvA_file_range);

	memory_guard::print_memory_policies();

	// Step 2. UnknownDriver.sys is in memory 0xF1000000-0xF1008000
	char unkn_name[] = "UnknownDriver.sys";
	memory_guard::AddressRangeEntry unknown_file_range =
	{ (void*)0xF1000000 /*DllBase*/, (void*)0xF1008000 /*DllBase+SizeOfImage*/ };
	// we didn't add UnknownDriver, because it is super hidden

	// Step 3*. (UnknownDriver.sys+0x10) writes the 0xBB value in the 1-st byte of the DriverA.sys file
	char unkn_byte_value = (char)0xBB;
	void* unkn_addr_write = (void*)((int*)(unknown_file_range.start_address) + 0x10);
	memory_guard::write_byte(unkn_addr_write, drvA_file_range.start_address, unkn_byte_value);

	// Step 4*. (UnknownDriver.sys+0x30) reads 5-th byte of the DriverA.sys file
	unkn_byte_value = 0;
	void* unkn_addr_read = (void*)((int*)(unknown_file_range.start_address) + 0x30);
	unkn_byte_value = memory_guard::read_byte(unkn_addr_read, ((char*)drvA_file_range.start_address + 5));

	// Step 5*. (UnknownDriver.sys+0x80) tries to free the buffer via calling ExFreePoolWithTag
	void* unkn_addr_free = (void*)((int*)(unknown_file_range.start_address) + 0x80);
	memory_guard::free_buffer(unkn_addr_free, drvA_file_range.start_address);

	memory_guard::free_memory_policies();
}

int main() {

	test_simple();

	test_prevent_unauth_driver_read_write();

	test_prevent_unauth_code_read_write();

	return 0;
}