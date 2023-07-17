package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// The target bytes to look for in the memory areas
var target = []byte{0x76, 0x61, 0x6c, 0x75, 0x65, 0x20, 0x63, 0x61, 0x63, 0x68, 0x65, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x00, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x43, 0x61, 0x63, 0x68, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x00}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Usage: go run main.go -p PID [--analyze-items] [--show-items-details] [-v]")
		return
	}

	// Parse the arguments using "flag"
	var pid string
	var analyzeItems bool
	var numberOfTopItems int
	var histogramMaxItemids int
	var showItemsDetails bool
	flag.StringVar(&pid, "p", "", "The PID of the process to analyze")
	flag.BoolVar(&analyzeItems, "analyze-items", false, "Analyze the items slots")
	flag.IntVar(&numberOfTopItems, "number-of-top-items", 10, "Number of top items to show")
	flag.IntVar(&histogramMaxItemids, "histogram-max-itemids", 10, "Max number of itemids to show in the histogram")
	flag.BoolVar(&showItemsDetails, "show-items-details", false, "Show the data for each itemid stored")
	flag.Parse()

	// Check if the PID is valid
	if pid == "" {
		fmt.Println("Error: PID is required")
		return
	}

	// Execute the pmap command with the PID
	cmd := exec.Command("pmap", pid)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running pmap: ", err)
		fmt.Printf("Output: %s\n", output)
		return
	}

	// Split the output by lines and filter those with "rw-s-"
	lines := strings.Split(string(output), "\n")
	var filtered []string
	for _, line := range lines {
		if strings.Contains(line, "rw-s-") {
			filtered = append(filtered, line)
		}
	}

	// Find the target bytes in the memory areas
	addr := findTargetBytes(pid, filtered)
	if addr == -1 {
		fmt.Println("Target bytes not found")
		return
	}

	// Read the memory area at the address where the target bytes were found
	buf, err := readMemoryArea(pid, strconv.FormatInt(addr, 16), 208)
	if err != nil {
		fmt.Println("Error reading memory area:", err)
		return
	}

	// Skip the len(target) bytes, the memory description.
	// Also skip the next 8 bytes (empty space).
	addr += int64(len(target)) + 8
	buf = buf[len(target)+8:]

	itemsSlotsPtr, itemsSlotsSize, strpoolSlotsPtr, strpoolSlotsSize := parseZbxVcCacheT(addr, buf)
	_, _ = strpoolSlotsPtr, strpoolSlotsSize

	if analyzeItems {
		// Analyze the items slots
		itemValues, err := analyzeItemsSlots(pid, itemsSlotsPtr, itemsSlotsSize, showItemsDetails)
		if err != nil {
			fmt.Println("Error analyzing items slots:", err)
			return
		}

		printItemsValuesStats(itemValues, numberOfTopItems, histogramMaxItemids)
	}
}

func findTargetBytes(pid string, filtered []string) int64 {
	// For each filtered line, parse the address and size of the memory area
	for _, line := range filtered {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue // Skip invalid lines
		}
		address := fields[0]                      // The address is the first field
		sizeStr := fields[1]                      // The size is the second field
		sizeStr = strings.TrimRight(sizeStr, "K") // Remove the K suffix
		size, err := strconv.Atoi(sizeStr)        // Convert the size to an integer
		if err != nil {
			fmt.Println("Error parsing size:", err)
			continue
		}

		// Read the memory area using /proc/PID/mem and a file descriptor
		memPath := fmt.Sprintf("/proc/%s/mem", pid) // The path to the memory file
		memFile, err := os.Open(memPath)            // Open the memory file for reading
		if err != nil {
			fmt.Println("Error opening memory file:", err)
			continue
		}
		defer memFile.Close() // Close the file when done

		// Seek to the address of the memory area
		addrInt64, err := strconv.ParseInt(address, 16, 64) // Convert the address to an int64
		if err != nil {
			fmt.Println("Error parsing address:", err)
			continue
		}
		_, err = memFile.Seek(addrInt64, os.SEEK_SET) // Seek to the address from the start of the file
		if err != nil {
			fmt.Println("Error seeking to address:", err)
			continue
		}

		// Read the memory area into a buffer
		buf := make([]byte, size*1024) // Allocate a buffer of size bytes (multiply by 1024 to get bytes from kilobytes)
		_, err = memFile.Read(buf)     // Read from the file into the buffer
		if err != nil {
			fmt.Println("Error reading memory area:", err)
			continue
		}

		// Search for the target bytes in the buffer using bytes.Index
		index := bytes.Index(buf, target) // Returns -1 if not found
		if index != -1 {
			// If found, print the address where it is located (add the index to the base address)
			foundAddr := addrInt64 + int64(index) // The address where the target bytes are located
			return foundAddr
		}
	}
	return -1
}

// printMemoryArea prints the memory area at the given address with format:
// 00007fa05de00130  00 00 00 00 00 00 00 00  f0 45 e0 5d a0 7f 00 00  |.........E.]....|
// It should print first the memory address.
// Then it should print the hex representation of the 16 bytes in the memory area.
// Then it should print the ASCII representation of the 16 bytes in the memory area.
// Then change line, and print the next 16 bytes, and so on.
func printMemoryArea(address int64, buf []byte) {
	// Print the address
	fmt.Printf("%016x ", address)

	// Print the hex representation of the bytes
	for i, b := range buf {
		fmt.Printf("%02x ", b)

		// Print a space after 8 bytes
		if i%8 == 7 {
			fmt.Print(" ")
		}

		// Print a newline after 16 bytes
		if i%16 == 15 {
			fmt.Print(" |")
			// Print the ASCII representation of the bytes
			for j := i - 15; j <= i; j++ {
				if buf[j] >= 32 && buf[j] <= 126 {
					fmt.Printf("%c", buf[j])
				} else {
					fmt.Print(".")
				}
			}
			fmt.Println("|")
			if i < len(buf)-1 {
				// Print the address
				fmt.Printf("%016x ", address+int64(i+1))
			}
		}
	}
	fmt.Println()
}

// Parse the zbx_vc_cache_t struct from the given buffer.
// Return the address of the items->slots and strpool->slots arrays with its size.
// The C struct is:
// typedef struct
//
//	{
//		/* the number of cache hits, used for statistics */
//		zbx_uint64_t	hits;
//
//		/* the number of cache misses, used for statistics */
//		zbx_uint64_t	misses;
//
//		/* value cache operating mode - see ZBX_VC_MODE_* defines */
//		int		mode;
//
//		/* time when cache operating mode was changed */
//		int		mode_time;
//
//		/* timestamp of the last low memory warning message */
//		int		last_warning_time;
//
//		/* the minimum number of bytes to be freed when cache runs out of space */
//		size_t		min_free_request;
//
//		/* the cached items */
//		zbx_hashset_t	items;
//
//		/* the string pool for str, text and log item values */
//		zbx_hashset_t	strpool;
//	}
//
// zbx_vc_cache_t;
//
// typedef struct
//
//	{
//		zbx_hashset_entry_s **slots;
//		int			num_slots;
//		int			num_data;
//		zbx_hash_func_t		hash_func;
//		zbx_compare_func_t	compare_func;
//		zbx_clean_func_t	clean_func;
//		zbx_mem_malloc_func_t	mem_malloc_func;
//		zbx_mem_realloc_func_t	mem_realloc_func;
//		zbx_mem_free_func_t	mem_free_func;
//	}
//
// zbx_hashset_t;
func parseZbxVcCacheT(addr int64, buf []byte) (itemsSlotsAddr uint64, itemsSlotsSize uint32, strpoolSlotsAddr uint64, strpoolSlotsSize uint32) {
	fmt.Println("-- zbx_vc_cache_t --")

	// Parse the hits and misses fields
	hits := binary.LittleEndian.Uint64(buf[0:8])
	misses := binary.LittleEndian.Uint64(buf[8:16])
	fmt.Printf("hits: %d\n", hits)
	fmt.Printf("misses: %d\n", misses)

	// Parse the mode field
	mode := binary.LittleEndian.Uint32(buf[16:20])
	fmt.Printf("mode: %d\n", mode)

	// Parse the mode_time field
	modeTime := binary.LittleEndian.Uint32(buf[20:24])
	fmt.Printf("mode_time: %d\n", modeTime)

	// Parse the last_warning_time field
	lastWarningTime := binary.LittleEndian.Uint32(buf[24:28])
	fmt.Printf("last_warning_time: %d\n", lastWarningTime)

	// Parse the min_free_request field
	// minFreeRequest := binary.LittleEndian.Uint64(buf[28:36])
	// fmt.Printf("min_free_request: %d\n", minFreeRequest)

	// Skip 4 bytes

	// Parse the zbx_hashset_t struct for the items field
	// Get the slots address
	itemsSlotsPtr := binary.LittleEndian.Uint64(buf[40:48])
	// fmt.Printf("items: 0x%x\n", itemsSlotsPtr)

	itemsNumSlots := binary.LittleEndian.Uint32(buf[48:52])
	fmt.Printf("items.num_slots: %d\n", itemsNumSlots)

	itemsNumData := binary.LittleEndian.Uint32(buf[52:56])
	fmt.Printf("items.num_data: %d\n", itemsNumData)

	// Skip 6*8 bytes (function pointers)

	// Parse the zbx_hashset_t struct for the strpool field
	// Get the slots address
	strpoolSlotsPtr := binary.LittleEndian.Uint64(buf[104:112])
	// fmt.Printf("strpool: 0x%x\n", strpoolSlotsPtr)

	strpoolNumSlots := binary.LittleEndian.Uint32(buf[112:116])
	fmt.Printf("strpool.num_slots: %d\n", strpoolNumSlots)

	strpoolNumData := binary.LittleEndian.Uint32(buf[116:120])
	fmt.Printf("strpool.num_data: %d\n", strpoolNumData)

	fmt.Println()

	return itemsSlotsPtr, itemsNumSlots, strpoolSlotsPtr, strpoolNumSlots
}

// analyzeItemsSlots analyzes the items->slots array.
// Each block of 8 bytes could be a pointer to a zbx_hashset_entry_s struct.
// The field "data" of this struct is a pointer to a zbx_vc_item_t struct.
// The C struct is:
//
// typedef struct
//
//	{
//		zbx_hashset_entry_s	*next;
//		zbx_hash_t		hash;
//
// #if SIZEOF_VOID_P > 4
//
//	/* the data member must be properly aligned on 64-bit architectures that require aligned memory access */
//	char			padding[sizeof(void *) - sizeof(zbx_hash_t)];
//
// #endif
//
//		char			data[1];
//	}
//
// zbx_hashset_entry_s;
//
/* the value cache item data */
// typedef struct
// {
// 	/* the item id */
// 	zbx_uint64_t	itemid;

// 	/* the item value type */
// 	unsigned char	value_type;

// 	/* the item operational state flags (ZBX_ITEM_STATE_*)        */
// 	unsigned char	state;

// 	/* the item status flags (ZBX_ITEM_STATUS_*)                  */
// 	unsigned char	status;

// 	/* the hour when the current/global range sync was done       */
// 	unsigned char	range_sync_hour;

// 	/* The total number of item values in cache.                  */
// 	/* Used to evaluate if the item must be dropped from cache    */
// 	/* in low memory situation.                                   */
// 	int		values_total;

// 	/* The last time when item cache was accessed.                */
// 	/* Used to evaluate if the item must be dropped from cache    */
// 	/* in low memory situation.                                   */
// 	int		last_accessed;

// 	/* reference counter indicating number of processes           */
// 	/* accessing item                                             */
// 	int		refcount;

// 	/* The range of the largest request in seconds.               */
// 	/* Used to determine if data can be removed from cache.       */
// 	int		active_range;

// 	/* The range for last 24 hours since active_range update.     */
// 	/* Once per day the active_range is synchronized (updated)    */
// 	/* with daily_range and the daily range is reset.             */
// 	int		daily_range;

// 	/* The timestamp marking the oldest value that is guaranteed  */
// 	/* to be cached.                                              */
// 	/* The db_cached_from value is based on actual requests made  */
// 	/* to database and is used to check if the requested time     */
// 	/* interval should be cached.                                 */
// 	int		db_cached_from;

// 	/* The number of cache hits for this item.                    */
// 	/* Used to evaluate if the item must be dropped from cache    */
// 	/* in low memory situation.                                   */
// 	zbx_uint64_t	hits;

// 	/* the last (newest) chunk of item history data               */
// 	zbx_vc_chunk_t	*head;

//		/* the first (oldest) chunk of item history data              */
//		zbx_vc_chunk_t	*tail;
//	}
//
// zbx_vc_item_t;
func analyzeItemsSlots(pid string, slotsAddr uint64, size uint32, showItemsDetails bool) (map[uint64]uint32, error) {
	// map to store itemid and number of values
	itemValues := make(map[uint64]uint32)

	if showItemsDetails {
		fmt.Println("-- Items stored in the value cache --")
		fmt.Println("--------------------")
		defer fmt.Println()
	}

	// Parse the slots array
	for i := uint64(0); i < uint64(size); i++ {
		// Read 8 bytes
		slot, err := readMemoryArea(pid, strconv.FormatInt(int64(slotsAddr+i*8), 16), 8)
		if err != nil {
			return nil, fmt.Errorf("Error reading slots array: %s\n", err)
		}

		// Ignore empty slots
		if bytes.Equal(slot, make([]byte, 8)) {
			continue
		}

		// Convert slot to uint64
		slotPtr := binary.LittleEndian.Uint64(slot)

		// Read the zbx_hashset_entry_s struct
		hashsetBuf, err := readMemoryArea(pid, strconv.FormatInt(int64(slotPtr), 16), 80)
		if err != nil {
			return nil, fmt.Errorf("Error reading zbx_vc_item_t struct: %s\n", err)
		}

		// Get the "next" pointer from the hashsetBuf
		// nextPtr := binary.LittleEndian.Uint64(hashsetBuf[0:8])

		// Get the "hash" from the hashsetBuf
		// hash := binary.LittleEndian.Uint64(hashsetBuf[8:16])

		// Now read the zbx_vc_item_t struct, from the hashsetBuf
		itemid := binary.LittleEndian.Uint64(hashsetBuf[16:24])

		valuesTotal := binary.LittleEndian.Uint32(hashsetBuf[28:32])

		if showItemsDetails {
			fmt.Printf("itemid: %d (", itemid)

			valueType := hashsetBuf[24]
			// Print the data type
			//  0 -> double/float
			// 1 -> char
			// 2 -> log
			// 3 -> uint
			// 4 -> text
			if valueType == 0 {
				fmt.Printf("double")
			} else if valueType == 1 {
				fmt.Printf("char")
			} else if valueType == 2 {
				fmt.Printf("log")
			} else if valueType == 3 {
				fmt.Printf("uint")
			} else if valueType == 4 {
				fmt.Printf("text")
			}

			fmt.Printf(", ")

			state := hashsetBuf[25]
			// Print "normal" if 0 or "not supported" if 1
			if state == 0 {
				fmt.Printf("normal")
			} else {
				fmt.Printf("not supported")
			}

			fmt.Printf(", ")

			status := hashsetBuf[26]
			// Print "enabled" if 0 or "disabled" if 1
			if status == 1 {
				fmt.Printf("enabled")
			} else {
				fmt.Printf("disabled")
			}

			fmt.Printf(")\n")

			fmt.Printf("valuesTotal: %d\n", valuesTotal)

			fmt.Println("--------------------")
		}

		// rangeSyncHour := hashsetBuf[27]
		// fmt.Printf("rangeSyncHour: %d\n", rangeSyncHour)

		// lastAccessed := binary.LittleEndian.Uint32(hashsetBuf[32:36])
		// fmt.Printf("lastAccessed: %d\n", lastAccessed)

		// refcount := binary.LittleEndian.Uint32(hashsetBuf[36:40])
		// fmt.Printf("refcount: %d\n", refcount)

		// activeRange := binary.LittleEndian.Uint32(hashsetBuf[40:44])
		// fmt.Printf("activeRange: %d\n", activeRange)

		// dailyRange := binary.LittleEndian.Uint32(hashsetBuf[44:48])
		// fmt.Printf("dailyRange: %d\n", dailyRange)

		// dbCachedFrom := binary.LittleEndian.Uint32(hashsetBuf[48:52])
		// fmt.Printf("dbCachedFrom: %d\n", dbCachedFrom)

		// skip 4 bytes
		// No entiendo muy bien esto, pero parece que los hits están en los 4 bytes siguientes

		// hits := binary.LittleEndian.Uint64(hashsetBuf[56:64])
		// fmt.Printf("hits: %d\n", hits)

		// head := binary.LittleEndian.Uint64(hashsetBuf[64:72])
		// fmt.Printf("head: %x\n", head)

		// tail := binary.LittleEndian.Uint64(hashsetBuf[72:80])
		// fmt.Printf("tail: %x\n", tail)

		// If we want to access the cached values, we need to read the zbx_vc_chunk_t struct using the head or tail pointers.

		itemValues[itemid] = valuesTotal

		// // Print itemBuf
		// printMemoryArea(int64(slotPtr), hashsetBuf)
	}

	return itemValues, nil
}

// sortMapByValue sorts a map by value
func sortMapByValue(m map[uint64]uint32) []uint64 {
	// Convert the map to a slice
	var sortedSlice []uint64
	for k := range m {
		sortedSlice = append(sortedSlice, k)
	}

	// Sort the slice
	sort.Slice(sortedSlice, func(i, j int) bool {
		return m[sortedSlice[i]] > m[sortedSlice[j]]
	})

	return sortedSlice
}

// readMemoryArea reads the memory area of the given size at the given address.
// Size is in bytes.
func readMemoryArea(pid string, address string, size int) ([]byte, error) {
	// Read the memory area using /proc/PID/mem and a file descriptor
	memPath := fmt.Sprintf("/proc/%s/mem", pid) // The path to the memory file
	memFile, err := os.Open(memPath)            // Open the memory file for reading
	if err != nil {
		return nil, fmt.Errorf("Error opening memory file: %s", err)
	}
	defer memFile.Close() // Close the file when done

	// Seek to the address of the memory area
	addrInt64, err := strconv.ParseInt(address, 16, 64) // Convert the address to an int64
	if err != nil {
		return nil, fmt.Errorf("Error parsing address: %s", err)
	}
	_, err = memFile.Seek(addrInt64, os.SEEK_SET) // Seek to the address from the start of the file
	if err != nil {
		return nil, fmt.Errorf("Error seeking to address: %s", err)
	}

	// Read the memory area into a buffer
	buf := make([]byte, size)  // Allocate a buffer of size bytes (multiply by 1024 to get bytes from kilobytes)
	_, err = memFile.Read(buf) // Read from the file into the buffer
	if err != nil {
		return nil, fmt.Errorf("Error reading memory area: %s", err)
	}

	return buf, nil
}

// printItemsValuesStats prints info about the items stored in the value cache.
// It prints the top 10 items by number of values stored.
// It also prints an histogram, where each line groups items by number of values stored.
func printItemsValuesStats(itemValues map[uint64]uint32, numberOfTopItems int, histogramMaxItemids int) {
	// Sort the map by value
	sortedSlice := sortMapByValue(itemValues)

	// Print the top items by number of values stored
	fmt.Printf("Top %d items by number of values stored:\n", numberOfTopItems)
	for i := 0; i < numberOfTopItems && i < len(sortedSlice); i++ {
		itemid := sortedSlice[i]
		fmt.Printf("  %d: %d\n", itemid, itemValues[itemid])
	}

	fmt.Println()

	// Get the different values stored in a list
	var values []uint32
	var itemids []uint64
	for itemid, value := range itemValues {
		itemids = append(itemids, itemid)
		values = append(values, value)
	}

	// Split the values into 10 buckets of equal size.
	// The max value of the last bucket should be the max value of the list.
	buckets := make([]int, 10)
	bucketsItems := make([][]uint64, 10)
	maxValue := uint32(0)
	for _, value := range values {
		if value > maxValue {
			maxValue = value
		}
	}
	bucketSize := maxValue / 9
	for i, value := range values {
		bucket := value / bucketSize
		buckets[bucket]++
		bucketsItems[bucket] = append(bucketsItems[bucket], itemids[i])
	}

	// Print the histogram
	fmt.Println("Histogram, format: value range: N values (item ids)")
	for i, bucket := range buckets {
		fmt.Printf("  %5d - %5d: %d items", i*int(bucketSize), (i+1)*int(bucketSize), bucket)
		if len(bucketsItems[i]) > 0 {
			fmt.Print(" (")
			for j, itemid := range bucketsItems[i] {
				fmt.Printf("%d", itemid)
				// Print comma if not last
				if j < len(bucketsItems[i])-1 {
					fmt.Print(", ")
				}

				// Print ellipsis if too many items
				if j == histogramMaxItemids-1 {
					fmt.Printf("...")
					break
				}
			}
			fmt.Println(")")
		} else {
			fmt.Println()
		}
	}
}
