/*
 * Just bunch of copy&paste from makedumpfile
 */
#include "makedumpfile.h"
#include "elf_info.h"
#include "cache.h"
#include <stddef.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>
#include <sys/time.h>

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/nbd.h>

#include <errno.h>

int retcd;
int message_level;

struct symbol_table	symbol_table;
struct size_table	size_table;
struct offset_table	offset_table;
struct array_table	array_table;
struct number_table	number_table;
struct srcfile_table	srcfile_table;
struct save_control	sc;

struct vm_table		vt = { 0 };
struct DumpInfo		*info = NULL;
struct SplitBlock		*splitblock = NULL;
struct vmap_pfns	*gvmem_pfns;
int nr_gvmem_pfns;
extern int find_vmemmap();

char filename_stdout[] = FILENAME_STDOUT;

/* #define CRASH_RESERVED_MEM_NR   8 */
struct memory_range crash_reserved_mem[CRASH_RESERVED_MEM_NR];
int crash_reserved_mem_nr;

/* Cache statistics */
static unsigned long long	cache_hit;
static unsigned long long	cache_miss;

/*
 * Get the amount of free memory from /proc/meminfo.
 */
unsigned long long
get_free_memory_size(void) {
	char buf[BUFSIZE_FGETS];
	char unit[4];
	unsigned long long free_size = 0;
	char *name_meminfo = "/proc/meminfo";
	FILE *file_meminfo;

	if ((file_meminfo = fopen(name_meminfo, "r")) == NULL) {
		ERRMSG("Can't open the %s. %s\n", name_meminfo, strerror(errno));
		return FALSE;
	}

	while (fgets(buf, BUFSIZE_FGETS, file_meminfo) != NULL) {
		if (sscanf(buf, "MemFree: %llu %s", &free_size, unit) == 2) {
			if (strcmp(unit, "kB") == 0) {
				free_size *= 1024;
				goto out;
			}
		}
	}

	ERRMSG("Can't get free memory size.\n");
	free_size = 0;
out:
	if (fclose(file_meminfo) < 0)
		ERRMSG("Can't close the %s. %s\n", name_meminfo, strerror(errno));

	return free_size;
}

int
open_dump_memory(char *vmcore)
{
	int fd;

	if ((fd = open(vmcore, O_RDONLY)) < 0) {
		ERRMSG("Can't open the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	info->fd_memory = fd;
	return TRUE;
}

static int
read_from_vmcore(off_t offset, void *bufptr, unsigned long size)
{
	const off_t failed = (off_t)-1;

	if (lseek(info->fd_memory, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). (offset: %llx) %s\n",
		       info->name_memory, (unsigned long long)offset, strerror(errno));
		return FALSE;
	}

	if (read(info->fd_memory, bufptr, size) != size) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		       info->name_memory, strerror(errno));
		return FALSE;
	}

	return TRUE;
}

#define INITIALIZE_LONG_TABLE(table, value) \
do { \
	size_member = sizeof(long); \
	num_member  = sizeof(table) / size_member; \
	ptr_long_table = (long *)&table; \
	for (i = 0; i < num_member; i++, ptr_long_table++) \
		*ptr_long_table = value; \
} while (0)

static void first_cycle(mdf_pfn_t start, mdf_pfn_t max, struct cycle *cycle)
{
	cycle->start_pfn = round(start, info->pfn_cyclic);
	cycle->end_pfn = cycle->start_pfn + info->pfn_cyclic;

	if (cycle->end_pfn > max)
		cycle->end_pfn = max;

	/*
	 * Mitigate statistics problem in ELF dump mode.
	 * A cycle must start with a pfn that is divisible by BITPERBYTE.
	 * See create_bitmap_from_memhole().
	 */
	if (info->flag_elf_dumpfile && cycle->start_pfn < start)
		cycle->start_pfn = round(start, BITPERBYTE);

	cycle->exclude_pfn_start = 0;
	cycle->exclude_pfn_end = 0;
}

static void update_cycle(mdf_pfn_t max, struct cycle *cycle)
{
	cycle->start_pfn= cycle->end_pfn;
	cycle->end_pfn=  cycle->start_pfn + info->pfn_cyclic;

	if (cycle->end_pfn > max)
		cycle->end_pfn = max;
}

static int end_cycle(mdf_pfn_t max, struct cycle *cycle)
{
	return (cycle->start_pfn >=  max)?TRUE:FALSE;
}

#define for_each_cycle(start, max, C) \
	for (first_cycle(start, max, C); !end_cycle(max, C); \
	     update_cycle(max, C))

int
is_kvaddr(unsigned long long addr)
{
	return (addr >= (unsigned long long)(KVBASE));
}

int
is_in_same_page(unsigned long vaddr1, unsigned long vaddr2)
{
	if (round(vaddr1, info->page_size) == round(vaddr2, info->page_size))
		return TRUE;

	return FALSE;
}

static inline int
isHugetlb(unsigned long dtor)
{
        return ((NUMBER(HUGETLB_PAGE_DTOR) != NOT_FOUND_NUMBER)
		&& (NUMBER(HUGETLB_PAGE_DTOR) == dtor))
                || ((SYMBOL(free_huge_page) != NOT_FOUND_SYMBOL)
                    && (SYMBOL(free_huge_page) == dtor));
}

static int
isOffline(unsigned long flags, unsigned int _mapcount)
{
	if (NUMBER(PAGE_OFFLINE_MAPCOUNT_VALUE) == NOT_FOUND_NUMBER)
		return FALSE;

	if (flags & (1UL << NUMBER(PG_slab)))
		return FALSE;

	if (_mapcount == (int)NUMBER(PAGE_OFFLINE_MAPCOUNT_VALUE))
		return TRUE;

	return FALSE;
}

static int
is_cache_page(unsigned long flags)
{
	if (isLRU(flags))
		return TRUE;

	/* PG_swapcache is valid only if:
	 *   a. PG_swapbacked bit is set, or
	 *   b. PG_swapbacked did not exist (kernels before 4.10-rc1).
	 */
	if ((NUMBER(PG_swapbacked) == NOT_FOUND_NUMBER || isSwapBacked(flags))
	    && isSwapCache(flags))
		return TRUE;

	return FALSE;
}

/*
 * The numbers of the excluded pages
 */
mdf_pfn_t pfn_zero;
mdf_pfn_t pfn_memhole;
mdf_pfn_t pfn_cache;
mdf_pfn_t pfn_cache_private;
mdf_pfn_t pfn_user;
mdf_pfn_t pfn_free;
mdf_pfn_t pfn_hwpoison;
mdf_pfn_t pfn_offline;
mdf_pfn_t pfn_elf_excluded;

mdf_pfn_t num_dumped;

int retcd = FAILED;	/* return code */

#define INITIALIZE_LONG_TABLE(table, value) \
do { \
	size_member = sizeof(long); \
	num_member  = sizeof(table) / size_member; \
	ptr_long_table = (long *)&table; \
	for (i = 0; i < num_member; i++, ptr_long_table++) \
		*ptr_long_table = value; \
} while (0)

static void setup_page_is_buddy(void);

static int
is_mapped_with_mmap(off_t offset) {

	if (info->flag_usemmap == MMAP_ENABLE
	    && offset >= info->mmap_start_offset
	    && offset < info->mmap_end_offset)
		return TRUE;
	else
		return FALSE;
}

static void
unmap_cache(struct cache_entry *entry)
{
	munmap(entry->bufptr, entry->buflen);
}

static int
update_mmap_range(off_t offset, int initial) {
	off_t start_offset, end_offset;
	off_t map_size;
	off_t max_offset = get_max_file_offset();
	off_t pt_load_end = offset_to_pt_load_end(offset);

	/*
	 * offset for mmap() must be page aligned.
	 */
	start_offset = roundup(offset, info->page_size);
	end_offset = MIN(max_offset, round(pt_load_end, info->page_size));

	if (!pt_load_end || (end_offset - start_offset) <= 0)
		return FALSE;

	map_size = MIN(end_offset - start_offset, info->mmap_region_size);

	info->mmap_buf = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE,
				     info->fd_memory, start_offset);

	if (info->mmap_buf == MAP_FAILED) {
		if (!initial)
			DEBUG_MSG("Can't map [%llx-%llx] with mmap()\n %s",
				  (ulonglong)start_offset,
				  (ulonglong)(start_offset + map_size),
				  strerror(errno));
		return FALSE;
	}

	info->mmap_start_offset = start_offset;
	info->mmap_end_offset = start_offset + map_size;

	return TRUE;
}

int
initialize_mmap(void) {
	unsigned long long phys_start;
	info->mmap_region_size = MAP_REGION;
	info->mmap_buf = MAP_FAILED;

	get_pt_load(0, &phys_start, NULL, NULL, NULL);
	if (!update_mmap_range(paddr_to_offset(phys_start), 1))
		return FALSE;

	return TRUE;
}

static char *
mappage_elf(unsigned long long paddr)
{
	off_t offset, offset2;

	if (info->flag_usemmap != MMAP_ENABLE)
		return NULL;

	offset = paddr_to_offset(paddr);
	if (!offset || page_is_fractional(offset))
		return NULL;

	offset2 = paddr_to_offset(paddr + info->page_size);
	if (!offset2)
		return NULL;

	if (offset2 - offset != info->page_size)
		return NULL;

	if (!is_mapped_with_mmap(offset) &&
	    !update_mmap_range(offset, 0)) {
		ERRMSG("Can't read the dump memory(%s) with mmap().\n",
		       info->name_memory);

		ERRMSG("This kernel might have some problems about mmap().\n");
		ERRMSG("read() will be used instead of mmap() from now.\n");

		/*
		 * Fall back to read().
		 */
		info->flag_usemmap = MMAP_DISABLE;
		return NULL;
	}

	if (offset < info->mmap_start_offset ||
	    offset + info->page_size > info->mmap_end_offset)
		return NULL;

	return info->mmap_buf + (offset - info->mmap_start_offset);
}

/*
 * This function is specific for reading page from ELF.
 *
 * If reading the separated page on different PT_LOAD segments,
 * this function gets the page data from both segments. This is
 * worthy of ia64 /proc/vmcore. In ia64 /proc/vmcore, region 5
 * segment is overlapping to region 7 segment. The following is
 * example (page_size is 16KBytes):
 *
 *  region |       paddr        |       memsz
 * --------+--------------------+--------------------
 *     5   | 0x0000000004000000 | 0x0000000000638ce0
 *     7   | 0x0000000004000000 | 0x0000000000db3000
 *
 * In the above example, the last page of region 5 is 0x4638000
 * and the segment does not contain complete data of this page.
 * Then this function gets the data of 0x4638000 - 0x4638ce0
 * from region 5, and gets the remaining data from region 7.
 */
static int
readpage_elf(unsigned long long paddr, void *bufptr)
{
	int idx;
	off_t offset, size;
	void *p, *endp;
	unsigned long long phys_start, phys_end;

	p = bufptr;
	endp = p + info->page_size;
	while (p < endp) {
		idx = closest_pt_load(paddr, endp - p);
		if (idx < 0)
			break;

		get_pt_load_extents(idx, &phys_start, &phys_end, &offset, &size);
		if (phys_start > paddr) {
			memset(p, 0, phys_start - paddr);
			p += phys_start - paddr;
			paddr = phys_start;
		}

		offset += paddr - phys_start;
		if (size > paddr - phys_start) {
			size -= paddr - phys_start;
			if (size > endp - p)
				size = endp - p;
			if (!read_from_vmcore(offset, p, size)) {
				ERRMSG("Can't read the dump memory(%s).\n",
				       info->name_memory);
				return FALSE;
			}
			p += size;
			paddr += size;
		}
		if (p < endp) {
			size = phys_end - paddr;
			if (size > endp - p)
				size = endp - p;
			memset(p, 0, size);
			p += size;
			paddr += size;
		}
	}

	if (p == bufptr) {
		ERRMSG("Attempt to read non-existent page at 0x%llx.\n",
		       paddr);
		return FALSE;
	} else if (p < endp)
		memset(p, 0, endp - p);

	return TRUE;
}

int
readmem(int type_addr, unsigned long long addr, void *bufptr, size_t size)
{
	size_t read_size, size_orig = size;
	unsigned long long paddr;
	unsigned long long pgaddr;
	void *pgbuf;
	struct cache_entry *cached;

next_page:
	switch (type_addr) {
	case VADDR:
		if ((paddr = vaddr_to_paddr(addr)) == NOT_PADDR) {
			ERRMSG("Can't convert a virtual address(%llx) to physical address.\n",
			    addr);
			goto error;
		}
		break;
	case PADDR:
		paddr = addr;
		break;
	// case VADDR_XEN:
	// 	if ((paddr = kvtop_xen(addr)) == NOT_PADDR) {
	// 		ERRMSG("Can't convert a virtual address(%llx) to machine address.\n",
	// 		    addr);
	// 		goto error;
	// 	}
	// 	break;
	default:
		ERRMSG("Invalid address type (%d).\n", type_addr);
		goto error;
	}

	/*
	 * Read each page, because pages are not necessarily continuous.
	 * Ex) pages in vmalloc area
	 */
	read_size = MIN(info->page_size - PAGEOFFSET(paddr), size);

	pgaddr = PAGEBASE(paddr);
	if (NUMBER(sme_mask) != NOT_FOUND_NUMBER)
		pgaddr = pgaddr & ~(NUMBER(sme_mask));
	pgbuf = cache_search(pgaddr, read_size);
	if (!pgbuf) {
		++cache_miss;
		cached = cache_alloc(pgaddr);
		if (!cached)
			goto error;
		pgbuf = cached->bufptr;

		char *mapbuf = mappage_elf(pgaddr);
		size_t mapoff;

		if (mapbuf) {
			pgbuf = mapbuf;
			mapoff = mapbuf - info->mmap_buf;
			cached->paddr = pgaddr - mapoff;
			cached->bufptr = info->mmap_buf;
			cached->buflen = info->mmap_end_offset -
				info->mmap_start_offset;
			cached->discard = unmap_cache;
		} else if (!readpage_elf(pgaddr, pgbuf))
			goto error_cached;

		cache_add(cached);
	} else
		++cache_hit;

	memcpy(bufptr, pgbuf + PAGEOFFSET(paddr), read_size);

	addr += read_size;
	bufptr += read_size;
	size -= read_size;

	if (size > 0)
		goto next_page;

	return size_orig;

error_cached:
	cache_free(cached);
error:
	ERRMSG("type_addr: %d, addr:%llx, size:%zd\n", type_addr, addr, size_orig);
	return FALSE;
}

void
initialize_tables(void)
{
	int i, size_member, num_member;
	unsigned long long *ptr_symtable;
	long *ptr_long_table;

	/*
	 * Initialize the symbol table.
	 */
	size_member = sizeof(symbol_table.mem_map);
	num_member  = sizeof(symbol_table) / size_member;

	ptr_symtable = (unsigned long long *)&symbol_table;

	for (i = 0; i < num_member; i++, ptr_symtable++)
		*ptr_symtable = NOT_FOUND_SYMBOL;

	INITIALIZE_LONG_TABLE(size_table, NOT_FOUND_STRUCTURE);
	INITIALIZE_LONG_TABLE(offset_table, NOT_FOUND_STRUCTURE);
	INITIALIZE_LONG_TABLE(array_table, NOT_FOUND_STRUCTURE);
	INITIALIZE_LONG_TABLE(number_table, NOT_FOUND_NUMBER);
}

int
parse_dump_level(char *str_dump_level)
{
	int i, ret = FALSE;
	char *buf, *ptr;

	if (!(buf = strdup(str_dump_level))) {
		MSG("Can't duplicate strings(%s).\n", str_dump_level);
		return FALSE;
	}
	info->max_dump_level = 0;
	info->num_dump_level = 0;
	ptr = buf;
	while(TRUE) {
		ptr = strtok(ptr, ",");
		if (!ptr)
			break;

		i = atoi(ptr);
		if ((i < MIN_DUMP_LEVEL) || (MAX_DUMP_LEVEL < i)) {
			MSG("Dump_level(%d) is invalid.\n", i);
			goto out;
		}
		if (NUM_ARRAY_DUMP_LEVEL <= info->num_dump_level) {
			MSG("Dump_level is invalid.\n");
			goto out;
		}
		if (info->max_dump_level < i)
			info->max_dump_level = i;
		if (info->num_dump_level == 0)
			info->dump_level = i;
		info->array_dump_level[info->num_dump_level] = i;
		info->num_dump_level++;
		ptr = NULL;
	}
	ret = TRUE;
out:
	free(buf);

	return ret;
}

int
is_page_size(long page_size)
{
	/*
	 * Page size is restricted to a hamming weight of 1.
	 */
	if (page_size > 0 && !(page_size & (page_size - 1)))
		return TRUE;

	return FALSE;
}

int
set_page_size(long page_size)
{
	if (!is_page_size(page_size)) {
		ERRMSG("Invalid page_size: %ld", page_size);
		return FALSE;
	}
	info->page_size = page_size;
	info->page_shift = ffs(info->page_size) - 1;
	DEBUG_MSG("page_size    : %ld\n", info->page_size);

	return TRUE;
}

int
read_vmcoreinfo_basic_info(void)
{
	time_t tv_sec = 0;
	long page_size = FALSE;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int get_release = FALSE, i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}

	DEBUG_MSG("VMCOREINFO   :\n");
	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';

		DEBUG_MSG("  %s\n", buf);
		if (strncmp(buf, STR_OSRELEASE, strlen(STR_OSRELEASE)) == 0) {
			get_release = TRUE;
			/* if the release have been stored, skip this time. */
			if (strlen(info->release))
				continue;
			strcpy(info->release, buf + strlen(STR_OSRELEASE));
		}
		if (strncmp(buf, STR_PAGESIZE, strlen(STR_PAGESIZE)) == 0) {
			page_size = strtol(buf+strlen(STR_PAGESIZE),&endp,10);
			if ((!page_size || page_size == LONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
			if (!set_page_size(page_size)) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
		}
		if (strncmp(buf, STR_CRASHTIME, strlen(STR_CRASHTIME)) == 0) {
			tv_sec = strtol(buf+strlen(STR_CRASHTIME),&endp,10);
			if ((!tv_sec || tv_sec == LONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return FALSE;
			}
			info->timestamp.tv_sec = tv_sec;
		}
		if (strncmp(buf, STR_CONFIG_X86_PAE,
		    strlen(STR_CONFIG_X86_PAE)) == 0)
			vt.mem_flags |= MEMORY_X86_PAE;

		if (strncmp(buf, STR_CONFIG_PGTABLE_3,
		    strlen(STR_CONFIG_PGTABLE_3)) == 0)
			vt.mem_flags |= MEMORY_PAGETABLE_3L;

		if (strncmp(buf, STR_CONFIG_PGTABLE_4,
		    strlen(STR_CONFIG_PGTABLE_4)) == 0)
			vt.mem_flags |= MEMORY_PAGETABLE_4L;
	}
	DEBUG_MSG("\n");

	if (!get_release || !info->page_size) {
		ERRMSG("Invalid format in %s", info->name_vmcoreinfo);
		return FALSE;
	}
	return TRUE;
}

unsigned long
read_vmcoreinfo_symbol(char *str_symbol)
{
	unsigned long symbol = NOT_FOUND_SYMBOL;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return INVALID_SYMBOL_DATA;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_symbol, strlen(str_symbol)) == 0) {
			symbol = strtoul(buf + strlen(str_symbol), &endp, 16);
			if ((!symbol || symbol == ULONG_MAX)
			    || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return INVALID_SYMBOL_DATA;
			}
			break;
		}
	}
	return symbol;
}

unsigned long
read_vmcoreinfo_ulong(char *str_structure)
{
	long data = NOT_FOUND_LONG_VALUE;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return INVALID_STRUCTURE_DATA;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_structure, strlen(str_structure)) == 0) {
			data = strtoul(buf + strlen(str_structure), &endp, 10);
			if (strlen(endp) != 0)
				data = strtoul(buf + strlen(str_structure), &endp, 16);
			if ((data == LONG_MAX) || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return INVALID_STRUCTURE_DATA;
			}
			break;
		}
	}
	return data;
}

long
read_vmcoreinfo_long(char *str_structure)
{
	long data = NOT_FOUND_LONG_VALUE;
	char buf[BUFSIZE_FGETS], *endp;
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return INVALID_STRUCTURE_DATA;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_structure, strlen(str_structure)) == 0) {
			data = strtol(buf + strlen(str_structure), &endp, 10);
			if (strlen(endp) != 0)
				data = strtol(buf + strlen(str_structure), &endp, 16);
			if ((data == LONG_MAX) || strlen(endp) != 0) {
				ERRMSG("Invalid data in %s: %s",
				    info->name_vmcoreinfo, buf);
				return INVALID_STRUCTURE_DATA;
			}
			break;
		}
	}
	return data;
}

int
read_vmcoreinfo_string(char *str_in, char *str_out)
{
	char buf[BUFSIZE_FGETS];
	unsigned int i;

	if (fseek(info->file_vmcoreinfo, 0, SEEK_SET) < 0) {
		ERRMSG("Can't seek the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}

	while (fgets(buf, BUFSIZE_FGETS, info->file_vmcoreinfo)) {
		i = strlen(buf);
		if (!i)
			break;
		if (buf[i - 1] == '\n')
			buf[i - 1] = '\0';
		if (strncmp(buf, str_in, strlen(str_in)) == 0) {
			strncpy(str_out, buf + strlen(str_in), LEN_SRCFILE - strlen(str_in));
			break;
		}
	}
	return TRUE;
}

int
read_vmcoreinfo(void)
{
	if (!read_vmcoreinfo_basic_info())
		return FALSE;

	READ_SYMBOL("mem_map", mem_map);
	READ_SYMBOL("vmem_map", vmem_map);
	READ_SYMBOL("mem_section", mem_section);
	READ_SYMBOL("pkmap_count", pkmap_count);
	READ_SYMBOL("pkmap_count_next", pkmap_count_next);
	READ_SYMBOL("system_utsname", system_utsname);
	READ_SYMBOL("init_uts_ns", init_uts_ns);
	READ_SYMBOL("_stext", _stext);
	READ_SYMBOL("swapper_pg_dir", swapper_pg_dir);
	READ_SYMBOL("init_level4_pgt", init_level4_pgt);
	READ_SYMBOL("level4_kernel_pgt", level4_kernel_pgt);
	READ_SYMBOL("init_top_pgt", init_top_pgt);
	READ_SYMBOL("vmlist", vmlist);
	READ_SYMBOL("vmap_area_list", vmap_area_list);
	READ_SYMBOL("node_online_map", node_online_map);
	READ_SYMBOL("node_states", node_states);
	READ_SYMBOL("node_data", node_data);
	READ_SYMBOL("pgdat_list", pgdat_list);
	READ_SYMBOL("contig_page_data", contig_page_data);
	READ_SYMBOL("log_buf", log_buf);
	READ_SYMBOL("log_buf_len", log_buf_len);
	READ_SYMBOL("log_end", log_end);
	READ_SYMBOL("log_first_idx", log_first_idx);
	READ_SYMBOL("clear_idx", clear_idx);
	READ_SYMBOL("log_next_idx", log_next_idx);
	READ_SYMBOL("max_pfn", max_pfn);
	READ_SYMBOL("high_memory", high_memory);
	READ_SYMBOL("node_remap_start_vaddr", node_remap_start_vaddr);
	READ_SYMBOL("node_remap_end_vaddr", node_remap_end_vaddr);
	READ_SYMBOL("node_remap_start_pfn", node_remap_start_pfn);
	READ_SYMBOL("vmemmap_list", vmemmap_list);
	READ_SYMBOL("mmu_psize_defs", mmu_psize_defs);
	READ_SYMBOL("mmu_vmemmap_psize", mmu_vmemmap_psize);
	READ_SYMBOL("cpu_pgd", cpu_pgd);
	READ_SYMBOL("demote_segment_4k", demote_segment_4k);
	READ_SYMBOL("cur_cpu_spec", cur_cpu_spec);
	READ_SYMBOL("free_huge_page", free_huge_page);

	READ_STRUCTURE_SIZE("page", page);
	READ_STRUCTURE_SIZE("mem_section", mem_section);
	READ_STRUCTURE_SIZE("pglist_data", pglist_data);
	READ_STRUCTURE_SIZE("zone", zone);
	READ_STRUCTURE_SIZE("free_area", free_area);
	READ_STRUCTURE_SIZE("list_head", list_head);
	READ_STRUCTURE_SIZE("node_memblk_s", node_memblk_s);
	READ_STRUCTURE_SIZE("nodemask_t", nodemask_t);
	READ_STRUCTURE_SIZE("pageflags", pageflags);
	READ_STRUCTURE_SIZE("vmemmap_backing", vmemmap_backing);
	READ_STRUCTURE_SIZE("mmu_psize_def", mmu_psize_def);


	READ_MEMBER_OFFSET("page.flags", page.flags);
	READ_MEMBER_OFFSET("page._refcount", page._refcount);
	if (OFFSET(page._refcount) == NOT_FOUND_STRUCTURE) {
		info->flag_use_count = TRUE;
		READ_MEMBER_OFFSET("page._count", page._refcount);
	} else {
		info->flag_use_count = FALSE;
	}
	READ_MEMBER_OFFSET("page.mapping", page.mapping);
	READ_MEMBER_OFFSET("page.lru", page.lru);
	READ_MEMBER_OFFSET("page._mapcount", page._mapcount);
	READ_MEMBER_OFFSET("page.private", page.private);
	READ_MEMBER_OFFSET("page.compound_dtor", page.compound_dtor);
	READ_MEMBER_OFFSET("page.compound_order", page.compound_order);
	READ_MEMBER_OFFSET("page.compound_head", page.compound_head);
	READ_MEMBER_OFFSET("mem_section.section_mem_map",
	    mem_section.section_mem_map);
	READ_MEMBER_OFFSET("pglist_data.node_zones", pglist_data.node_zones);
	READ_MEMBER_OFFSET("pglist_data.nr_zones", pglist_data.nr_zones);
	READ_MEMBER_OFFSET("pglist_data.node_mem_map",pglist_data.node_mem_map);
	READ_MEMBER_OFFSET("pglist_data.node_start_pfn",
	    pglist_data.node_start_pfn);
	READ_MEMBER_OFFSET("pglist_data.node_spanned_pages",
	    pglist_data.node_spanned_pages);
	READ_MEMBER_OFFSET("pglist_data.pgdat_next", pglist_data.pgdat_next);
	READ_MEMBER_OFFSET("zone.free_pages", zone.free_pages);
	READ_MEMBER_OFFSET("zone.free_area", zone.free_area);
	READ_MEMBER_OFFSET("zone.vm_stat", zone.vm_stat);
	READ_MEMBER_OFFSET("zone.spanned_pages", zone.spanned_pages);
	READ_MEMBER_OFFSET("free_area.free_list", free_area.free_list);
	READ_MEMBER_OFFSET("list_head.next", list_head.next);
	READ_MEMBER_OFFSET("list_head.prev", list_head.prev);
	READ_MEMBER_OFFSET("node_memblk_s.start_paddr", node_memblk_s.start_paddr);
	READ_MEMBER_OFFSET("node_memblk_s.size", node_memblk_s.size);
	READ_MEMBER_OFFSET("node_memblk_s.nid", node_memblk_s.nid);
	READ_MEMBER_OFFSET("vm_struct.addr", vm_struct.addr);
	READ_MEMBER_OFFSET("vmap_area.va_start", vmap_area.va_start);
	READ_MEMBER_OFFSET("vmap_area.list", vmap_area.list);
	READ_MEMBER_OFFSET("vmemmap_backing.phys", vmemmap_backing.phys);
	READ_MEMBER_OFFSET("vmemmap_backing.virt_addr",
	    vmemmap_backing.virt_addr);
	READ_MEMBER_OFFSET("vmemmap_backing.list", vmemmap_backing.list);
	READ_MEMBER_OFFSET("mmu_psize_def.shift", mmu_psize_def.shift);
	READ_MEMBER_OFFSET("cpu_spec.mmu_features", cpu_spec.mmu_features);

	READ_STRUCTURE_SIZE("printk_log", printk_log);
	if (SIZE(printk_log) != NOT_FOUND_STRUCTURE) {
		info->flag_use_printk_log = TRUE;
		READ_MEMBER_OFFSET("printk_log.ts_nsec", printk_log.ts_nsec);
		READ_MEMBER_OFFSET("printk_log.len", printk_log.len);
		READ_MEMBER_OFFSET("printk_log.text_len", printk_log.text_len);
	} else {
		info->flag_use_printk_log = FALSE;
		READ_STRUCTURE_SIZE("log", printk_log);
		READ_MEMBER_OFFSET("log.ts_nsec", printk_log.ts_nsec);
		READ_MEMBER_OFFSET("log.len", printk_log.len);
		READ_MEMBER_OFFSET("log.text_len", printk_log.text_len);
	}

	READ_ARRAY_LENGTH("node_data", node_data);
	READ_ARRAY_LENGTH("pgdat_list", pgdat_list);
	READ_ARRAY_LENGTH("mem_section", mem_section);
	READ_ARRAY_LENGTH("node_memblk", node_memblk);
	READ_ARRAY_LENGTH("zone.free_area", zone.free_area);
	READ_ARRAY_LENGTH("free_area.free_list", free_area.free_list);
	READ_ARRAY_LENGTH("node_remap_start_pfn", node_remap_start_pfn);

	READ_NUMBER("NR_FREE_PAGES", NR_FREE_PAGES);
	READ_NUMBER("N_ONLINE", N_ONLINE);
	READ_NUMBER("pgtable_l5_enabled", pgtable_l5_enabled);
	READ_NUMBER("sme_mask", sme_mask);

	READ_NUMBER("PG_lru", PG_lru);
	READ_NUMBER("PG_private", PG_private);
	READ_NUMBER("PG_head_mask", PG_head_mask);
	READ_NUMBER("PG_swapcache", PG_swapcache);
	READ_NUMBER("PG_swapbacked", PG_swapbacked);
	READ_NUMBER("PG_slab", PG_slab);
	READ_NUMBER("PG_buddy", PG_buddy);
	READ_NUMBER("PG_hwpoison", PG_hwpoison);
	READ_NUMBER("SECTION_SIZE_BITS", SECTION_SIZE_BITS);
	READ_NUMBER("MAX_PHYSMEM_BITS", MAX_PHYSMEM_BITS);

	READ_SRCFILE("pud_t", pud_t);

	READ_NUMBER("PAGE_BUDDY_MAPCOUNT_VALUE", PAGE_BUDDY_MAPCOUNT_VALUE);
	READ_NUMBER("PAGE_OFFLINE_MAPCOUNT_VALUE", PAGE_OFFLINE_MAPCOUNT_VALUE);
	READ_NUMBER("phys_base", phys_base);
	READ_NUMBER("KERNEL_IMAGE_SIZE", KERNEL_IMAGE_SIZE);
#ifdef __aarch64__
	READ_NUMBER("VA_BITS", VA_BITS);
	READ_NUMBER_UNSIGNED("PHYS_OFFSET", PHYS_OFFSET);
	READ_NUMBER_UNSIGNED("kimage_voffset", kimage_voffset);
#endif

	READ_NUMBER("HUGETLB_PAGE_DTOR", HUGETLB_PAGE_DTOR);

	return TRUE;
}

/*
 * Extract vmcoreinfo from /proc/vmcore and output it to /tmp/vmcoreinfo.tmp.
 */
int
copy_vmcoreinfo(off_t offset, unsigned long size)
{
	int fd;
	char buf[VMCOREINFO_BYTES];
	const off_t failed = (off_t)-1;

	if (!offset || !size)
		return FALSE;

	if ((fd = mkstemp(info->name_vmcoreinfo)) < 0) {
		ERRMSG("Can't open the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}
	if (lseek(info->fd_memory, offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (read(info->fd_memory, &buf, size) != size) {
		ERRMSG("Can't read the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
		return FALSE;
	}
	if (write(fd, &buf, size) != size) {
		ERRMSG("Can't write the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}
	if (close(fd) < 0) {
		ERRMSG("Can't close the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
open_vmcoreinfo(char *mode)
{
	FILE *file_vmcoreinfo;

	if ((file_vmcoreinfo = fopen(info->name_vmcoreinfo, mode)) == NULL) {
		ERRMSG("Can't open the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
		return FALSE;
	}
	info->file_vmcoreinfo = file_vmcoreinfo;
	return TRUE;
}

void
close_vmcoreinfo(void)
{
	if(fclose(info->file_vmcoreinfo) < 0)
		ERRMSG("Can't close the vmcoreinfo file(%s). %s\n",
		    info->name_vmcoreinfo, strerror(errno));
	info->file_vmcoreinfo = NULL;
}

int
read_vmcoreinfo_from_vmcore(off_t offset, unsigned long size, int flag_xen_hv)
{
	int ret = FALSE;

	/*
	 * Copy vmcoreinfo to /tmp/vmcoreinfoXXXXXX.
	 */
	if (!(info->name_vmcoreinfo = strdup(FILENAME_VMCOREINFO))) {
		MSG("Can't duplicate strings(%s).\n", FILENAME_VMCOREINFO);
		return FALSE;
	}
	if (!copy_vmcoreinfo(offset, size))
		goto out;

	/*
	 * Read vmcoreinfo from /tmp/vmcoreinfoXXXXXX.
	 */
	if (!open_vmcoreinfo("r"))
		goto out;

	unlink(info->name_vmcoreinfo);

// 	if (flag_xen_hv) {
// 		if (!read_vmcoreinfo_xen())
// 			goto out;
// 	} else {
// 		if (!read_vmcoreinfo())
// 			goto out;
// 	}
	if (!read_vmcoreinfo())
	        goto out;
	close_vmcoreinfo();

	ret = TRUE;
out:
	free(info->name_vmcoreinfo);
	info->name_vmcoreinfo = NULL;

	return ret;
}

int
get_value_for_old_linux(void)
{
	if (NUMBER(PG_lru) == NOT_FOUND_NUMBER)
		NUMBER(PG_lru) = PG_lru_ORIGINAL;
	if (NUMBER(PG_private) == NOT_FOUND_NUMBER)
		NUMBER(PG_private) = PG_private_ORIGINAL;
	if (NUMBER(PG_swapcache) == NOT_FOUND_NUMBER)
		NUMBER(PG_swapcache) = PG_swapcache_ORIGINAL;
	if (NUMBER(PG_swapbacked) == NOT_FOUND_NUMBER
	    && NUMBER(PG_swapcache) < NUMBER(PG_private))
		NUMBER(PG_swapbacked) = NUMBER(PG_private) + 6;
	if (NUMBER(PG_slab) == NOT_FOUND_NUMBER)
		NUMBER(PG_slab) = PG_slab_ORIGINAL;
	if (NUMBER(PG_head_mask) == NOT_FOUND_NUMBER)
		NUMBER(PG_head_mask) = 1L << PG_compound_ORIGINAL;

	/*
	 * The values from here are for free page filtering based on
	 * mem_map array. These are minimum effort to cover old
	 * kernels.
	 *
	 * The logic also needs offset values for some members of page
	 * structure. But it much depends on kernel versions. We avoid
	 * to hard code the values.
	 */
	if (NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE) == NOT_FOUND_NUMBER) {
		if (info->kernel_version == KERNEL_VERSION(2, 6, 38))
			NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE) =
				PAGE_BUDDY_MAPCOUNT_VALUE_v2_6_38;
		if (info->kernel_version >= KERNEL_VERSION(2, 6, 39))
			NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE) =
			PAGE_BUDDY_MAPCOUNT_VALUE_v2_6_39_to_latest_version;
	}
	if (SIZE(pageflags) == NOT_FOUND_STRUCTURE) {
		if (info->kernel_version >= KERNEL_VERSION(2, 6, 27))
			SIZE(pageflags) =
				PAGE_FLAGS_SIZE_v2_6_27_to_latest_version;
	}
	return TRUE;
}

int fallback_to_current_page_size(void)
{

	if (!set_page_size(sysconf(_SC_PAGE_SIZE)))
		return FALSE;

	DEBUG_MSG("WARNING: Cannot determine page size (no vmcoreinfo).\n");
	DEBUG_MSG("Using the dump kernel page size: %ld\n",
	    info->page_size);

	return TRUE;
}

/*
 * Get the number of the page descriptors from the ELF info.
 */
int
get_max_mapnr(void)
{
	unsigned long long max_paddr;

	max_paddr = get_max_paddr();
	info->max_mapnr = paddr_to_pfn(roundup(max_paddr, PAGESIZE()));

	DEBUG_MSG("\n");
	DEBUG_MSG("max_mapnr    : %llx\n", info->max_mapnr);

	return TRUE;
}

int
calibrate_machdep_info(void)
{
	if (NUMBER(MAX_PHYSMEM_BITS) > 0)
		info->max_physmem_bits = NUMBER(MAX_PHYSMEM_BITS);

	if (NUMBER(SECTION_SIZE_BITS) > 0)
		info->section_size_bits = NUMBER(SECTION_SIZE_BITS);

	return TRUE;
}

int
check_release(void)
{
	unsigned long utsname;

	/*
	 * Get the kernel version.
	 */
	if (SYMBOL(system_utsname) != NOT_FOUND_SYMBOL) {
		utsname = SYMBOL(system_utsname);
	} else if (SYMBOL(init_uts_ns) != NOT_FOUND_SYMBOL) {
		utsname = SYMBOL(init_uts_ns) + sizeof(int);
	} else {
		ERRMSG("Can't get the symbol of system_utsname.\n");
		return FALSE;
	}
	if (!readmem(VADDR, utsname, &info->system_utsname,
					sizeof(struct utsname))) {
		ERRMSG("Can't get the address of system_utsname.\n");
		return FALSE;
	}

	if (info->flag_read_vmcoreinfo) {
		if (strcmp(info->system_utsname.release, info->release)) {
			ERRMSG("%s and %s don't match.\n",
			    info->name_vmcoreinfo, info->name_memory);
			retcd = WRONG_RELEASE;
			return FALSE;
		}
	}

	if (info->kernel_version == FALSE) {
		ERRMSG("Can't get the kernel version.\n");
		return FALSE;
	}

	return TRUE;
}

/*
 * Get the number of online nodes.
 */
int
get_nodes_online(void)
{
	int len, i, j, online;
	unsigned long node_online_map = 0, bitbuf, *maskptr;

	if ((SYMBOL(node_online_map) == NOT_FOUND_SYMBOL)
	    && (SYMBOL(node_states) == NOT_FOUND_SYMBOL))
		return 0;

	if (SIZE(nodemask_t) == NOT_FOUND_STRUCTURE) {
		ERRMSG("Can't get the size of nodemask_t.\n");
		return 0;
	}

	len = SIZE(nodemask_t);
	vt.node_online_map_len = len/sizeof(unsigned long);
	if (!(vt.node_online_map = (unsigned long *)malloc(len))) {
		ERRMSG("Can't allocate memory for the node online map. %s\n",
		    strerror(errno));
		return 0;
	}
	if (SYMBOL(node_online_map) != NOT_FOUND_SYMBOL) {
		node_online_map = SYMBOL(node_online_map);
	} else if (SYMBOL(node_states) != NOT_FOUND_SYMBOL) {
		/*
		 * For linux-2.6.23-rc4-mm1
		 */
		node_online_map = SYMBOL(node_states)
		     + (SIZE(nodemask_t) * NUMBER(N_ONLINE));
	}
	if (!readmem(VADDR, node_online_map, vt.node_online_map, len)){
		ERRMSG("Can't get the node online map.\n");
		return 0;
	}
	online = 0;
	maskptr = (unsigned long *)vt.node_online_map;
	for (i = 0; i < vt.node_online_map_len; i++, maskptr++) {
		bitbuf = *maskptr;
		for (j = 0; j < sizeof(bitbuf) * 8; j++) {
			online += bitbuf & 1;
			bitbuf = bitbuf >> 1;
		}
	}
	return online;
}

int
get_numnodes(void)
{
	if (!(vt.numnodes = get_nodes_online())) {
		vt.numnodes = 1;
	}
	DEBUG_MSG("num of NODEs : %d\n", vt.numnodes);

	return TRUE;
}

int
next_online_node(int first)
{
	int i, j, node;
	unsigned long mask, *maskptr;

	/* It cannot occur */
	if ((first/(sizeof(unsigned long) * 8)) >= vt.node_online_map_len) {
		ERRMSG("next_online_node: %d is too large!\n", first);
		return -1;
	}

	maskptr = (unsigned long *)vt.node_online_map;
	for (i = node = 0; i <  vt.node_online_map_len; i++, maskptr++) {
		mask = *maskptr;
		for (j = 0; j < (sizeof(unsigned long) * 8); j++, node++) {
			if (mask & 1) {
				if (node >= first)
					return node;
			}
			mask >>= 1;
		}
	}
	return -1;
}

unsigned long
next_online_pgdat(int node)
{
	int i;
	unsigned long pgdat;

	/*
	 * Get the pglist_data structure from symbol "node_data".
	 *     The array number of symbol "node_data" cannot be gotten
	 *     from vmlinux. Instead, check it is DW_TAG_array_type.
	 */
	if ((SYMBOL(node_data) == NOT_FOUND_SYMBOL)
	    || (ARRAY_LENGTH(node_data) == NOT_FOUND_STRUCTURE))
		goto pgdat2;

	if (!readmem(VADDR, SYMBOL(node_data) + (node * sizeof(void *)),
	    &pgdat, sizeof pgdat))
		goto pgdat2;

	if (!is_kvaddr(pgdat))
		goto pgdat2;

	return pgdat;

pgdat2:
	/*
	 * Get the pglist_data structure from symbol "pgdat_list".
	 */
	if (SYMBOL(pgdat_list) == NOT_FOUND_SYMBOL)
		goto pgdat3;

	else if ((0 < node)
	    && (ARRAY_LENGTH(pgdat_list) == NOT_FOUND_STRUCTURE))
		goto pgdat3;

	else if ((ARRAY_LENGTH(pgdat_list) != NOT_FOUND_STRUCTURE)
	    && (ARRAY_LENGTH(pgdat_list) < node))
		goto pgdat3;

	if (!readmem(VADDR, SYMBOL(pgdat_list) + (node * sizeof(void *)),
	    &pgdat, sizeof pgdat))
		goto pgdat3;

	if (!is_kvaddr(pgdat))
		goto pgdat3;

	return pgdat;

pgdat3:
	/*
	 * linux-2.6.16 or former
	 */
	if ((SYMBOL(pgdat_list) == NOT_FOUND_SYMBOL)
	    || (OFFSET(pglist_data.pgdat_next) == NOT_FOUND_STRUCTURE))
		goto pgdat4;

	if (!readmem(VADDR, SYMBOL(pgdat_list), &pgdat, sizeof pgdat))
		goto pgdat4;

	if (!is_kvaddr(pgdat))
		goto pgdat4;

	if (node == 0)
		return pgdat;

	for (i = 1; i <= node; i++) {
		if (!readmem(VADDR, pgdat+OFFSET(pglist_data.pgdat_next),
		    &pgdat, sizeof pgdat))
			goto pgdat4;

		if (!is_kvaddr(pgdat))
			goto pgdat4;
	}
	return pgdat;

pgdat4:
	/*
	 * Get the pglist_data structure from symbol "contig_page_data".
	 */
	if (SYMBOL(contig_page_data) == NOT_FOUND_SYMBOL)
		return FALSE;

	if (node != 0)
		return FALSE;

	return SYMBOL(contig_page_data);
}


void
dump_mem_map(mdf_pfn_t pfn_start, mdf_pfn_t pfn_end,
    unsigned long mem_map, int num_mm)
{
	struct mem_map_data *mmd;

	mmd = &info->mem_map_data[num_mm];
	mmd->pfn_start = pfn_start;
	mmd->pfn_end   = pfn_end;
	mmd->mem_map   = mem_map;

	if (num_mm == 0)
		DEBUG_MSG("%13s %16s %16s %16s\n",
			"", "mem_map", "pfn_start", "pfn_end");

	DEBUG_MSG("mem_map[%4d] %16lx %16llx %16llx\n",
		num_mm, mem_map, pfn_start, pfn_end);

	return;
}

int
get_mm_flatmem(void)
{
	unsigned long mem_map;

	/*
	 * Get the address of the symbol "mem_map".
	 */
	if (!readmem(VADDR, SYMBOL(mem_map), &mem_map, sizeof mem_map)
	    || !mem_map) {
		ERRMSG("Can't get the address of mem_map.\n");
		return FALSE;
	}
	info->num_mem_map = 1;
	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		return FALSE;
	}
	// if (is_xen_memory())
	// 	dump_mem_map(0, info->dom0_mapnr, mem_map, 0);
	// else
		dump_mem_map(0, info->max_mapnr, mem_map, 0);

	return TRUE;
}

int
get_node_memblk(int num_memblk,
    unsigned long *start_paddr, unsigned long *size, int *nid)
{
	unsigned long node_memblk;

	if (ARRAY_LENGTH(node_memblk) <= num_memblk) {
		ERRMSG("Invalid num_memblk.\n");
		return FALSE;
	}
	node_memblk = SYMBOL(node_memblk) + SIZE(node_memblk_s) * num_memblk;
	if (!readmem(VADDR, node_memblk+OFFSET(node_memblk_s.start_paddr),
	    start_paddr, sizeof(unsigned long))) {
		ERRMSG("Can't get node_memblk_s.start_paddr.\n");
		return FALSE;
	}
	if (!readmem(VADDR, node_memblk + OFFSET(node_memblk_s.size),
	    size, sizeof(unsigned long))) {
		ERRMSG("Can't get node_memblk_s.size.\n");
		return FALSE;
	}
	if (!readmem(VADDR, node_memblk + OFFSET(node_memblk_s.nid),
	    nid, sizeof(int))) {
		ERRMSG("Can't get node_memblk_s.nid.\n");
		return FALSE;
	}
	return TRUE;
}

int
get_num_mm_discontigmem(void)
{
	int i, nid;
	unsigned long start_paddr, size;

	if ((SYMBOL(node_memblk) == NOT_FOUND_SYMBOL)
	    || (ARRAY_LENGTH(node_memblk) == NOT_FOUND_STRUCTURE)
	    || (SIZE(node_memblk_s) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(node_memblk_s.start_paddr) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(node_memblk_s.size) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(node_memblk_s.nid) == NOT_FOUND_STRUCTURE)) {
		return vt.numnodes;
	} else {
		for (i = 0; i < ARRAY_LENGTH(node_memblk); i++) {
			if (!get_node_memblk(i, &start_paddr, &size, &nid)) {
				ERRMSG("Can't get the node_memblk (%d)\n", i);
				return 0;
			}
			if (!start_paddr && !size &&!nid)
				break;

			DEBUG_MSG("nid : %d\n", nid);
			DEBUG_MSG("  start_paddr: %lx\n", start_paddr);
			DEBUG_MSG("  size       : %lx\n", size);
		}
		if (i == 0) {
			/*
			 * On non-NUMA systems, node_memblk_s is not set.
			 */
			return vt.numnodes;
		} else {
			return i;
		}
	}
}

int
separate_mem_map(struct mem_map_data *mmd, int *id_mm, int nid_pgdat,
    unsigned long mem_map_pgdat, unsigned long pfn_start_pgdat)
{
	int i, nid;
	unsigned long start_paddr, size, pfn_start, pfn_end, mem_map;

	for (i = 0; i < ARRAY_LENGTH(node_memblk); i++) {
		if (!get_node_memblk(i, &start_paddr, &size, &nid)) {
			ERRMSG("Can't get the node_memblk (%d)\n", i);
			return FALSE;
		}
		if (!start_paddr && !size && !nid)
			break;

		/*
		 * Check pglist_data.node_id and node_memblk_s.nid match.
		 */
		if (nid_pgdat != nid)
			continue;

		pfn_start = paddr_to_pfn(start_paddr);
		pfn_end   = paddr_to_pfn(start_paddr + size);

		if (pfn_start < pfn_start_pgdat) {
			ERRMSG("node_memblk_s.start_paddr of node (%d) is invalid.\n", nid);
			return FALSE;
		}
		if (info->max_mapnr < pfn_end) {
			DEBUG_MSG("pfn_end of node (%d) is over max_mapnr.\n",
			    nid);
			DEBUG_MSG("  pfn_start: %lx\n", pfn_start);
			DEBUG_MSG("  pfn_end  : %lx\n", pfn_end);
			DEBUG_MSG("  max_mapnr: %llx\n", info->max_mapnr);

			pfn_end = info->max_mapnr;
		}

		mem_map = mem_map_pgdat+SIZE(page)*(pfn_start-pfn_start_pgdat);

		mmd->pfn_start = pfn_start;
		mmd->pfn_end   = pfn_end;
		mmd->mem_map   = mem_map;

		mmd++;
		(*id_mm)++;
	}
	return TRUE;
}

int
get_mm_discontigmem(void)
{
	int i, j, id_mm, node, num_mem_map, separate_mm = FALSE;
	unsigned long pgdat, mem_map, pfn_start, pfn_end, node_spanned_pages;
	unsigned long vmem_map;
	struct mem_map_data temp_mmd;

	num_mem_map = get_num_mm_discontigmem();
	if (num_mem_map < vt.numnodes) {
		ERRMSG("Can't get the number of mem_map.\n");
		return FALSE;
	}
	struct mem_map_data mmd[num_mem_map];
	if (vt.numnodes < num_mem_map) {
		separate_mm = TRUE;
	}

	/*
	 * Note:
	 *  This note is only for ia64 discontigmem kernel.
	 *  It is better to take mem_map information from a symbol vmem_map
	 *  instead of pglist_data.node_mem_map, because some node_mem_map
	 *  sometimes does not have mem_map information corresponding to its
	 *  node_start_pfn.
	 */
	if (SYMBOL(vmem_map) != NOT_FOUND_SYMBOL) {
		if (!readmem(VADDR, SYMBOL(vmem_map), &vmem_map, sizeof vmem_map)) {
			ERRMSG("Can't get vmem_map.\n");
			return FALSE;
		}
	}

	/*
	 * Get the first node_id.
	 */
	if ((node = next_online_node(0)) < 0) {
		ERRMSG("Can't get next online node.\n");
		return FALSE;
	}
	if (!(pgdat = next_online_pgdat(node))) {
		ERRMSG("Can't get pgdat list.\n");
		return FALSE;
	}
	id_mm = 0;
	for (i = 0; i < vt.numnodes; i++) {
		if (!readmem(VADDR, pgdat + OFFSET(pglist_data.node_start_pfn),
		    &pfn_start, sizeof pfn_start)) {
			ERRMSG("Can't get node_start_pfn.\n");
			return FALSE;
		}
		if (!readmem(VADDR,pgdat+OFFSET(pglist_data.node_spanned_pages),
		    &node_spanned_pages, sizeof node_spanned_pages)) {
			ERRMSG("Can't get node_spanned_pages.\n");
			return FALSE;
		}
		pfn_end = pfn_start + node_spanned_pages;

		if (SYMBOL(vmem_map) == NOT_FOUND_SYMBOL) {
			if (!readmem(VADDR, pgdat + OFFSET(pglist_data.node_mem_map),
			    &mem_map, sizeof mem_map)) {
				ERRMSG("Can't get mem_map.\n");
				return FALSE;
			}
		} else
			mem_map = vmem_map + (SIZE(page) * pfn_start);

		if (separate_mm) {
			/*
			 * For some ia64 NUMA systems.
			 * On some systems, a node has the separated memory.
			 * And pglist_data(s) have the duplicated memory range
			 * like following:
			 *
			 * Nid:      Physical address
			 *  0 : 0x1000000000 - 0x2000000000
			 *  1 : 0x2000000000 - 0x3000000000
			 *  2 : 0x0000000000 - 0x6020000000 <- Overlapping
			 *  3 : 0x3000000000 - 0x4000000000
			 *  4 : 0x4000000000 - 0x5000000000
			 *  5 : 0x5000000000 - 0x6000000000
			 *
			 * Then, mem_map(s) should be separated by
			 * node_memblk_s info.
			 */
			if (!separate_mem_map(&mmd[id_mm], &id_mm, node,
			    mem_map, pfn_start)) {
				ERRMSG("Can't separate mem_map.\n");
				return FALSE;
			}
		} else {
			if (info->max_mapnr < pfn_end) {
				DEBUG_MSG("pfn_end of node (%d) is over max_mapnr.\n",
				    node);
				DEBUG_MSG("  pfn_start: %lx\n", pfn_start);
				DEBUG_MSG("  pfn_end  : %lx\n", pfn_end);
				DEBUG_MSG("  max_mapnr: %llx\n", info->max_mapnr);

				pfn_end = info->max_mapnr;
			}

			/*
			 * The number of mem_map is the same as the number
			 * of nodes.
			 */
			mmd[id_mm].pfn_start = pfn_start;
			mmd[id_mm].pfn_end   = pfn_end;
			mmd[id_mm].mem_map   = mem_map;
			id_mm++;
		}

		/*
		 * Get pglist_data of the next node.
		 */
		if (i < (vt.numnodes - 1)) {
			if ((node = next_online_node(node + 1)) < 0) {
				ERRMSG("Can't get next online node.\n");
				return FALSE;
			} else if (!(pgdat = next_online_pgdat(node))) {
				ERRMSG("Can't determine pgdat list (node %d).\n",
				    node);
				return FALSE;
			}
		}
	}

	/*
	 * Sort mem_map by pfn_start.
	 */
	for (i = 0; i < (num_mem_map - 1); i++) {
		for (j = i + 1; j < num_mem_map; j++) {
			if (mmd[j].pfn_start < mmd[i].pfn_start) {
				temp_mmd = mmd[j];
				mmd[j] = mmd[i];
				mmd[i] = temp_mmd;
			}
		}
	}

	/*
	 * Calculate the number of mem_map.
	 */
	info->num_mem_map = num_mem_map;
	if (mmd[0].pfn_start != 0)
		info->num_mem_map++;

	for (i = 0; i < num_mem_map - 1; i++) {
		if (mmd[i].pfn_end > mmd[i + 1].pfn_start) {
			ERRMSG("The mem_map is overlapped with the next one.\n");
			ERRMSG("mmd[%d].pfn_end   = %llx\n", i, mmd[i].pfn_end);
			ERRMSG("mmd[%d].pfn_start = %llx\n", i + 1, mmd[i + 1].pfn_start);
			return FALSE;
		} else if (mmd[i].pfn_end == mmd[i + 1].pfn_start)
			/*
			 * Continuous mem_map
			 */
			continue;

		/*
		 * Discontinuous mem_map
		 */
		info->num_mem_map++;
	}
	if (mmd[num_mem_map - 1].pfn_end < info->max_mapnr)
		info->num_mem_map++;

	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		return FALSE;
	}

	/*
	 * Create mem_map data.
	 */
	id_mm = 0;
	if (mmd[0].pfn_start != 0) {
		dump_mem_map(0, mmd[0].pfn_start, NOT_MEMMAP_ADDR, id_mm);
		id_mm++;
	}
	for (i = 0; i < num_mem_map; i++) {
		dump_mem_map(mmd[i].pfn_start, mmd[i].pfn_end,
		    mmd[i].mem_map, id_mm);
		id_mm++;
		if ((i < num_mem_map - 1)
		    && (mmd[i].pfn_end != mmd[i + 1].pfn_start)) {
			dump_mem_map(mmd[i].pfn_end, mmd[i +1].pfn_start,
			    NOT_MEMMAP_ADDR, id_mm);
			id_mm++;
		}
	}
	i = num_mem_map - 1;
	// if (is_xen_memory()) {
	// 	if (mmd[i].pfn_end < info->dom0_mapnr)
	// 		dump_mem_map(mmd[i].pfn_end, info->dom0_mapnr,
	// 		    NOT_MEMMAP_ADDR, id_mm);
	// } else {
		if (mmd[i].pfn_end < info->max_mapnr)
			dump_mem_map(mmd[i].pfn_end, info->max_mapnr,
			    NOT_MEMMAP_ADDR, id_mm);
	// }
	return TRUE;
}

int
is_sparsemem_extreme(void)
{
	if ((ARRAY_LENGTH(mem_section)
	     == divideup(NR_MEM_SECTIONS(), _SECTIONS_PER_ROOT_EXTREME()))
	    || (ARRAY_LENGTH(mem_section) == NOT_FOUND_STRUCTURE))
		return TRUE;
	else
		return FALSE;
}

int
get_mem_type(void)
{
	int ret;

	if ((SIZE(page) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.flags) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page._refcount) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.mapping) == NOT_FOUND_STRUCTURE)) {
		ret = NOT_FOUND_MEMTYPE;
	} else if ((((SYMBOL(node_data) != NOT_FOUND_SYMBOL)
	        && (ARRAY_LENGTH(node_data) != NOT_FOUND_STRUCTURE))
	    || ((SYMBOL(pgdat_list) != NOT_FOUND_SYMBOL)
	        && (OFFSET(pglist_data.pgdat_next) != NOT_FOUND_STRUCTURE))
	    || ((SYMBOL(pgdat_list) != NOT_FOUND_SYMBOL)
	        && (ARRAY_LENGTH(pgdat_list) != NOT_FOUND_STRUCTURE)))
	    && (SIZE(pglist_data) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(pglist_data.node_mem_map) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(pglist_data.node_start_pfn) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(pglist_data.node_spanned_pages) !=NOT_FOUND_STRUCTURE)){
		ret = DISCONTIGMEM;
	} else if ((SYMBOL(mem_section) != NOT_FOUND_SYMBOL)
	    && (SIZE(mem_section) != NOT_FOUND_STRUCTURE)
	    && (OFFSET(mem_section.section_mem_map) != NOT_FOUND_STRUCTURE)) {
		if (is_sparsemem_extreme())
			ret = SPARSEMEM_EX;
		else
			ret = SPARSEMEM;
	} else if (SYMBOL(mem_map) != NOT_FOUND_SYMBOL) {
		ret = FLATMEM;
	} else {
		ret = NOT_FOUND_MEMTYPE;
	}

	return ret;
}

static unsigned long
nr_to_section(unsigned long nr, unsigned long *mem_sec)
{
	unsigned long addr;

	if (is_sparsemem_extreme()) {
		if (mem_sec[SECTION_NR_TO_ROOT(nr)] == 0)
			return NOT_KV_ADDR;
		addr = mem_sec[SECTION_NR_TO_ROOT(nr)] +
		    (nr & SECTION_ROOT_MASK()) * SIZE(mem_section);
	} else {
		addr = SYMBOL(mem_section) + (nr * SIZE(mem_section));
	}

	return addr;
}

static unsigned long
section_mem_map_addr(unsigned long addr, unsigned long *map_mask)
{
	char *mem_section;
	unsigned long map;
	unsigned long mask;

	*map_mask = 0;

	if (!is_kvaddr(addr))
		return NOT_KV_ADDR;

	if ((mem_section = malloc(SIZE(mem_section))) == NULL) {
		ERRMSG("Can't allocate memory for a struct mem_section. %s\n",
		    strerror(errno));
		return NOT_KV_ADDR;
	}
	if (!readmem(VADDR, addr, mem_section, SIZE(mem_section))) {
		ERRMSG("Can't get a struct mem_section(%lx).\n", addr);
		free(mem_section);
		return NOT_KV_ADDR;
	}
	map = ULONG(mem_section + OFFSET(mem_section.section_mem_map));
	mask = SECTION_MAP_MASK;
	*map_mask = map & ~mask;
	map &= mask;
	free(mem_section);

	return map;
}

static unsigned long
sparse_decode_mem_map(unsigned long coded_mem_map, unsigned long section_nr)
{
	unsigned long mem_map;

	mem_map =  coded_mem_map +
	    (SECTION_NR_TO_PFN(section_nr) * SIZE(page));

	return mem_map;
}

/*
 * On some kernels, mem_section may be a pointer or an array, when
 * SPARSEMEM_EXTREME is on.
 *
 * We assume that section_mem_map is either 0 or has the present bit set.
 *
 */

static int
validate_mem_section(unsigned long *mem_sec,
		     unsigned long mem_section_ptr, unsigned int mem_section_size,
		     unsigned long *mem_maps, unsigned int num_section)
{
	unsigned int section_nr;
	unsigned long map_mask;
	unsigned long section, mem_map;
	int ret = FALSE;

	if (!readmem(VADDR, mem_section_ptr, mem_sec, mem_section_size)) {
		ERRMSG("Can't read mem_section array.\n");
		return FALSE;
	}
	for (section_nr = 0; section_nr < num_section; section_nr++) {
		section = nr_to_section(section_nr, mem_sec);
		if (section == NOT_KV_ADDR) {
			mem_map = NOT_MEMMAP_ADDR;
		} else {
			mem_map = section_mem_map_addr(section, &map_mask);
			/* for either no mem_map or hot-removed */
			if (!(map_mask & SECTION_MARKED_PRESENT)) {
				mem_map = NOT_MEMMAP_ADDR;
			} else {
				mem_map = sparse_decode_mem_map(mem_map,
								section_nr);
				if (!is_kvaddr(mem_map)) {
					return FALSE;
				}
				ret = TRUE;
			}
		}
		mem_maps[section_nr] = mem_map;
	}
	return ret;
}

static int
get_mem_section(unsigned int mem_section_size, unsigned long *mem_maps,
		unsigned int num_section)
{
	int ret = FALSE;
	unsigned long *mem_sec = NULL;

	if ((mem_sec = malloc(mem_section_size)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_section. %s\n",
		    strerror(errno));
		return FALSE;
	}
	ret = validate_mem_section(mem_sec, SYMBOL(mem_section),
				   mem_section_size, mem_maps, num_section);

	if (!ret && is_sparsemem_extreme()) {
		unsigned long mem_section_ptr;

		if (!readmem(VADDR, SYMBOL(mem_section), &mem_section_ptr,
			     sizeof(mem_section_ptr)))
			goto out;

		ret = validate_mem_section(mem_sec, mem_section_ptr,
				mem_section_size, mem_maps, num_section);

		if (!ret)
			ERRMSG("Could not validate mem_section.\n");
	}
out:
	if (mem_sec != NULL)
		free(mem_sec);
	return ret;
}

int
get_mm_sparsemem(void)
{
	unsigned int section_nr, mem_section_size, num_section;
	mdf_pfn_t pfn_start, pfn_end;
	unsigned long *mem_maps = NULL;

	int ret = FALSE;

	/*
	 * Get the address of the symbol "mem_section".
	 */
	num_section = divideup(info->max_mapnr, PAGES_PER_SECTION());
	if (is_sparsemem_extreme()) {
		info->sections_per_root = _SECTIONS_PER_ROOT_EXTREME();
		mem_section_size = sizeof(void *) * NR_SECTION_ROOTS();
	} else {
		info->sections_per_root = _SECTIONS_PER_ROOT();
		mem_section_size = SIZE(mem_section) * NR_SECTION_ROOTS();
	}
	if ((mem_maps = malloc(sizeof(*mem_maps) * num_section)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_maps. %s\n",
			strerror(errno));
		return FALSE;
	}
	if (!get_mem_section(mem_section_size, mem_maps, num_section)) {
		ERRMSG("Can't get the address of mem_section.\n");
		goto out;
	}
	info->num_mem_map = num_section;
	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		goto out;
	}
	for (section_nr = 0; section_nr < num_section; section_nr++) {
		pfn_start = section_nr * PAGES_PER_SECTION();
		pfn_end   = pfn_start + PAGES_PER_SECTION();
		if (info->max_mapnr < pfn_end)
			pfn_end = info->max_mapnr;
		dump_mem_map(pfn_start, pfn_end, mem_maps[section_nr], section_nr);
	}
	ret = TRUE;
out:
	if (mem_maps != NULL)
		free(mem_maps);
	return ret;
}

int
get_mem_map_without_mm(void)
{
	info->num_mem_map = 1;
	if ((info->mem_map_data = (struct mem_map_data *)
	    malloc(sizeof(struct mem_map_data)*info->num_mem_map)) == NULL) {
		ERRMSG("Can't allocate memory for the mem_map_data. %s\n",
		    strerror(errno));
		return FALSE;
	}
	// if (is_xen_memory())
	// 	dump_mem_map(0, info->dom0_mapnr, NOT_MEMMAP_ADDR, 0);
	// else
		dump_mem_map(0, info->max_mapnr, NOT_MEMMAP_ADDR, 0);

	return TRUE;
}

int
get_mem_map(void)
{
	mdf_pfn_t max_pfn = 0;
	unsigned int i;
	int ret;

	switch (get_mem_type()) {
	case SPARSEMEM:
		DEBUG_MSG("Memory type  : SPARSEMEM\n\n");
		ret = get_mm_sparsemem();
		break;
	case SPARSEMEM_EX:
		DEBUG_MSG("Memory type  : SPARSEMEM_EX\n\n");
		ret = get_mm_sparsemem();
		break;
	case DISCONTIGMEM:
		DEBUG_MSG("Memory type  : DISCONTIGMEM\n\n");
		ret = get_mm_discontigmem();
		break;
	case FLATMEM:
		DEBUG_MSG("Memory type  : FLATMEM\n\n");
		ret = get_mm_flatmem();
		break;
	default:
		ERRMSG("Can't distinguish the memory type.\n");
		ret = FALSE;
		break;
	}
	/*
	 * Adjust "max_mapnr" for the case that Linux uses less memory
	 * than is dumped. For example when "mem=" has been used for the
	 * dumped system.
	 */
	if (!is_xen_memory()) {
		unsigned int valid_memmap = 0;
		for (i = 0; i < info->num_mem_map; i++) {
			if (info->mem_map_data[i].mem_map == NOT_MEMMAP_ADDR)
				continue;
			max_pfn = MAX(max_pfn, info->mem_map_data[i].pfn_end);
			valid_memmap++;
		}
		if (valid_memmap) {
			info->max_mapnr = MIN(info->max_mapnr, max_pfn);
		}
	}
	return ret;
}

void
initialize_bitmap(struct dump_bitmap *bitmap)
{
	if (info->fd_bitmap >= 0) {
		bitmap->fd        = info->fd_bitmap;
		bitmap->file_name = info->name_bitmap;
		bitmap->no_block  = -1;
		memset(bitmap->buf, 0, BUFSIZE_BITMAP);
	} else {
		bitmap->fd        = -1;
		bitmap->file_name = NULL;
		bitmap->no_block  = -1;
		memset(bitmap->buf, 0, info->bufsize_cyclic);
	}
}

void
initialize_1st_bitmap(struct dump_bitmap *bitmap)
{
	initialize_bitmap(bitmap);
	bitmap->offset = 0;
}

void
initialize_2nd_bitmap(struct dump_bitmap *bitmap)
{
	initialize_bitmap(bitmap);
	bitmap->offset = info->len_bitmap / 2;
}

void
initialize_2nd_bitmap_parallel(struct dump_bitmap *bitmap, int thread_num)
{
	bitmap->fd = FD_BITMAP_PARALLEL(thread_num);
	bitmap->file_name = info->name_bitmap;
	bitmap->no_block = -1;
	memset(bitmap->buf, 0, BUFSIZE_BITMAP);
	bitmap->offset = info->len_bitmap / 2;
}

int
set_bitmap_file(struct dump_bitmap *bitmap, mdf_pfn_t pfn, int val)
{
	int byte, bit;
	off_t old_offset, new_offset;
	old_offset = bitmap->offset + BUFSIZE_BITMAP * bitmap->no_block;
	new_offset = bitmap->offset + BUFSIZE_BITMAP * (pfn / PFN_BUFBITMAP);

	if (0 <= bitmap->no_block && old_offset != new_offset) {
		if (lseek(bitmap->fd, old_offset, SEEK_SET) < 0 ) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
			    bitmap->file_name, strerror(errno));
			return FALSE;
		}
		if (write(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP)
		    != BUFSIZE_BITMAP) {
			ERRMSG("Can't write the bitmap(%s). %s\n",
			    bitmap->file_name, strerror(errno));
			return FALSE;
		}
	}
	if (old_offset != new_offset) {
		if (lseek(bitmap->fd, new_offset, SEEK_SET) < 0 ) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
			    bitmap->file_name, strerror(errno));
			return FALSE;
		}
		if (read(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP)
		    != BUFSIZE_BITMAP) {
			ERRMSG("Can't read the bitmap(%s). %s\n",
			    bitmap->file_name, strerror(errno));
			return FALSE;
		}
		bitmap->no_block = pfn / PFN_BUFBITMAP;
	}
	/*
	 * If val is 0, clear bit on the bitmap.
	 */
	byte = (pfn%PFN_BUFBITMAP)>>3;
	bit  = (pfn%PFN_BUFBITMAP) & 7;
	if (val)
		bitmap->buf[byte] |= 1<<bit;
	else
		bitmap->buf[byte] &= ~(1<<bit);

	return TRUE;
}

int
set_bitmap_buffer(struct dump_bitmap *bitmap, mdf_pfn_t pfn, int val, struct cycle *cycle)
{
	int byte, bit;
	static int warning = 0;

        if (!is_cyclic_region(pfn, cycle)) {
		if (warning == 0) {
			MSG("WARNING: PFN out of cycle range. (pfn:%llx, ", pfn);
			MSG("cycle:[%llx-%llx])\n", cycle->start_pfn, cycle->end_pfn);
			warning = 1;
		}
                return FALSE;
	}

	/*
	 * If val is 0, clear bit on the bitmap.
	 */
	byte = (pfn - cycle->start_pfn)>>3;
	bit  = (pfn - cycle->start_pfn) & 7;
	if (val)
		bitmap->buf[byte] |= 1<<bit;
	else
		bitmap->buf[byte] &= ~(1<<bit);

	return TRUE;
}

int
set_bitmap(struct dump_bitmap *bitmap, mdf_pfn_t pfn, int val, struct cycle *cycle)
{
	if (bitmap->fd >= 0) {
		return set_bitmap_file(bitmap, pfn, val);
	} else {
		return set_bitmap_buffer(bitmap, pfn, val, cycle);
	}
}

int
sync_bitmap(struct dump_bitmap *bitmap)
{
	off_t offset;
	offset = bitmap->offset + BUFSIZE_BITMAP * bitmap->no_block;

	/*
	 * The bitmap doesn't have the fd, it's a on-memory bitmap.
	 */
	if (bitmap->fd < 0)
		return TRUE;
	/*
	 * The bitmap buffer is not dirty, and it is not necessary
	 * to write out it.
	 */
	if (bitmap->no_block < 0)
		return TRUE;

	if (lseek(bitmap->fd, offset, SEEK_SET) < 0 ) {
		ERRMSG("Can't seek the bitmap(%s). %s\n",
		    bitmap->file_name, strerror(errno));
		return FALSE;
	}
	if (write(bitmap->fd, bitmap->buf, BUFSIZE_BITMAP)
	    != BUFSIZE_BITMAP) {
		ERRMSG("Can't write the bitmap(%s). %s\n",
		    bitmap->file_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

int
sync_1st_bitmap(void)
{
	return sync_bitmap(info->bitmap1);
}

int
sync_2nd_bitmap(void)
{
	return sync_bitmap(info->bitmap2);
}

int
set_bit_on_1st_bitmap(mdf_pfn_t pfn, struct cycle *cycle)
{
	return set_bitmap(info->bitmap1, pfn, 1, cycle);
}

int
clear_bit_on_1st_bitmap(mdf_pfn_t pfn, struct cycle *cycle)
{
	return set_bitmap(info->bitmap1, pfn, 0, cycle);

}

int
clear_bit_on_2nd_bitmap(mdf_pfn_t pfn, struct cycle *cycle)
{
	return set_bitmap(info->bitmap2, pfn, 0, cycle);
}

int
clear_bit_on_2nd_bitmap_for_kernel(mdf_pfn_t pfn, struct cycle *cycle)
{
	unsigned long long maddr;

	// if (is_xen_memory()) {
	// 	maddr = ptom_xen(pfn_to_paddr(pfn));
	// 	if (maddr == NOT_PADDR) {
	// 		ERRMSG("Can't convert a physical address(%llx) to machine address.\n",
	// 		    pfn_to_paddr(pfn));
	// 		return FALSE;
	// 	}
	// 	pfn = paddr_to_pfn(maddr);
	// }
	return clear_bit_on_2nd_bitmap(pfn, cycle);
}

int
set_bit_on_2nd_bitmap(mdf_pfn_t pfn, struct cycle *cycle)
{
	return set_bitmap(info->bitmap2, pfn, 1, cycle);
}

int
set_bit_on_2nd_bitmap_for_kernel(mdf_pfn_t pfn, struct cycle *cycle)
{
	unsigned long long maddr;

	// if (is_xen_memory()) {
	// 	maddr = ptom_xen(pfn_to_paddr(pfn));
	// 	if (maddr == NOT_PADDR) {
	// 		ERRMSG("Can't convert a physical address(%llx) to machine address.\n",
	// 		    pfn_to_paddr(pfn));
	// 		return FALSE;
	// 	}
	// 	pfn = paddr_to_pfn(maddr);
	// }
	return set_bit_on_2nd_bitmap(pfn, cycle);
}

int
read_cache(struct cache_data *cd)
{
	const off_t failed = (off_t)-1;

	if (lseek(cd->fd, cd->offset, SEEK_SET) == failed) {
		ERRMSG("Can't seek the dump file(%s). %s\n",
		    cd->file_name, strerror(errno));
		return FALSE;
	}
	if (read(cd->fd, cd->buf, cd->cache_size) != cd->cache_size) {
		ERRMSG("Can't read the dump file(%s). %s\n",
		    cd->file_name, strerror(errno));
		return FALSE;
	}
	cd->offset += cd->cache_size;
	return TRUE;
}

int
is_bigendian(void)
{
	int i = 0x12345678;

	if (*(char *)&i == 0x12)
		return TRUE;
	else
		return FALSE;
}


mdf_pfn_t
page_to_pfn(unsigned long page)
{
	unsigned int num;
	mdf_pfn_t pfn = ULONGLONG_MAX;
	unsigned long long index = 0;
	struct mem_map_data *mmd;

	mmd = info->mem_map_data;
	for (num = 0; num < info->num_mem_map; num++, mmd++) {
		if (mmd->mem_map == NOT_MEMMAP_ADDR)
			continue;
		if (page < mmd->mem_map)
			continue;
		index = (page - mmd->mem_map) / SIZE(page);
		if (index >= mmd->pfn_end - mmd->pfn_start)
			continue;
		pfn = mmd->pfn_start + index;
		break;
	}
	if (pfn == ULONGLONG_MAX) {
		ERRMSG("Can't convert the address of page descriptor (%lx) to pfn.\n", page);
		return ULONGLONG_MAX;
	}
	return pfn;
}

int
reset_bitmap_of_free_pages(unsigned long node_zones, struct cycle *cycle)
{

	int order, i, migrate_type, migrate_types;
	unsigned long curr, previous, head, curr_page, curr_prev;
	unsigned long addr_free_pages, free_pages = 0, found_free_pages = 0;
	mdf_pfn_t pfn, start_pfn;

	/*
	 * On linux-2.6.24 or later, free_list is divided into the array.
	 */
	migrate_types = ARRAY_LENGTH(free_area.free_list);
	if (migrate_types == NOT_FOUND_STRUCTURE)
		migrate_types = 1;

	for (order = (ARRAY_LENGTH(zone.free_area) - 1); order >= 0; --order) {
		for (migrate_type = 0; migrate_type < migrate_types;
		     migrate_type++) {
			head = node_zones + OFFSET(zone.free_area)
				+ SIZE(free_area) * order
				+ OFFSET(free_area.free_list)
				+ SIZE(list_head) * migrate_type;
			previous = head;
			if (!readmem(VADDR, head + OFFSET(list_head.next),
				     &curr, sizeof curr)) {
				ERRMSG("Can't get next list_head.\n");
				return FALSE;
			}
			for (;curr != head;) {
				curr_page = curr - OFFSET(page.lru);
				start_pfn = page_to_pfn(curr_page);
				if (start_pfn == ULONGLONG_MAX)
					return FALSE;

				if (!readmem(VADDR, curr+OFFSET(list_head.prev),
					     &curr_prev, sizeof curr_prev)) {
					ERRMSG("Can't get prev list_head.\n");
					return FALSE;
				}
				if (previous != curr_prev) {
					ERRMSG("The free list is broken.\n");
					return FALSE;
				}
				for (i = 0; i < (1<<order); i++) {
					pfn = start_pfn + i;
					if (clear_bit_on_2nd_bitmap_for_kernel(pfn, cycle))
						found_free_pages++;
				}

				previous = curr;
				if (!readmem(VADDR, curr+OFFSET(list_head.next),
					     &curr, sizeof curr)) {
					ERRMSG("Can't get next list_head.\n");
					return FALSE;
				}
			}
		}
	}

	/*
	 * Check the number of free pages.
	 */
	if (OFFSET(zone.free_pages) != NOT_FOUND_STRUCTURE) {
		addr_free_pages = node_zones + OFFSET(zone.free_pages);

	} else if (OFFSET(zone.vm_stat) != NOT_FOUND_STRUCTURE) {
		/*
		 * On linux-2.6.21 or later, the number of free_pages is
		 * in vm_stat[NR_FREE_PAGES].
		 */
		addr_free_pages = node_zones + OFFSET(zone.vm_stat)
		    + sizeof(long) * NUMBER(NR_FREE_PAGES);

	} else {
		ERRMSG("Can't get addr_free_pages.\n");
		return FALSE;
	}
	if (!readmem(VADDR, addr_free_pages, &free_pages, sizeof free_pages)) {
		ERRMSG("Can't get free_pages.\n");
		return FALSE;
	}
	if (free_pages != found_free_pages && !info->flag_cyclic) {
		/*
		 * On linux-2.6.21 or later, the number of free_pages is
		 * sometimes different from the one of the list "free_area",
		 * because the former is flushed asynchronously.
		 */
		DEBUG_MSG("The number of free_pages is invalid.\n");
		DEBUG_MSG("  free_pages       = %ld\n", free_pages);
		DEBUG_MSG("  found_free_pages = %ld\n", found_free_pages);
	}
	pfn_free += found_free_pages;

	return TRUE;
}


int
initial(void)
{
	off_t offset;
	unsigned long size;
	int debug_info = FALSE;

	// if (is_xen_memory() && !initial_xen())
	// 	return FALSE;

	/*
	 * Check whether /proc/vmcore contains vmcoreinfo,
	 * and get both the offset and the size.
	 */
	if (!has_vmcoreinfo()) {
		if (info->max_dump_level <= DL_EXCLUDE_ZERO)
			goto out;

		MSG("%s doesn't contain vmcoreinfo.\n",
				info->name_memory);
		MSG("Specify '-x' option or '-i' option.\n");
		MSG("Commandline parameter is invalid.\n");
		MSG("Try `makedumpfile --help' for more information.\n");
		return FALSE;
	}

	/*
	 * Get the debug information from /proc/vmcore.
	 * NOTE: Don't move this code to the above, because the debugging
	 *       information token by -x/-i option is overwritten by vmcoreinfo
	 *       in /proc/vmcore. vmcoreinfo in /proc/vmcore is more reliable
	 *       than -x/-i option.
	 */
	if (has_vmcoreinfo()) {
		get_vmcoreinfo(&offset, &size);
		if (!read_vmcoreinfo_from_vmcore(offset, size, FALSE))
			return FALSE;
		debug_info = TRUE;
	}

	if (!get_value_for_old_linux())
		return FALSE;

out:
	if (!info->page_size) {
		/*
		 * If we cannot get page_size from a vmcoreinfo file,
		 * fall back to the current kernel page size.
		 */
		if (!fallback_to_current_page_size())
			return FALSE;
	}

	if (!is_xen_memory() && !cache_init())
		return FALSE;

	if (!get_phys_base())
		return FALSE;

	if (!get_max_mapnr())
		return FALSE;

	unsigned long long free_memory;

	/*
	* The buffer size is specified as Kbyte with
	* --cyclic-buffer <size> option.
	*/
	info->bufsize_cyclic <<= 10;

	/*
	 * Truncate the buffer size to free memory size.
	 */
	free_memory = get_free_memory_size();
	if (info->num_dumpfile > 1)
		free_memory /= info->num_dumpfile;
	if (info->bufsize_cyclic > free_memory) {
		MSG("Specified buffer size is larger than free memory.\n");
		MSG("The buffer size for the cyclic mode will ");
		MSG("be truncated to %lld byte.\n", free_memory);
		info->bufsize_cyclic = free_memory;
	}

	info->pfn_cyclic = info->bufsize_cyclic * BITPERBYTE;

	DEBUG_MSG("\n");
	DEBUG_MSG("Buffer size for the cyclic mode: %ld\n", info->bufsize_cyclic);

	if (debug_info && !get_machdep_info())
		return FALSE;

	if (debug_info && !calibrate_machdep_info())
		return FALSE;

	if (debug_info) {
		if (!check_release())
			return FALSE;

		if (!get_versiondep_info())
			return FALSE;

		/*
		 * NOTE: This must be done before refering to
		 * VMALLOC'ed memory. The first 640kB contains data
		 * necessary for paging, like PTE. The absence of the
		 * region affects reading VMALLOC'ed memory such as
		 * module data.
		 */
		if (!get_numnodes())
			return FALSE;

		if (!get_mem_map())
			return FALSE;

	} else {
		/// XXX: Error
		exit(1);
	}

	/* use buddy identification of free pages whether cyclic or not */
	/* (this can reduce pages scan of 1TB memory from 60sec to 30sec) */
	if (info->dump_level & DL_EXCLUDE_FREE)
		setup_page_is_buddy();

	if (info->flag_usemmap == MMAP_TRY ) {
		if (initialize_mmap()) {
			DEBUG_MSG("mmap() is available on the kernel.\n");
			info->flag_usemmap = MMAP_ENABLE;
		} else {
			DEBUG_MSG("The kernel doesn't support mmap(),");
			DEBUG_MSG("read() will be used instead.\n");
			info->flag_usemmap = MMAP_DISABLE;
		}
        } else if (info->flag_usemmap == MMAP_DISABLE)
		DEBUG_MSG("mmap() is disabled by specified option '--non-mmap'.\n");

	return TRUE;
}

int
open_dump_bitmap(void)
{
	int i, fd;
	char *tmpname;

	/* Unnecessary to open */
	if (!info->working_dir && !info->flag_reassemble && !info->flag_refiltering
	    && info->flag_cyclic)
		return TRUE;

	tmpname = getenv("TMPDIR");
	if (info->working_dir)
		tmpname = info->working_dir;
	else if (!tmpname)
		tmpname = "/tmp";

	if ((info->name_bitmap = (char *)malloc(sizeof(FILENAME_BITMAP) +
						strlen(tmpname) + 1)) == NULL) {
		ERRMSG("Can't allocate memory for the filename. %s\n",
		    strerror(errno));
		return FALSE;
	}
	strcpy(info->name_bitmap, tmpname);
	strcat(info->name_bitmap, "/");
	strcat(info->name_bitmap, FILENAME_BITMAP);
	if ((fd = mkstemp(info->name_bitmap)) < 0) {
		ERRMSG("Can't open the bitmap file(%s). %s\n",
		    info->name_bitmap, strerror(errno));
		return FALSE;
	}
	info->fd_bitmap = fd;

	if (info->flag_split) {
		/*
		 * Reserve file descriptors of bitmap for creating split
		 * dumpfiles by multiple processes, because a bitmap file will
		 * be unlinked just after this and it is not possible to open
		 * a bitmap file later.
		 */
		for (i = 0; i < info->num_dumpfile; i++) {
			if ((fd = open(info->name_bitmap, O_RDONLY)) < 0) {
				ERRMSG("Can't open the bitmap file(%s). %s\n",
				    info->name_bitmap, strerror(errno));
				return FALSE;
			}
			SPLITTING_FD_BITMAP(i) = fd;
		}
	}

	if (info->num_threads) {
		/*
		 * Reserve file descriptors of bitmap for creating dumpfiles
		 * parallelly, because a bitmap file will be unlinked just after
		 * this and it is not possible to open a bitmap file later.
		 */
		for (i = 0; i < info->num_threads; i++) {
			if ((fd = open(info->name_bitmap, O_RDONLY)) < 0) {
				ERRMSG("Can't open the bitmap file(%s). %s\n",
				    info->name_bitmap, strerror(errno));
				return FALSE;
			}
			FD_BITMAP_PARALLEL(i) = fd;
		}
	}

	unlink(info->name_bitmap);

	return TRUE;
}

int
_exclude_free_page(struct cycle *cycle)
{
	int i, nr_zones, num_nodes, node;
	unsigned long node_zones, zone, spanned_pages, pgdat;
	struct timespec ts_start;

	if ((node = next_online_node(0)) < 0) {
		ERRMSG("Can't get next online node.\n");
		return FALSE;
	}
	if (!(pgdat = next_online_pgdat(node))) {
		ERRMSG("Can't get pgdat list.\n");
		return FALSE;
	}
	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	for (num_nodes = 1; num_nodes <= vt.numnodes; num_nodes++) {
		node_zones = pgdat + OFFSET(pglist_data.node_zones);

		if (!readmem(VADDR, pgdat + OFFSET(pglist_data.nr_zones),
		    &nr_zones, sizeof(nr_zones))) {
			ERRMSG("Can't get nr_zones.\n");
			return FALSE;
		}

		for (i = 0; i < nr_zones; i++) {
			zone = node_zones + (i * SIZE(zone));
			if (!readmem(VADDR, zone + OFFSET(zone.spanned_pages),
			    &spanned_pages, sizeof spanned_pages)) {
				ERRMSG("Can't get spanned_pages.\n");
				return FALSE;
			}
			if (!spanned_pages)
				continue;
			if (!reset_bitmap_of_free_pages(zone, cycle))
				return FALSE;
		}
		if (num_nodes < vt.numnodes) {
			if ((node = next_online_node(node + 1)) < 0) {
				ERRMSG("Can't get next online node.\n");
				return FALSE;
			} else if (!(pgdat = next_online_pgdat(node))) {
				ERRMSG("Can't determine pgdat list (node %d).\n",
				    node);
				return FALSE;
			}
		}
	}

	return TRUE;
}

int
exclude_free_page(struct cycle *cycle)
{
	/*
	 * Check having necessary information.
	 */
	if ((SYMBOL(node_data) == NOT_FOUND_SYMBOL)
	    && (SYMBOL(pgdat_list) == NOT_FOUND_SYMBOL)
	    && (SYMBOL(contig_page_data) == NOT_FOUND_SYMBOL)) {
		ERRMSG("Can't get necessary symbols for excluding free pages.\n");
		return FALSE;
	}
	if ((SIZE(zone) == NOT_FOUND_STRUCTURE)
	    || ((OFFSET(zone.free_pages) == NOT_FOUND_STRUCTURE)
	        && (OFFSET(zone.vm_stat) == NOT_FOUND_STRUCTURE))
	    || (OFFSET(zone.free_area) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(zone.spanned_pages) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(pglist_data.node_zones) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(pglist_data.nr_zones) == NOT_FOUND_STRUCTURE)
	    || (SIZE(free_area) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(free_area.free_list) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(list_head.next) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(list_head.prev) == NOT_FOUND_STRUCTURE)
	    || (OFFSET(page.lru) == NOT_FOUND_STRUCTURE)
	    || (ARRAY_LENGTH(zone.free_area) == NOT_FOUND_STRUCTURE)) {
		ERRMSG("Can't get necessary structures for excluding free pages.\n");
		return FALSE;
	}
	// if (is_xen_memory() && !info->dom0_mapnr) {
	// 	ERRMSG("Can't get max domain-0 PFN for excluding free pages.\n");
	// 	return FALSE;
	// }

	/*
	 * Detect free pages and update 2nd-bitmap.
	 */
	if (!_exclude_free_page(cycle))
		return FALSE;

	return TRUE;
}

/*
 * For the kernel versions from v2.6.17 to v2.6.37.
 */
static int
page_is_buddy_v2(unsigned long flags, unsigned int _mapcount,
			unsigned long private, unsigned int _count)
{
	if (flags & (1UL << NUMBER(PG_buddy)))
		return TRUE;

	return FALSE;
}

/*
 * For v2.6.38 and later kernel versions.
 */
static int
page_is_buddy_v3(unsigned long flags, unsigned int _mapcount,
			unsigned long private, unsigned int _count)
{
	if (flags & (1UL << NUMBER(PG_slab)))
		return FALSE;

	if (_mapcount == (int)NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE))
		return TRUE;

	return FALSE;
}

static void
setup_page_is_buddy(void)
{
	if (OFFSET(page.private) == NOT_FOUND_STRUCTURE)
		goto out;

	if (NUMBER(PG_buddy) == NOT_FOUND_NUMBER) {
		if (NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE) != NOT_FOUND_NUMBER) {
			if (OFFSET(page._mapcount) != NOT_FOUND_STRUCTURE)
				info->page_is_buddy = page_is_buddy_v3;
		}
	} else
		info->page_is_buddy = page_is_buddy_v2;

out:
	if (!info->page_is_buddy)
		DEBUG_MSG("Can't select page_is_buddy handler; "
			  "follow free lists instead of mem_map array.\n");
}

static mdf_pfn_t count_bits(char *buf, int sz)
{
	char *p = buf;
	int i, j;
	mdf_pfn_t cnt = 0;

	for (i = 0; i < sz; i++, p++) {
		if (*p == 0)
			continue;
		else if (*p == 0xff) {
			cnt += 8;
			continue;
		}
		for (j = 0; j < 8; j++) {
			if (*p & (1<<j))
				cnt++;
		}
	}
	return cnt;
}

int
create_1st_bitmap_file(void)
{
	int i;
	unsigned int num_pt_loads = get_num_pt_loads();
 	char buf[info->page_size];
	mdf_pfn_t pfn, pfn_start, pfn_end, pfn_bitmap1;
	unsigned long long phys_start, phys_end;
	struct timespec ts_start;
	off_t offset_page;

	/*
	 * At first, clear all the bits on the 1st-bitmap.
	 */
	memset(buf, 0, sizeof(buf));

	if (lseek(info->bitmap1->fd, info->bitmap1->offset, SEEK_SET) < 0) {
		ERRMSG("Can't seek the bitmap(%s). %s\n",
		    info->bitmap1->file_name, strerror(errno));
		return FALSE;
	}
	offset_page = 0;
	while (offset_page < (info->len_bitmap / 2)) {
		if (write(info->bitmap1->fd, buf, info->page_size)
		    != info->page_size) {
			ERRMSG("Can't write the bitmap(%s). %s\n",
			    info->bitmap1->file_name, strerror(errno));
			return FALSE;
		}
		offset_page += info->page_size;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	/*
	 * If page is on memory hole, set bit on the 1st-bitmap.
	 */
	pfn_bitmap1 = 0;
	for (i = 0; get_pt_load(i, &phys_start, &phys_end, NULL, NULL); i++) {
		pfn_start = paddr_to_pfn(phys_start);
		pfn_end   = paddr_to_pfn(phys_end);
		if (pfn_start > info->max_mapnr)
			continue;
		pfn_end = MIN(pfn_end, info->max_mapnr);
		/* Account for last page if it has less than page_size data in it */
		if (phys_end & (info->page_size - 1))
			++pfn_end;

		for (pfn = pfn_start; pfn < pfn_end; pfn++) {
			set_bit_on_1st_bitmap(pfn, NULL);
			pfn_bitmap1++;
		}
	}
	pfn_memhole = info->max_mapnr - pfn_bitmap1;

	if (!sync_1st_bitmap())
		return FALSE;

	return TRUE;
}

int
create_bitmap_from_memhole(struct cycle *cycle, struct dump_bitmap *bitmap, int count_memhole,
			   int (*set_bit)(mdf_pfn_t pfn, struct cycle *cycle));

int
create_1st_bitmap_buffer(struct cycle *cycle)
{
	return create_bitmap_from_memhole(cycle, info->bitmap1, TRUE,
					  set_bit_on_1st_bitmap);
}

int
create_1st_bitmap(struct cycle *cycle)
{
	if (info->bitmap1->fd >= 0) {
		return create_1st_bitmap_file();
	} else {
		return create_1st_bitmap_buffer(cycle);
	}
}

static inline int
is_in_segs(unsigned long long paddr)
{
	if (paddr_to_offset(paddr))
		return TRUE;
	else
		return FALSE;
}

/*
 * Exclude the page filled with zero in case of creating an elf dumpfile.
 */
int
exclude_zero_pages_cyclic(struct cycle *cycle)
{
	mdf_pfn_t pfn;
	unsigned long long paddr;
	unsigned char buf[info->page_size];

	for (pfn = cycle->start_pfn, paddr = pfn_to_paddr(pfn); pfn < cycle->end_pfn;
	    pfn++, paddr += info->page_size) {

		if (!is_in_segs(paddr))
			continue;

		if (!sync_2nd_bitmap())
			return FALSE;

		if (!is_dumpable(info->bitmap2, pfn, cycle))
			continue;

		if (!readmem(PADDR, paddr, buf, info->page_size)) {
			ERRMSG("Can't get the page data(pfn:%llx, max_mapnr:%llx).\n",
			    pfn, info->max_mapnr);
			return FALSE;
		}
		if (is_zero_page(buf, info->page_size)) {
			if (clear_bit_on_2nd_bitmap(pfn, cycle))
				pfn_zero++;
		}
	}

	return TRUE;
}

int
initialize_2nd_bitmap_cyclic(struct cycle *cycle)
{
	return create_bitmap_from_memhole(cycle, info->bitmap2, FALSE,
					  set_bit_on_2nd_bitmap_for_kernel);
}

int
create_bitmap_from_memhole(struct cycle *cycle, struct dump_bitmap *bitmap, int count_memhole,
			   int (*set_bit)(mdf_pfn_t pfn, struct cycle *cycle))
{
	int i;
	mdf_pfn_t pfn;
	unsigned long long phys_start, phys_end;
	mdf_pfn_t pfn_start, pfn_end;
	mdf_pfn_t pfn_start_roundup, pfn_end_round;
	unsigned long pfn_start_byte, pfn_end_byte;
	unsigned int num_pt_loads = get_num_pt_loads();
	struct timespec ts_start;

	/*
	 * At first, clear all the bits on the bitmap.
	 */
	initialize_bitmap(bitmap);

	/*
	 * If page is on memory hole, set bit on the bitmap.
	 */
	clock_gettime(CLOCK_MONOTONIC, &ts_start);
	for (i = 0; get_pt_load(i, &phys_start, &phys_end, NULL, NULL); i++) {
		pfn_start = MAX(paddr_to_pfn(phys_start), cycle->start_pfn);
		pfn_end = MIN(paddr_to_pfn(phys_end), cycle->end_pfn);

		if (pfn_start >= pfn_end)
			continue;

		pfn_start_roundup = MIN(roundup(pfn_start, BITPERBYTE),
					pfn_end);
		pfn_end_round = MAX(round(pfn_end, BITPERBYTE), pfn_start);

		for (pfn = pfn_start; pfn < pfn_start_roundup; ++pfn) {
			if (!set_bit(pfn, cycle))
				return FALSE;
			if (count_memhole)
				pfn_memhole--;
		}

		pfn_start_byte = (pfn_start_roundup - cycle->start_pfn) >> 3;
		pfn_end_byte = (pfn_end_round - cycle->start_pfn) >> 3;

		if (pfn_start_byte < pfn_end_byte) {
			memset(bitmap->buf + pfn_start_byte,
			       0xff,
			       pfn_end_byte - pfn_start_byte);
			if (count_memhole)
				pfn_memhole -= (pfn_end_byte - pfn_start_byte) << 3;
		}

		if (pfn_end_round >= pfn_start) {
			for (pfn = pfn_end_round; pfn < pfn_end; ++pfn) {
				if (!set_bit(pfn, cycle))
					return FALSE;
				if (count_memhole)
					pfn_memhole--;
			}
		}
	}
	return TRUE;
}

static void
exclude_range(mdf_pfn_t *counter, mdf_pfn_t pfn, mdf_pfn_t endpfn,
	      struct cycle *cycle)
{
	if (cycle) {
		cycle->exclude_pfn_start = cycle->end_pfn;
		cycle->exclude_pfn_end = endpfn;
		cycle->exclude_pfn_counter = counter;

		if (cycle->end_pfn < endpfn)
			endpfn = cycle->end_pfn;
	}

	while (pfn < endpfn) {
		if (clear_bit_on_2nd_bitmap_for_kernel(pfn, cycle))
			(*counter)++;
		++pfn;
	}
}

int
__exclude_unnecessary_pages(unsigned long mem_map,
    mdf_pfn_t pfn_start, mdf_pfn_t pfn_end, struct cycle *cycle)
{
	mdf_pfn_t pfn;
	mdf_pfn_t *pfn_counter;
	mdf_pfn_t nr_pages;
	unsigned long index_pg, pfn_mm;
	unsigned long long maddr;
	mdf_pfn_t pfn_read_start, pfn_read_end;
	unsigned char page_cache[SIZE(page) * PGMM_CACHED];
	unsigned char *pcache;
	unsigned int _count, _mapcount = 0, compound_order = 0;
	unsigned int order_offset, dtor_offset;
	unsigned long flags, mapping, private = 0;
	unsigned long compound_dtor, compound_head = 0;

	/*
	 * If a multi-page exclusion is pending, do it first
	 */
	if (cycle && cycle->exclude_pfn_start < cycle->exclude_pfn_end) {
		exclude_range(cycle->exclude_pfn_counter,
			cycle->exclude_pfn_start, cycle->exclude_pfn_end,
			cycle);

		mem_map += (cycle->exclude_pfn_end - pfn_start) * SIZE(page);
		pfn_start = cycle->exclude_pfn_end;
	}

	/*
	 * Refresh the buffer of struct page, when changing mem_map.
	 */
	pfn_read_start = ULONGLONG_MAX;
	pfn_read_end   = 0;

	for (pfn = pfn_start; pfn < pfn_end; pfn++, mem_map += SIZE(page)) {

		/*
		 * If this pfn doesn't belong to target region, skip this pfn.
		 */
		if (info->flag_cyclic && !is_cyclic_region(pfn, cycle))
			continue;

		/*
		 * Exclude the memory hole.
		 */
		// if (is_xen_memory()) {
		// 	maddr = ptom_xen(pfn_to_paddr(pfn));
		// 	if (maddr == NOT_PADDR) {
		// 		ERRMSG("Can't convert a physical address(%llx) to machine address.\n",
		// 		    pfn_to_paddr(pfn));
		// 		return FALSE;
		// 	}
		// 	if (!is_in_segs(maddr))
		// 		continue;
		// } else {
			if (!is_in_segs(pfn_to_paddr(pfn)))
				continue;
		// }

		index_pg = pfn % PGMM_CACHED;
		if (pfn < pfn_read_start || pfn_read_end < pfn) {
			if (roundup(pfn + 1, PGMM_CACHED) < pfn_end)
				pfn_mm = PGMM_CACHED - index_pg;
			else
				pfn_mm = pfn_end - pfn;

			if (!readmem(VADDR, mem_map,
			    page_cache + (index_pg * SIZE(page)),
			    SIZE(page) * pfn_mm)) {
				ERRMSG("Can't read the buffer of struct page.\n");
				return FALSE;
			}
			pfn_read_start = pfn;
			pfn_read_end   = pfn + pfn_mm - 1;
		}
		pcache  = page_cache + (index_pg * SIZE(page));

		flags   = ULONG(pcache + OFFSET(page.flags));
		_count  = UINT(pcache + OFFSET(page._refcount));
		mapping = ULONG(pcache + OFFSET(page.mapping));

		if (OFFSET(page.compound_order) != NOT_FOUND_STRUCTURE) {
			order_offset = OFFSET(page.compound_order);
		} else {
			if (info->kernel_version < KERNEL_VERSION(4, 4, 0))
				order_offset = OFFSET(page.lru) + OFFSET(list_head.prev);
			else
				order_offset = 0;
		}

		if (OFFSET(page.compound_dtor) != NOT_FOUND_STRUCTURE) {
			dtor_offset = OFFSET(page.compound_dtor);
		} else {
			if (info->kernel_version < KERNEL_VERSION(4, 4, 0))
				dtor_offset = OFFSET(page.lru) + OFFSET(list_head.next);
			else
				dtor_offset = 0;
		}

		compound_order = 0;
		compound_dtor = 0;
		/*
		 * The last pfn of the mem_map cache must not be compound head
		 * page since all compound pages are aligned to its page order
		 * and PGMM_CACHED is a power of 2.
		 */
		if ((index_pg < PGMM_CACHED - 1) && isCompoundHead(flags)) {
			unsigned char *addr = pcache + SIZE(page);

			if (order_offset) {
				if (info->kernel_version >=
				    KERNEL_VERSION(4, 16, 0)) {
					compound_order =
						UCHAR(addr + order_offset);
				} else {
					compound_order =
						USHORT(addr + order_offset);
				}
			}

			if (dtor_offset) {
				/*
				 * compound_dtor has been changed from the address of descriptor
				 * to the ID of it since linux-4.4.
				 */
				if (info->kernel_version >=
				    KERNEL_VERSION(4, 16, 0)) {
					compound_dtor =
						UCHAR(addr + dtor_offset);
				} else if (info->kernel_version >=
					   KERNEL_VERSION(4, 4, 0)) {
					compound_dtor =
						USHORT(addr + dtor_offset);
				} else {
					compound_dtor =
						ULONG(addr + dtor_offset);
				}
			}

			if ((compound_order >= sizeof(unsigned long) * 8)
			    || ((pfn & ((1UL << compound_order) - 1)) != 0)) {
				/* Invalid order */
				compound_order = 0;
			}
		}
		if (OFFSET(page.compound_head) != NOT_FOUND_STRUCTURE)
			compound_head = ULONG(pcache + OFFSET(page.compound_head));

		if (OFFSET(page._mapcount) != NOT_FOUND_STRUCTURE)
			_mapcount = UINT(pcache + OFFSET(page._mapcount));
		if (OFFSET(page.private) != NOT_FOUND_STRUCTURE)
			private = ULONG(pcache + OFFSET(page.private));

		nr_pages = 1 << compound_order;
		pfn_counter = NULL;

		/*
		 * Excludable compound tail pages must have already been excluded by
		 * exclude_range(), don't need to check them here.
		 */
		if (compound_head & 1) {
			continue;
		}
		/*
		 * Exclude the free page managed by a buddy
		 * Use buddy identification of free pages whether cyclic or not.
		 */
		else if ((info->dump_level & DL_EXCLUDE_FREE)
		    && info->page_is_buddy
		    && info->page_is_buddy(flags, _mapcount, private, _count)) {
			nr_pages = 1 << private;
			pfn_counter = &pfn_free;
		}
		/*
		 * Exclude the non-private cache page.
		 */
		else if ((info->dump_level & DL_EXCLUDE_CACHE)
		    && is_cache_page(flags)
		    && !isPrivate(flags) && !isAnon(mapping)) {
			pfn_counter = &pfn_cache;
		}
		/*
		 * Exclude the cache page whether private or non-private.
		 */
		else if ((info->dump_level & DL_EXCLUDE_CACHE_PRI)
		    && is_cache_page(flags)
		    && !isAnon(mapping)) {
			if (isPrivate(flags))
				pfn_counter = &pfn_cache_private;
			else
				pfn_counter = &pfn_cache;
		}
		/*
		 * Exclude the data page of the user process.
		 *  - anonymous pages
		 *  - hugetlbfs pages
		 */
		else if ((info->dump_level & DL_EXCLUDE_USER_DATA)
			 && (isAnon(mapping) || isHugetlb(compound_dtor))) {
			pfn_counter = &pfn_user;
		}
		/*
		 * Exclude the hwpoison page.
		 */
		else if (isHWPOISON(flags) && !info->flag_mem_reuse) {
			pfn_counter = &pfn_hwpoison;
		}
		/*
		 * Exclude pages that are logically offline.
		 */
		else if (isOffline(flags, _mapcount) && !info->flag_mem_reuse) {
			pfn_counter = &pfn_offline;
		}
		/*
		 * Unexcludable page
		 */
		else
			continue;

		/*
		 * Execute exclusion
		 */
		if (nr_pages == 1) {
			if (clear_bit_on_2nd_bitmap_for_kernel(pfn, cycle))
				(*pfn_counter)++;
		} else {
			exclude_range(pfn_counter, pfn, pfn + nr_pages, cycle);
			pfn += nr_pages - 1;
			mem_map += (nr_pages - 1) * SIZE(page);
		}
	}
	return TRUE;
}

int
exclude_unnecessary_pages(struct cycle *cycle)
{
	unsigned int mm;
	struct mem_map_data *mmd;
	struct timespec ts_start;

	// if (is_xen_memory() && !info->dom0_mapnr) {
	// 	ERRMSG("Can't get max domain-0 PFN for excluding pages.\n");
	// 	return FALSE;
	// }

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	for (mm = 0; mm < info->num_mem_map; mm++) {
		mmd = &info->mem_map_data[mm];

		if (mmd->mem_map == NOT_MEMMAP_ADDR)
			continue;

		if (mmd->pfn_end >= cycle->start_pfn &&
		    mmd->pfn_start <= cycle->end_pfn) {
			if (!__exclude_unnecessary_pages(mmd->mem_map,
							 mmd->pfn_start, mmd->pfn_end, cycle))
				return FALSE;
		}
	}

	return TRUE;
}

int
copy_bitmap_buffer(void)
{
	memcpy(info->bitmap2->buf, info->bitmap1->buf,
	       info->bufsize_cyclic);
	return TRUE;
}

int
copy_bitmap_file(void)
{
	off_t base, offset = 0;
	unsigned char buf[info->page_size];
 	const off_t failed = (off_t)-1;
	int fd;
	fd = info->bitmap1->fd;
	base = info->bitmap1->offset;

	while (offset < (info->len_bitmap / 2)) {
		if (lseek(fd, base + offset, SEEK_SET) == failed) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
			    info->name_bitmap, strerror(errno));
			return FALSE;
		}
		if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
			ERRMSG("Can't read the dump memory(%s). %s\n",
			    info->name_memory, strerror(errno));
			return FALSE;
		}
		if (lseek(info->bitmap2->fd, info->bitmap2->offset + offset,
		    SEEK_SET) == failed) {
			ERRMSG("Can't seek the bitmap(%s). %s\n",
			    info->name_bitmap, strerror(errno));
			return FALSE;
		}
		if (write(info->bitmap2->fd, buf, sizeof(buf)) != sizeof(buf)) {
			ERRMSG("Can't write the bitmap(%s). %s\n",
		    	info->name_bitmap, strerror(errno));
			return FALSE;
		}
		offset += sizeof(buf);
	}

	return TRUE;
}

int
copy_bitmap(void)
{
	if (info->fd_bitmap >= 0) {
		return copy_bitmap_file();
	} else {
		return copy_bitmap_buffer();
	}
}

static void
exclude_nodata_pages(struct cycle *cycle)
{
	int i;
	unsigned long long phys_start, phys_end;
	off_t file_size;

	i = 0;
	while (get_pt_load_extents(i, &phys_start, &phys_end,
				   NULL, &file_size)) {
		unsigned long long pfn, pfn_end;

		pfn = paddr_to_pfn(phys_start + file_size);
		pfn_end = paddr_to_pfn(roundup(phys_end, PAGESIZE()));

		if (pfn < cycle->start_pfn)
			pfn = cycle->start_pfn;
		if (pfn_end >= cycle->end_pfn)
			pfn_end = cycle->end_pfn;
		while (pfn < pfn_end) {
			clear_bit_on_2nd_bitmap(pfn, cycle);
			++pfn;
		}
		++i;
	}
}

int
create_2nd_bitmap(struct cycle *cycle)
{
	/*
	 * At first, clear all the bits on memory hole.
	 */
	if (info->flag_cyclic) {
		/* Have to do it from scratch. */
		initialize_2nd_bitmap_cyclic(cycle);
	} else {
		/* Can copy 1st-bitmap to 2nd-bitmap. */
		if (!copy_bitmap()) {
			ERRMSG("Can't copy 1st-bitmap to 2nd-bitmap.\n");
			return FALSE;
		}
	}

	/*
	 * If re-filtering ELF dump, exclude pages that were already
	 * excluded in the original file.
	 */
	exclude_nodata_pages(cycle);

	/*
	 * Exclude cache pages, cache private pages, user data pages,
	 * and hwpoison pages.
	 */
	if (info->dump_level & DL_EXCLUDE_CACHE ||
	    info->dump_level & DL_EXCLUDE_CACHE_PRI ||
	    info->dump_level & DL_EXCLUDE_USER_DATA ||
	    NUMBER(PG_hwpoison) != NOT_FOUND_NUMBER ||
	    ((info->dump_level & DL_EXCLUDE_FREE) && info->page_is_buddy)) {
		if (!exclude_unnecessary_pages(cycle)) {
			ERRMSG("Can't exclude unnecessary pages.\n");
			return FALSE;
		}
	}

	/*
	 * Exclude free pages.
	 */
	if ((info->dump_level & DL_EXCLUDE_FREE) && !info->page_is_buddy)
		if (!exclude_free_page(cycle))
			return FALSE;

	// /*
	//  * Exclude Xen user domain.
	//  */
	// if (info->flag_exclude_xen_dom && !info->flag_mem_reuse) {
	// 	if (!exclude_xen_user_domain()) {
	// 		ERRMSG("Can't exclude xen user domain.\n");
	// 		return FALSE;
	// 	}
	// }

	/*
	 * Exclude pages filled with zero for creating an ELF dumpfile.
	 *
	 * Note: If creating a kdump-compressed dumpfile, makedumpfile
	 *	 checks zero-pages while copying dumpable pages to a
	 *	 dumpfile from /proc/vmcore. That is valuable for the
	 *	 speed, because each page is read one time only.
	 *	 Otherwise (if creating an ELF dumpfile), makedumpfile
	 *	 should check zero-pages at this time because 2nd-bitmap
	 *	 should be fixed for creating an ELF header. That is slow
	 *	 due to reading each page two times, but it is necessary.
	 */
	if ((info->dump_level & DL_EXCLUDE_ZERO) &&
	    (info->flag_elf_dumpfile || info->flag_mem_usage) && !info->flag_mem_reuse) {
		/*
		 * 2nd-bitmap should be flushed at this time, because
		 * exclude_zero_pages() checks 2nd-bitmap.
		 */
		if (!sync_2nd_bitmap())
			return FALSE;

		if (!exclude_zero_pages_cyclic(cycle)) {
			ERRMSG("Can't exclude pages filled with zero for creating an ELF dumpfile.\n");
			return FALSE;
		}
	}

	if (!sync_2nd_bitmap())
		return FALSE;

	return TRUE;
}

int
prepare_bitmap1_buffer(void)
{
	/*
	 * Prepare bitmap buffers for cyclic processing.
	 */
	if ((info->bitmap1 = malloc(sizeof(struct dump_bitmap))) == NULL) {
		ERRMSG("Can't allocate memory for the 1st bitmaps. %s\n",
		       strerror(errno));
		return FALSE;
	}

	if (info->fd_bitmap >= 0) {
		if ((info->bitmap1->buf = (char *)malloc(BUFSIZE_BITMAP)) == NULL) {
			ERRMSG("Can't allocate memory for the 1st bitmaps's buffer. %s\n",
			       strerror(errno));
			return FALSE;
		}
	} else {
		if ((info->bitmap1->buf = (char *)malloc(info->bufsize_cyclic)) == NULL) {
			ERRMSG("Can't allocate memory for the 1st bitmaps's buffer. %s\n",
			       strerror(errno));
			return FALSE;
		}
	}
	initialize_1st_bitmap(info->bitmap1);

	return TRUE;
}

int
prepare_bitmap2_buffer(void)
{
	unsigned long tmp;

	/*
	 * Create 2 bitmaps (1st-bitmap & 2nd-bitmap) on block_size
	 * boundary. The crash utility requires both of them to be
	 * aligned to block_size boundary.
	 */
	tmp = divideup(divideup(info->max_mapnr, BITPERBYTE), info->page_size);
	info->len_bitmap = tmp * info->page_size * 2;

	/*
	 * Prepare bitmap buffers for cyclic processing.
	 */
	if ((info->bitmap2 = malloc(sizeof(struct dump_bitmap))) == NULL) {
		ERRMSG("Can't allocate memory for the 2nd bitmaps. %s\n",
		       strerror(errno));
		return FALSE;
	}
	if (info->fd_bitmap >= 0) {
		if ((info->bitmap2->buf = (char *)malloc(BUFSIZE_BITMAP)) == NULL) {
			ERRMSG("Can't allocate memory for the 2nd bitmaps's buffer. %s\n",
			       strerror(errno));
			return FALSE;
		}
	} else {
		if ((info->bitmap2->buf = (char *)malloc(info->bufsize_cyclic)) == NULL) {
			ERRMSG("Can't allocate memory for the 2nd bitmaps's buffer. %s\n",
			       strerror(errno));
			return FALSE;
		}
	}
	initialize_2nd_bitmap(info->bitmap2);

	return TRUE;
}

int
prepare_bitmap_buffer(void)
{
	/*
	 * Prepare bitmap buffers for creating dump bitmap.
	 */
	prepare_bitmap1_buffer();
	prepare_bitmap2_buffer();

	return TRUE;
}

void
free_bitmap1_buffer(void)
{
	if (info->bitmap1) {
		if (info->bitmap1->buf) {
			free(info->bitmap1->buf);
			info->bitmap1->buf = NULL;
		}
		free(info->bitmap1);
		info->bitmap1 = NULL;
	}
}

void
free_bitmap2_buffer(void)
{
	if (info->bitmap2) {
		if (info->bitmap2->buf) {
			free(info->bitmap2->buf);
			info->bitmap2->buf = NULL;
		}
		free(info->bitmap2);
		info->bitmap2 = NULL;
	}
}

void
free_bitmap_buffer(void)
{
	free_bitmap1_buffer();
	free_bitmap2_buffer();
}

int
prepare_cache_data(struct cache_data *cd)
{
	cd->fd         = info->fd_dumpfile;
	cd->file_name  = info->name_dumpfile;
	cd->cache_size = info->page_size << info->block_order;
	cd->buf_size   = 0;
	cd->buf        = NULL;

	if ((cd->buf = malloc(cd->cache_size + info->page_size)) == NULL) {
		ERRMSG("Can't allocate memory for the data buffer. %s\n",
		    strerror(errno));
		return FALSE;
	}
	return TRUE;
}

void
free_cache_data(struct cache_data *cd)
{
	free(cd->buf);
	cd->buf = NULL;
}

void
print_reusable_cyclic_single(int count)
{
	mdf_pfn_t pfn, pfn_start = 0,  pfn_end = 0, swap;
	struct cycle cycle = {0};

	struct {
		mdf_pfn_t pfn_start;
		mdf_pfn_t pfn_end;
	} reusable_area [count];
	memset(reusable_area, 0, sizeof(reusable_area));

	for_each_cycle(0, info->max_mapnr, &cycle) {
		if (info->flag_cyclic) {
			if (!create_2nd_bitmap(&cycle)) {
				ERRMSG("Failed to create bitmap.\n");
			}
		}

		for (pfn = cycle.start_pfn; pfn < cycle.end_pfn; pfn++) {
			if (is_dumpable(info->bitmap1, pfn, &cycle)) {
				/* Ensure it's not on a memory hole */
				if (!is_dumpable(info->bitmap2, pfn, &cycle)) {
					/* Usable region */
					if (pfn_end == pfn - 1) {
						pfn_end ++;
						continue;
					}
				}
			}

			/* End of a continues reusable region */
			pfn_end = round(pfn_end + 1, info->mem_reuse_align);
			pfn_start = roundup(pfn_start, info->mem_reuse_align);

			if (pfn_end > pfn_start) {
				for (int i = 0; i < count; ++i) {
					if (reusable_area[i].pfn_end - reusable_area[i].pfn_start < pfn_end - pfn_start) {
						swap = reusable_area[i].pfn_end;
						reusable_area[i].pfn_end = pfn_end;
						pfn_end = swap;

						swap = reusable_area[i].pfn_start;
						reusable_area[i].pfn_start = pfn_start;
						pfn_start = swap;
					}
				}
			}

			pfn_start = pfn_end = pfn;
		}
	}

	MSG("Reuseable memory range:\n");
	for (int i = 0; i < count; ++i) {
		if (reusable_area[i].pfn_end - reusable_area[i].pfn_start == 0) {
			if (i == 0)
				MSG("- No reuseable memory area found. -\n");
			break;
		}

		MSG("0x%llx - 0x%llx (%llx)\n",
				pfn_to_paddr(reusable_area[i].pfn_start),
				pfn_to_paddr(reusable_area[i].pfn_end),
				paddr_to_offset(pfn_to_paddr(reusable_area[i].pfn_start)));

	}
}


int show_mem(void)
{
	uint64_t vmcoreinfo_addr, vmcoreinfo_len;
	struct cycle cycle = {0};

	// Assuming kernel > 5.8.0
	info->kernel_version = KERNEL_VERSION(5, 8, 0);

	info->dump_level = MAX_DUMP_LEVEL;

	if (!open_dump_memory("/proc/kcore"))
		return FALSE;

	if (!get_elf_loads(info->fd_memory, info->name_memory))
		return FALSE;

	// if (!get_page_offset())
	// 	return FALSE;
	info->section_size_bits = _SECTION_SIZE_BITS;

	/* paddr_to_vaddr() on arm64 needs phys_base. */
	if (!get_phys_base())
		return FALSE;

	if (has_pt_note())
		get_pt_note_info();

	if (!get_dump_loads())
		return FALSE;

	if (!initial())
		return FALSE;

	if (!open_dump_bitmap())
		return FALSE;

	if (!prepare_bitmap_buffer())
		return FALSE;

	pfn_memhole = info->max_mapnr;
	first_cycle(0, info->max_mapnr, &cycle);
	if (!create_1st_bitmap(&cycle))
		return FALSE;
	if (!create_2nd_bitmap(&cycle))
		return FALSE;

	print_reusable_cyclic_single(10);

	free_bitmap_buffer();

	if (!close_files_for_creating_dumpfile())
		return FALSE;

	return TRUE;
}

void
close_dump_memory(void)
{
	if (close(info->fd_memory) < 0)
		ERRMSG("Can't close the dump memory(%s). %s\n",
		    info->name_memory, strerror(errno));
	info->fd_memory = -1;
}

void
close_dump_file(void)
{
	if (info->flag_flatten)
		return;

	if (close(info->fd_dumpfile) < 0)
		ERRMSG("Can't close the dump file(%s). %s\n",
		    info->name_dumpfile, strerror(errno));
	info->fd_dumpfile = -1;
}

void
close_dump_bitmap(void)
{
	if (info->fd_bitmap < 0)
		return;

	if (close(info->fd_bitmap) < 0)
		ERRMSG("Can't close the bitmap file(%s). %s\n",
		    info->name_bitmap, strerror(errno));
	info->fd_bitmap = -1;
	free(info->name_bitmap);
	info->name_bitmap = NULL;
}

void
close_kernel_file(void)
{
	if (info->name_vmlinux) {
		if (close(info->fd_vmlinux) < 0) {
			ERRMSG("Can't close the kernel file(%s). %s\n",
			    info->name_vmlinux, strerror(errno));
		}
		info->fd_vmlinux = -1;
	}
	if (info->name_xen_syms) {
		if (close(info->fd_xen_syms) < 0) {
			ERRMSG("Can't close the kernel file(%s). %s\n",
			    info->name_xen_syms, strerror(errno));
		}
		info->fd_xen_syms = -1;
	}
}

int
close_files_for_creating_dumpfile(void)
{
	if (info->max_dump_level > DL_EXCLUDE_ZERO)
		close_kernel_file();

	/* free name for vmcoreinfo */
	if (has_vmcoreinfo()) {
		free(info->name_vmcoreinfo);
		info->name_vmcoreinfo = NULL;
	}
	close_dump_memory();

	close_dump_bitmap();

	return TRUE;
}

int
mkdump_file_main()
{
	if ((info = calloc(1, sizeof(struct DumpInfo))) == NULL) {
		ERRMSG("Can't allocate memory for the pagedesc cache. %s.\n",
		    strerror(errno));
		goto out;
	}
	info->file_vmcoreinfo = NULL;
	info->fd_vmlinux = -1;
	info->fd_xen_syms = -1;
	info->fd_memory = -1;
	info->fd_dumpfile = -1;
	info->fd_bitmap = -1;
	info->kaslr_offset = 0;
	initialize_tables();

	/*
	 * By default, makedumpfile assumes that multi-cycle processing is
	 * necessary to work in constant memory space.
	 */
	info->flag_cyclic = TRUE;

	/*
	 * By default, makedumpfile try to use mmap(2) to read /proc/vmcore.
	 */
	info->flag_usemmap = MMAP_TRY;

	info->block_order = DEFAULT_ORDER;

	parse_dump_level("31");
	info->flag_mem_reuse = 1;
	info->mem_reuse_align = 512;
	info->bufsize_cyclic = 1024;

	// XXX: No kernel version check
	if (!show_mem())
			goto out;

	retcd = COMPLETED;
out:
	if (!info->flag_check_params) {
		MSG("\n");
		if (retcd != COMPLETED)
			MSG("makedumpfile Failed.\n");
		else if (!info->flag_mem_usage)
			MSG("makedumpfile Completed.\n");
	}

	if (info) {
		if (info->valid_pages)
			free(info->valid_pages);
		if (info->bitmap_memory) {
			if (info->bitmap_memory->buf)
				free(info->bitmap_memory->buf);
			free(info->bitmap_memory);
		}
		if (info->fd_memory >= 0)
			close(info->fd_memory);
		if (info->fd_dumpfile >= 0)
			close(info->fd_dumpfile);
		if (info->fd_bitmap >= 0)
			close(info->fd_bitmap);
		if (vt.node_online_map != NULL)
			free(vt.node_online_map);
		if (info->mem_map_data != NULL)
			free(info->mem_map_data);
		if (info->splitting_info != NULL)
			free(info->splitting_info);
		if (info->p2m_mfn_frame_list != NULL)
			free(info->p2m_mfn_frame_list);
		if (info->page_buf != NULL)
			free(info->page_buf);
		if (info->parallel_info != NULL)
			free(info->parallel_info);
		free(info);
	}

	free_elf_info();

	return retcd;
}
