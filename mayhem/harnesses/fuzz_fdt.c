/* Fuzz libfdt (scripts/dtc/libfdt, used by the kernel and dtc) on untrusted device tree blobs:
 * validate the header, walk read-only, then edit a copy through the read-write API. */
#include <libfdt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void walk(const void *fdt)
{
	int off, depth = 0, len, n;

	for (n = fdt_num_mem_rsv(fdt); n > 0; n--) {
		uint64_t a, s;
		(void)fdt_get_mem_rsv(fdt, n - 1, &a, &s);
	}

	for (off = fdt_next_node(fdt, -1, &depth); off >= 0 && depth >= 0;
	     off = fdt_next_node(fdt, off, &depth)) {
		char path[256];
		int prop, plen;
		const char *name = fdt_get_name(fdt, off, &len);

		if (name)
			(void)strlen(name);
		(void)fdt_get_path(fdt, off, path, sizeof(path));
		(void)fdt_get_phandle(fdt, off);
		(void)fdt_node_check_compatible(fdt, off, "simple-bus");
		(void)fdt_stringlist_count(fdt, off, "compatible");
		(void)fdt_address_cells(fdt, off);
		(void)fdt_size_cells(fdt, off);

		for (prop = fdt_first_property_offset(fdt, off); prop >= 0;
		     prop = fdt_next_property_offset(fdt, prop)) {
			const char *pname;
			const void *p = fdt_getprop_by_offset(fdt, prop, &pname, &plen);
			const struct fdt_property *fp = fdt_get_property_by_offset(fdt, prop, &plen);

			if (p && pname) {
				const unsigned char *b = p;
				volatile unsigned char sink = plen ? b[plen - 1] : 0;
				(void)sink;
				(void)strlen(pname);
			}
			(void)fp;
		}
	}

	(void)fdt_path_offset(fdt, "/chosen");
	(void)fdt_path_offset(fdt, "/soc/serial@0");
	(void)fdt_node_offset_by_phandle(fdt, 1);
	(void)fdt_node_offset_by_compatible(fdt, -1, "arm,pl011");
	(void)fdt_subnode_offset(fdt, 0, "cpus");
}

/* libfdt only promises memory-safe reads on a blob that passed fdt_check_full() (libfdt.h:337; the
 * function lives in upstream dtc's fdt_check.c, which this tree does not ship, so it is reproduced
 * here step for step). fdt_check_header() alone does not check the memory-reserve terminator, that
 * the structure block is a balanced node/property sequence, or the 8/4-byte alignment the DT spec
 * (section 5.2) requires of off_mem_rsvmap/off_dt_struct (libfdt then makes misaligned loads). */
static int check_full(const void *fdt, size_t bufsize)
{
	int err, offset, nextoffset = 0;
	uint32_t tag;
	unsigned int depth = 0;
	const void *prop;
	const char *propname;
	int expect_end = 0;

	if (bufsize < FDT_V17_SIZE)
		return -FDT_ERR_TRUNCATED;
	err = fdt_check_header(fdt);
	if (err)
		return err;
	if (fdt_totalsize(fdt) > bufsize)
		return -FDT_ERR_TRUNCATED;
	if ((fdt_off_mem_rsvmap(fdt) & 7) || (fdt_off_dt_struct(fdt) & 3))
		return -FDT_ERR_ALIGNMENT;

	err = fdt_num_mem_rsv(fdt);
	if (err < 0)
		return err;

	while (1) {
		offset = nextoffset;
		tag = fdt_next_tag(fdt, offset, &nextoffset);
		if (nextoffset < 0)
			return nextoffset;
		if (expect_end && tag != FDT_END)
			return -FDT_ERR_BADSTRUCTURE;

		switch (tag) {
		case FDT_NOP:
			break;
		case FDT_END:
			return depth ? -FDT_ERR_BADSTRUCTURE : 0;
		case FDT_BEGIN_NODE:
			depth++;
			if (depth > INT_MAX)
				return -FDT_ERR_BADSTRUCTURE;
			if (depth == 1) {
				int len;
				const char *name = fdt_get_name(fdt, offset, &len);

				if (!name)
					return len;
				if (*name || len)
					return -FDT_ERR_BADSTRUCTURE;
			}
			break;
		case FDT_END_NODE:
			if (depth == 0)
				return -FDT_ERR_BADSTRUCTURE;
			depth--;
			if (depth == 0)
				expect_end = 1;
			break;
		case FDT_PROP:
			prop = fdt_getprop_by_offset(fdt, offset, &propname, &err);
			if (!prop)
				return err;
			break;
		default:
			return -FDT_ERR_INTERNAL;
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	void *fdt;
	void *rw;
	int rwsize, child;

	/* fdt_check_header() reads every v17 header field (FDT_V17_SIZE bytes), so a shorter
	 * buffer is an overread by the caller, not something libfdt can reject. */
	if (size < FDT_V17_SIZE)
		return -1;
	fdt = malloc(size);
	if (!fdt)
		return 0;
	memcpy(fdt, data, size);

	if (check_full(fdt, size)) {
		free(fdt);
		return -1;
	}

	walk(fdt);

	rwsize = (int)size + 512;
	rw = malloc(rwsize);
	if (rw && fdt_open_into(fdt, rw, rwsize) == 0) {
		int sub = fdt_add_subnode(rw, 0, "mayhem-node");

		if (sub >= 0) {
			(void)fdt_setprop_u32(rw, sub, "mayhem-prop", 0x1234);
			(void)fdt_appendprop_string(rw, sub, "compatible", "mayhem,test");
			(void)fdt_delprop(rw, sub, "mayhem-prop");
		}
		child = fdt_first_subnode(rw, 0);
		if (child >= 0)
			(void)fdt_del_node(rw, child);
		(void)fdt_add_mem_rsv(rw, 0x1000, 0x1000);
		if (fdt_pack(rw) == 0)
			walk(rw);
	}
	free(rw);
	free(fdt);
	return 0;
}
