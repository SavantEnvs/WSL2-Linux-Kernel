/* Known-answer probe for libfdt: build a tree, validate it, query it, edit it, print facts. */
#include <libfdt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { int _r = (x); if (_r < 0) { printf("ERROR %s -> %d\n", #x, _r); return 1; } } while (0)

int main(void)
{
	static char blob[4096], rw[8192];
	const char compat[] = "vendor,soc\0vendor,bus";
	int soc, ser, off, len;
	const fdt32_t *reg;
	const char *s;
	char path[64];

	CHECK(fdt_create(blob, sizeof(blob)));
	CHECK(fdt_finish_reservemap(blob));
	CHECK(fdt_begin_node(blob, ""));
	CHECK(fdt_property_string(blob, "model", "Mayhem KAT"));
	CHECK(fdt_property_u32(blob, "#address-cells", 1));
	CHECK(fdt_property_u32(blob, "#size-cells", 1));
	CHECK(fdt_begin_node(blob, "soc"));
	CHECK(fdt_property(blob, "compatible", compat, sizeof(compat)));
	CHECK(fdt_begin_node(blob, "serial@1000"));
	CHECK(fdt_property_u32(blob, "phandle", 7));
	{
		fdt32_t cells[2] = { cpu_to_fdt32(0x1000), cpu_to_fdt32(0x100) };
		CHECK(fdt_property(blob, "reg", cells, sizeof(cells)));
	}
	CHECK(fdt_end_node(blob));
	CHECK(fdt_end_node(blob));
	CHECK(fdt_end_node(blob));
	CHECK(fdt_finish(blob));

	CHECK(fdt_check_header(blob));
	printf("magic=0x%x version=%d\n", fdt_magic(blob), fdt_version(blob));

	s = fdt_getprop(blob, 0, "model", &len);
	printf("model=%s len=%d\n", s, len);

	soc = fdt_path_offset(blob, "/soc");
	CHECK(soc);
	printf("soc compat count=%d\n", fdt_stringlist_count(blob, soc, "compatible"));
	printf("soc matches vendor,bus=%d vendor,none=%d\n",
	       fdt_node_check_compatible(blob, soc, "vendor,bus"),
	       fdt_node_check_compatible(blob, soc, "vendor,none"));

	off = fdt_node_offset_by_phandle(blob, 7);
	CHECK(off);
	CHECK(fdt_get_path(blob, off, path, sizeof(path)));
	printf("phandle 7 -> %s\n", path);

	ser = fdt_subnode_offset(blob, soc, "serial@1000");
	CHECK(ser);
	reg = fdt_getprop(blob, ser, "reg", &len);
	printf("serial reg=0x%x,0x%x len=%d\n", fdt32_to_cpu(reg[0]), fdt32_to_cpu(reg[1]), len);
	printf("bad path -> %s\n", fdt_strerror(fdt_path_offset(blob, "/nope")));

	CHECK(fdt_open_into(blob, rw, sizeof(rw)));
	CHECK(fdt_setprop_u32(rw, fdt_path_offset(rw, "/soc/serial@1000"), "clock-frequency", 115200));
	CHECK(fdt_del_node(rw, ser));
	CHECK(fdt_pack(rw));
	CHECK(fdt_check_header(rw));
	printf("after edit: serial=%s soc children=%d\n",
	       fdt_strerror(fdt_path_offset(rw, "/soc/serial@1000")),
	       fdt_first_subnode(rw, fdt_path_offset(rw, "/soc")) < 0 ? 0 : 1);

	{
		char bad[8] = "notafdt";
		printf("bad header check=%s\n", fdt_strerror(fdt_check_header(bad)));
	}
	return 0;
}
