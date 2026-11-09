/* Known-answer probe for libbpf: parse a clang-built BPF object and its BTF, and build/dump BTF. */
#include "libbpf.h"
#include "btf.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int quiet(enum libbpf_print_level l, const char *f, va_list a) { return 0; }

static void to_stdout(void *ctx, const char *fmt, va_list args) { vprintf(fmt, args); }

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct btf *btf, *mine;
	struct btf_dump *d;
	int i, n, st, in, rc = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: bpf_kat obj.bpf.o file.btf\n");
		return 2;
	}
	libbpf_set_print(quiet);

	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		printf("open failed\n");
		return 1;
	}
	bpf_object__for_each_program(prog, obj)
		printf("prog %s sec=%s type=%d\n", bpf_program__name(prog),
		       bpf_program__section_name(prog), bpf_program__type(prog));
	bpf_object__for_each_map(map, obj)
		printf("map %s type=%d key=%u value=%u max=%u\n", bpf_map__name(map),
		       bpf_map__type(map), bpf_map__key_size(map), bpf_map__value_size(map),
		       bpf_map__max_entries(map));
	bpf_object__close(obj);

	btf = btf__parse_raw(argv[2]);
	if (!btf) {
		printf("btf parse failed\n");
		return 1;
	}
	n = btf__type_cnt(btf);
	i = btf__find_by_name_kind(btf, "kat_value", BTF_KIND_STRUCT);
	printf("kat_value struct found=%s size=%ld\n", i > 0 ? "yes" : "no",
	       i > 0 ? (long)btf__resolve_size(btf, i) : -1L);
	d = btf_dump__new(btf, to_stdout, NULL, NULL);
	if (i > 0)
		btf_dump__dump_type(d, i);
	btf_dump__free(d);
	btf__free(btf);

	mine = btf__new_empty();
	in = btf__add_int(mine, "unsigned int", 4, 0);
	st = btf__add_struct(mine, "point", 8);
	btf__add_field(mine, "x", in, 0, 0);
	btf__add_field(mine, "y", in, 32, 0);
	printf("built btf: int=%d struct=%d size=%ld\n", in, st, (long)btf__resolve_size(mine, st));
	d = btf_dump__new(mine, to_stdout, NULL, NULL);
	btf_dump__dump_type(d, st);
	btf_dump__free(d);
	btf__free(mine);
	return rc;
}
