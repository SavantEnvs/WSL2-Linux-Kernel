/* Fuzz libbpf's BPF object (ELF) loader from the kernel tree: tools/lib/bpf. */
#include "libbpf.h"
#include "btf.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int quiet_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	(void)level; (void)fmt; (void)args;
	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	libbpf_set_print(quiet_print);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;

	obj = bpf_object__open_mem(data, size, &opts);
	if (!obj)
		return -1;

	bpf_object__for_each_program(prog, obj) {
		(void)bpf_program__name(prog);
		(void)bpf_program__section_name(prog);
		(void)bpf_program__type(prog);
		(void)bpf_program__insn_cnt(prog);
		(void)bpf_program__insns(prog);
	}
	bpf_object__for_each_map(map, obj) {
		(void)bpf_map__name(map);
		(void)bpf_map__type(map);
		(void)bpf_map__key_size(map);
		(void)bpf_map__value_size(map);
		(void)bpf_map__max_entries(map);
	}
	(void)bpf_object__btf(obj);
	(void)bpf_object__name(obj);
	bpf_object__close(obj);
	return 0;
}
