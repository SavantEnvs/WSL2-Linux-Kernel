/* Fuzz libbpf's BTF parser, type walker, C dumper and deduplicator (tools/lib/bpf/btf*.c). */
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

static void dump_sink(void *ctx, const char *fmt, va_list args)
{
	(void)ctx; (void)fmt; (void)args;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	libbpf_set_print(quiet_print);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct btf *btf;
	struct btf_dump *d;
	__u32 i, n, rawsz;
	void *buf;

	buf = malloc(size ? size : 1);
	if (!buf)
		return 0;
	memcpy(buf, data, size);
	btf = btf__new(buf, size);
	free(buf);
	if (!btf)
		return -1;

	n = btf__type_cnt(btf);
	for (i = 1; i < n; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);

		if (!t)
			continue;
		(void)btf__name_by_offset(btf, t->name_off);
		(void)btf__resolve_size(btf, i);
		(void)btf__resolve_type(btf, i);
		(void)btf__align_of(btf, i);
	}

	d = btf_dump__new(btf, dump_sink, NULL, NULL);
	if (d) {
		for (i = 1; i < n; i++)
			(void)btf_dump__dump_type(d, i);
		btf_dump__free(d);
	}

	(void)btf__raw_data(btf, &rawsz);
	(void)btf__dedup(btf, NULL);
	n = btf__type_cnt(btf);
	for (i = 1; i < n; i++)
		(void)btf__type_by_id(btf, i);
	btf__free(btf);
	return 0;
}
