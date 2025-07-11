/* radare - LGPLv3 - Copyright 2014-2025 - pancake, jvoisin, jfrankowski */

#include <r_core.h>
#if USE_YARAX
#include <yara_x.h>
#define YR_MAJOR_VERSION 6
#define R2YR_RULE YRX_RULE
#define R2YR_RULES YRX_RULES
#define R2YR_MATCH YRX_MATCH
#define R2YR_COMPILER YRX_COMPILER
#define R2YR_COMPILER_DESTROY yrx_compiler_destroy
#define R2YR_RULES_DESTROY yrx_rules_destroy
#define R2YR_RULE_STRINGS_FOREACH yrx_rule_strings_foreach
#else
#include <yara.h>
#define R2YR_RULE YR_RULE
#define R2YR_RULES YR_RULES
#define R2YR_MATCH YR_MATCH
#define R2YR_COMPILER YR_COMPILER
#define R2YR_COMPILER_DESTROY yr_compiler_destroy
#define R2YR_RULES_DESTROY yr_rules_destroy
#define R2YR_RULE_STRINGS_FOREACH yr_rule_strings_foreach
#endif

#if R2_VERSION_NUMBER >= 50909
#define R2_PRINTF(...) r_cons_printf(r2yara->core->cons, __VA_ARGS__)
#else
#define R2_PRINTF(...) r_cons_printf(__VA_ARGS__)
#endif

const char *short_help_message_yrg[] = {
	"Usage: yrg", "[action] [args..]", " load and run yara rules inside r2",
	"yrg-", "", "delete last pattern added to the yara rule",
	"yrg-", "*", "delete all the patterns in the current rule",
	"yrgs", " ([len])", "add string (optionally specify the length)",
	"yrgx", " ([len])", "add hexpairs of blocksize (or custom length)",
	"yrgf", " ([len])", "add function bytepattern signature",
	"yrgz", "", "add all strings referenced from current function",
	NULL
};

const char *short_help_message[] = {
	"Usage: yr", "[action] [args..]", " load and run yara rules inside r2",
	"yr", " [file]", "add yara rules from file",
	"yr+", "", "add the currently generated yara rule",
	"yr", "", "same as yr?",
	"yr", "-*", "unload all the rules",
	"yr?", "", "show this help (same as 'yara?')",
	"yrg", "[?][-sxf]", "generate yara rule",
	"yrl", "", "list loaded rules",
	"yrs", "[q]", "scan the current file, suffix with 'q' for quiet mode",
	"yrt", " ([tagname])", "list tags from loaded rules, or list rules from given tag",
	"yrv", "", "show version information about r2yara and yara",
	NULL
};

const char *long_help_message[] = {
	"Usage: yara", " [action] [args..]", " load and run yara rules inside r2",
	"yara", " add [file]", "Add yara rules from file",
	"yara", " clear", "Clear all rules",
	"yara", " help", "Show this help (same as 'yara?')",
	"yara", " list", "List all rules",
	"yara", " scan[S]", "Scan the current file, if S option is given it prints matching strings",
	"yara", " show [name]", "Show rules containing name",
	"yara", " tag [name]", "List rules with tag 'name'",
	"yara", " tags", "List tags from the loaded rules",
	"yara", " version", "Show version information about r2yara and yara",
	NULL
};

#if R2_VERSION_NUMBER < 50809
static inline char *r_str_after(char *s, char c) {
	if (s) {
		char *p = strchr (s, c);
		if (p) {
			*p++ = 0;
			return p;
		}
	}
	return NULL;
}
#endif
typedef struct {
	bool initialized;
	bool print_strings;
	unsigned int flagidx;
	bool iova; // true
	RList* rules_list;
	RList *genstrings;
	ut64 map_addr;
	RCore *core;
} R2Yara;

#if R2_VERSION_NUMBER < 50909
static R_TH_LOCAL R2Yara Gr2yara = {0};
#endif

/* Because of how the rules are compiled, we are not allowed to add more
 * rules to a compiler once it has compiled. That's why we keep a list
 * of those compiled rules.
 */

#if USE_YARAX
static void callback(const struct YRX_RULE *rule, void *user_data) {
	R_LOG_INFO ("YARA HIT");
}
#elif YR_MAJOR_VERSION < 4
static int callback(int message, void *msg_data, void *user_data) {
	R2Yara *r2yara = (R2Yara *)user_data;
	RCore *core = r2yara->core;
	RPrint *print = core->print;
	unsigned int ruleidx;
	st64 offset = 0;
	ut64 n = 0;

	R2YR_RULE* rule = msg_data;

	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_STRING* string;
		R2_PRINTF ("%s\n", rule->identifier);
		ruleidx = 0;
		yr_rule_strings_foreach (rule, string) {
			R2YR_MATCH* match;

			yr_string_matches_foreach (string, match) {
				n = match->base + match->offset;
				// Find virtual address if needed
				if (r2yara->iova) {
					RIOMap *map = r_io_map_get_paddr (core->io, n);
					if (map) {
						offset = r_io_map_begin (map) - map->delta;
					}
				}
				r_strf_var (flag, 256, "%s%d.%s_%d", "yara", flagidx, rule->identifier, ruleidx);
				if (r2yara->print_strings) {
					r_cons_printf ("0x%08" PFMT64x ": %s : ", n + offset, flag);
					r_print_bytes (print, match->data, match->data_length, "%02x");
				}
				r_flag_set (core->flags, flag, n + offset, match->data_length);
				ruleidx++;
			}
		}
		flagidx++;
	}
	return CALLBACK_CONTINUE;
}

static void compiler_callback(int error_level, const char* file_name,
		int line_number, const char* message, void* user_data) {
	// TODO depending on error_level. use R_LOG_WARN, ERROR or INFO
	R_LOG_INFO ("file: %s line_number: %d: %s", file_name, line_number, message);
	return;
}
#else
static int callback(YR_SCAN_CONTEXT* context, int message, void *msg_data, void *user_data) {
	R2Yara *r2yara = (R2Yara *)user_data;
	RCore *core = r2yara->core;
	RPrint *print = core->print;
	st64 offset = 0;
	ut64 n = 0;
	ut64 map_addr = r2yara->map_addr;
	R2YR_RULE* rule = msg_data;

#if USE_YARAX
#else
	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_STRING* string;
		R2_PRINTF ("%s\n", rule->identifier);
		unsigned int ruleidx = 0;
		yr_rule_strings_foreach (rule, string) {
			YR_MATCH* match;
			yr_string_matches_foreach (context, string, match) {
				n = map_addr + match->base + match->offset;
				// Find virtual address if needed
				if (!r2yara->iova) {
					RIOMap *map = r_io_map_get_at (core->io, n);
					if (map) {
						n -= r_io_map_begin (map) - map->delta;
					}
#if 0
					RIOMap *map = r_io_map_get_paddr (core->io, n);
					if (map) {
						// offset = r_io_map_begin (map) - map->delta;
						n -= r_io_map_begin (map) + map->delta;
						// n = r_io_map_begin (map) - map->delta;
					}
#endif
				}
				r_strf_var (flag, 256, "yara%d.%s_%d", r2yara->flagidx, rule->identifier, ruleidx);
				if (r2yara->print_strings) {
					R2_PRINTF ("0x%08" PFMT64x ": %s : ", n, flag);
#if R2_VERSION_NUMBER >= 50909
					r_print_bytes (print, match->data, match->data_length, "%02x", 0);
#else
					r_print_bytes (print, match->data, match->data_length, "%02x");
#endif
				}
				r_flag_set (core->flags, flag, n, match->data_length);
				ruleidx++;
			}
		}
		r2yara->flagidx++;
	}
#endif
	return CALLBACK_CONTINUE;
}

static void compiler_callback(int error_level, const char* file_name,
		int line_number, const struct R2YR_RULE *rule, const char* message, void* user_data) {
	// TODO depending on error_level. use R_LOG_WARN, ERROR or INFO
	R_LOG_INFO ("file: %s line_number: %d %s", file_name, line_number, message);
	return;
}
#endif

static bool yr_scan(R2Yara *r2yara, void *to_scan, size_t to_scan_size) {
	RListIter* rules_it;
	R2YR_RULES* rules;
#if USE_YARAX
	YRX_SCANNER *scanner = NULL;
	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		YRX_RESULT res = yrx_scanner_create (rules, &scanner);
		if (res == SUCCESS) {
			YRX_RESULT res = yrx_scanner_on_matching_rule (scanner, callback, r2yara);
			yrx_scanner_scan (scanner, to_scan, to_scan_size);
		}
	}
#else
	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		yr_rules_scan_mem (rules, to_scan, to_scan_size, 0, callback, (void*)r2yara, 0);
	}
#endif
	return true;
}

static bool yr_vscan(R2Yara *r2yara, ut64 from, int to_scan_size) {
	eprintf ("-> 0x%"PFMT64x" + %d\n", from, to_scan_size);
	RCore *core = r2yara->core;
	if (to_scan_size < 1) {
		R_LOG_ERROR ("Invalid file size");
		return false;
	}
	void* to_scan = malloc (to_scan_size);
	if (!to_scan) {
		R_LOG_ERROR ("Something went wrong during memory allocation");
		return false;
	}
	int result = r_io_read_at (core->io, from, to_scan, to_scan_size);
	if (!result) {
		R_LOG_ERROR ("Something went wrong during r_io_read_at");
		free (to_scan);
		return false;
	}
	bool res = yr_scan (r2yara, to_scan, to_scan_size);
	free (to_scan);
	return res;
}

static bool yr_pscan(R2Yara *r2yara) {
	RCore *core = r2yara->core;
	const size_t to_scan_size = r_io_size (core->io);
	if (to_scan_size < 1) {
		R_LOG_ERROR ("Invalid file size");
		return false;
	}
	void* to_scan = malloc (to_scan_size);
	if (!to_scan) {
		R_LOG_ERROR ("Something went wrong during memory allocation");
		return false;
	}
	int result = r_io_pread_at (core->io, 0L, to_scan, to_scan_size);
	if (!result) {
		R_LOG_ERROR ("Something went wrong during r_io_read_at");
		free (to_scan);
		return false;
	}
	bool res = yr_scan (r2yara, to_scan, to_scan_size);
	free (to_scan);
	return res;
}

static int cmd_yara_scan(R2Yara *r2yara, const char* R_NULLABLE option) {
	RCore *core = r2yara->core;
 
	const char *yara_in = r_config_get (core->config, "yara.in");
	RList *ranges = r_core_get_boundaries_prot (core, 0, yara_in, NULL);
	RListIter *iter;
	RIOMap *range;
	r_flag_space_push (core->flags, "yara");
	r2yara->iova = r_config_get_b (core->config, "yara.va");
#if 0
	if (r2yara->iova) {
		r2yara->iova = r_config_get_b (core->config, "io.va");
	}
#endif
	r2yara->print_strings = true;
	if (option != NULL) {
		if (*option == 'q') {
			r2yara->print_strings = false;
		} else {
			R_LOG_ERROR ("Invalid option");
			return false;
		}
	}
	r2yara->map_addr = 0;
	if (!r_list_empty (ranges)) {
		r_list_foreach (ranges, iter, range) {
			ut64 begin = r_io_map_begin (range);
			ut64 end = r_io_map_end (range);
			ut64 size = end - begin;
			r2yara->map_addr = begin;
			yr_vscan (r2yara, begin, (int)size);
		}
		return true;
	}
	return yr_pscan (r2yara);
}

static int cmd_yara_show(R2Yara *r2yara, const char * name) {
	/* List loaded rules containing name */
	RListIter* rules_it;
	R2YR_RULES* rules;
	R2YR_RULE* rule;

	r_list_foreach (r2yara->rules_list, rules_it, rules) {
#if USE_YARAX
		// TODO
#else
		yr_rules_foreach (rules, rule) {
			if (r_str_casestr (rule->identifier, name)) {
				R2_PRINTF ("%s\n", rule->identifier);
			}
		}
#endif
	}
	return true;
}

static int cmd_yara_tags(R2Yara *r2yara) {
	/* List tags from all the different loaded rules */
	RListIter* rules_it;
	RListIter *tags_it;
	R2YR_RULES* rules;
	R2YR_RULE* rule;
	const char* tag_name;
	RList *tag_list = r_list_new();
	tag_list->free = free;

	r_list_foreach (r2yara->rules_list, rules_it, rules) {
#if USE_YARAX
#else
		yr_rules_foreach (rules, rule) {
			yr_rule_tags_foreach (rule, tag_name) {
				if (! r_list_find (tag_list, tag_name, (RListComparator)strcmp)) {
					r_list_add_sorted (tag_list,
							strdup (tag_name), (RListComparator)strcmp);
				}
			}
		}
#endif
	}

	R2_PRINTF ("[YARA tags]\n");
	r_list_foreach (tag_list, tags_it, tag_name) {
		R2_PRINTF ("%s\n", tag_name);
	}

	r_list_free (tag_list);

	return true;
}

static int cmd_yara_tag(R2Yara *r2yara, const char * search_tag) {
	/* List rules with tag search_tag */
	RListIter* rules_it;
	R2YR_RULES* rules;
	R2YR_RULE* rule;
	const char* tag_name;

#if USE_YARAX
#else
	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			yr_rule_tags_foreach (rule, tag_name) {
				R_LOG_WARN ("Invalid option");
				if (search_tag && r_str_casestr (tag_name, search_tag)) {
					R2_PRINTF ("%s\n", rule->identifier);
					break;
				}
			}
		}
	}
#endif

	return true;
}

static int cmd_yara_list(R2Yara *r2yara) {
#if USE_YARAX
	R_LOG_TODO ("not implemented");
#else
	/* List all loaded rules */
	RListIter* rules_it;
	R2YR_RULES* rules;
	R2YR_RULE* rule;
	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			R2_PRINTF ("%s\n", rule->identifier);
		}
	}
#endif
	return 0;
}

static int cmd_yara_clear(R2Yara *r2yara) {
	/* Clears all loaded rules */
	r_list_free (r2yara->rules_list);
	r2yara->rules_list = r_list_newf ((RListFree) R2YR_RULES_DESTROY);
	R_LOG_INFO ("Rules cleared");
	return 0;
}

static void logerr(R2YR_COMPILER* compiler, const char * R_NULLABLE arg) {
#if USE_YARAX
	R_LOG_ERROR ("log error %s", arg);
#else
	char buf[64];
	const char *errmsg = yr_compiler_get_error_message (compiler, buf, sizeof (buf));
	if (R_STR_ISNOTEMPTY (arg)) {
		R_LOG_ERROR ("%s %s", errmsg, arg);
	} else {
		R_LOG_ERROR ("%s", errmsg);
	}
#endif
}

static int cmd_yara_add_file(R2Yara *r2yara, const char* rules_path) {
	R2YR_COMPILER* compiler = NULL;
	R2YR_RULES* rules = NULL;

	if (!rules_path) {
		R_LOG_INFO ("Please tell me what am I supposed to load");
		return false;
	}

	FILE* rules_file = r_sandbox_fopen (rules_path, "r");
	if (!rules_file) {
		R_LOG_ERROR ("Unable to open %s", rules_path);
		return false;
	}

#if USE_YARAX
	int result = -1;
#else
	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}
	int result = yr_compiler_add_file (compiler, rules_file, NULL, rules_path);
#endif
	fclose (rules_file);
	rules_file = NULL;
	if (result > 0) {
		logerr (compiler, rules_path);
		goto err_exit;
	}

#if USE_YARAX
	yrx_compiler_destroy (compiler);
#else
	if (yr_compiler_get_rules (compiler, &rules) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}
	yr_compiler_destroy (compiler);
#endif
	r_list_append (r2yara->rules_list, rules);

	return true;

err_exit:
	if (compiler) {
		R2YR_COMPILER_DESTROY (compiler);
	}
	if (rules_file) {
		fclose (rules_file);
	}
	return false;
}

static RStrBuf *get_current_rule(R2Yara *r2yara) {
	RStrBuf *sb = r_strbuf_new ("");
	RConfig *cfg = r2yara->core->config;
	const char *name = r_config_get (cfg, "yara.rule");
	const char *tags = r_config_get (cfg, "yara.tags");
	const char *auth = r_config_get (cfg, "yara.author");
	const char *desc = r_config_get (cfg, "yara.description");
	const char *date = r_config_get (cfg, "yara.date");
	const char *vers = r_config_get (cfg, "yara.version");
	const int amount = r_config_get_i (cfg, "yara.amount");
	r_strbuf_appendf (sb, "rule %s : %s {\n", name, tags);
	r_strbuf_appendf (sb,"  meta:\n");
	r_strbuf_appendf (sb,"    author = \"%s\"\n", auth);
	r_strbuf_appendf (sb,"    description = \"%s\"\n", desc);
	r_strbuf_appendf (sb,"    date = \"%s\"\n", date);
	r_strbuf_appendf (sb,"    version = \"%s\"\n", vers);
	if (r_list_empty (r2yara->genstrings)) {
		R_LOG_WARN ("See 'yrg?' to find out which subcommands use to append patterns to the rule");
	} else {
		r_strbuf_append (sb,"  strings:\n");
		RListIter *iter;
		const char *s;
		r_list_foreach (r2yara->genstrings, iter, s) {
			r_strbuf_appendf (sb,"    $ = %s\n", s);
		}
		r_strbuf_append (sb,"  condition:\n");
		if (amount > 1) {
			r_strbuf_appendf (sb,"    %d of them\n", amount);
		} else {
			r_strbuf_append (sb,"    all of them\n");
		}
	}
	r_strbuf_append (sb,"}\n");
	return sb;
}

static void cmd_yara_gen_show(R2Yara *r2yara) {
	R2_PRINTF ("%s", r_strbuf_tostring (get_current_rule (r2yara)));
}

static void cmd_yara_add_current(R2Yara *r2yara) {
	R2YR_COMPILER* compiler = NULL;
	R2YR_RULES* yr_rules = NULL;

	if (r_list_empty (r2yara->genstrings)) {
		R_LOG_WARN ("Empty pattern, see 'yrg?' to find out which subcommands use to append patterns to the rule");
		return;
	}

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}
	if (yr_compiler_add_string (compiler, r_strbuf_tostring(get_current_rule(r2yara)), NULL) > 0) {
		logerr (compiler, NULL);
		goto err_exit;
	}
	if (yr_compiler_get_rules (compiler, &yr_rules) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	r_list_append (r2yara->rules_list, yr_rules);
	R_LOG_INFO ("Rule successfully added");
	
	err_exit:
	if (compiler != NULL) {
		R2YR_COMPILER_DESTROY (compiler);
	}
}

static char *yarastring(const char *s) {
	RStrBuf *sb = r_strbuf_new ("\"");
	char *a = strdup (s);
	r_str_trim (a);
	a = r_str_replace_all (a, "\n", "\\n");
	r_strbuf_append (sb, a);
	r_strbuf_append (sb, "\"");
	free (a);
	return r_strbuf_drain (sb);;
}

static int cmd_yara_gen(R2Yara *r2yara, const char* input) {
	const char arg0 = input? *input: 0;
	switch (arg0) {
	case 0:
		cmd_yara_gen_show (r2yara);
		break;
	case '?':
		r_core_cmd_help (r2yara->core, short_help_message_yrg);
		break;
	case 'z':
		{
			char *s = r_core_cmd_str (r2yara->core, "axff~str.~[3]~$$");
			r_str_trim (s);
			RList *words = r_str_split_list (s, "\n", 0);
			RListIter *iter;
			char *word;
			r_list_foreach (words, iter, word) {
				char *z = r_core_cmd_strf (r2yara->core, "psz @ %s", word);
				r_list_append (r2yara->genstrings, yarastring (z));
				free (z);
			}
			r_list_free (words);
			free (s);
		}
		break;
	case 'f':
		{
			char *b = r_core_cmd_str (r2yara->core, "zj $$~{.bytes}");
			char *m = r_core_cmd_str (r2yara->core, "zj $$~{.mask}");

			r_str_trim (b);
			r_str_trim (m);
			size_t blen = strlen (b);
			if (blen != strlen (m)) {
				R_LOG_WARN ("Mismatch");
				break;
			}
			if (blen % 2) {
				R_LOG_WARN ("Uneven pattern");
				break;
			}
			if (blen == 0) {
				R_LOG_WARN ("No byte pattern");
				break;
			}
			R_LOG_DEBUG ("-> %s\n", b);
			R_LOG_DEBUG ("=> %s\n", m);
			RStrBuf *sb = r_strbuf_new ("{");
			int i;
			for (i = 0; b[i]; i += 2) {
				if (r_str_startswith (m + i, "ff")) {
					r_strbuf_appendf (sb, " %c%c", b[i], b[i + 1]);
				} else {
					r_strbuf_append (sb, " ??");
				}
			}
			r_strbuf_append (sb, " }");
			char *s = r_strbuf_drain (sb);
			r_list_append (r2yara->genstrings, s);
		}
		break;
	case 's':
		{
			char *s;
			if (input[1]) {
				int len = (int)r_num_math (r2yara->core->num, input + 1);
				s = r_core_cmd_strf (r2yara->core, "psz %d", len);
			} else {
				s = r_core_cmd_str (r2yara->core, "psz");
			}
			r_list_append (r2yara->genstrings, yarastring (s));
		}
		break;
	case '-':
		if (input && input[1] == '*') {
			r_list_free (r2yara->genstrings);
			r2yara->genstrings = r_list_newf (free);
		} else {
			free (r_list_pop (r2yara->genstrings));
		}
		break;
	case 'x':
		{
			char *s;
			if (input[1]) {
				int len = r_num_math (r2yara->core->num, input + 1);
				s = r_core_cmd_strf (r2yara->core, "pcy %d", len);
			} else {
				s = r_core_cmd_str (r2yara->core, "pcy");
			}
			r_str_trim (s);
			r_list_append (r2yara->genstrings, s);
		}
		break;
	}
	return 0;
}

static bool cmd_yara_add(R2Yara *r2yara, const char* input) {
	/* Add a rule with user input */
	R2YR_COMPILER* compiler = NULL;
	int i;
	if (!input) {
		R_LOG_ERROR ("Missing argument");
		return false;
	}

	for (i = 0; input[i]; i++) {
		if (input[i] != ' ') {
			return cmd_yara_add_file (r2yara, input + i);
		}
	}
	return false;
}

static int cmd_yara_version(R2Yara *r2yara) {
	R2_PRINTF ("r2 %s\n", R2_VERSION);
#if USE_YARAX
	R2_PRINTF ("yarax git\n");
#else
	R2_PRINTF ("yara %s\n", YR_VERSION);
#endif
	R2_PRINTF ("r2yara %s\n", R2Y_VERSION);
	return 0;
}

// TODO: deprecate the "yara" command, unless we expose "yara" and "yarac" commands as the original tools from the r2 shell
static int cmd_yara_process(R2Yara *r2yara, const char* input) {
	char *inp = strdup (input);
	char *arg = r_str_after (inp, ' ');
	if (arg) {
		arg = (char *)r_str_trim_head_ro (arg);
	}
	int res = -1;
	if (r_str_startswith (input, "add")) {
		res = cmd_yara_add (r2yara, arg);
	} else if (r_str_startswith (inp, "clear")) {
		res = cmd_yara_clear (r2yara);
	} else if (r_str_startswith (inp, "list")) {
		res = cmd_yara_list (r2yara);
	} else if (r_str_startswith (inp, "scanS") || r_str_startswith (inp, "scan S")) {
		res = cmd_yara_scan (r2yara, "q");
	} else if (r_str_startswith (inp, "scan")) {
		res = cmd_yara_scan (r2yara, arg);
	} else if (r_str_startswith (inp, "show")) {
		res = cmd_yara_show (r2yara, arg);
	} else if (r_str_startswith (inp, "tags")) {
		res = cmd_yara_tags (r2yara);
	} else if (r_str_startswith (input, "tag ")) {
		res = cmd_yara_tag (r2yara, arg);
	} else if (r_str_startswith (input, "ver")) {
		res = cmd_yara_version (r2yara);
	} else {
		r_core_cmd_help (r2yara->core, long_help_message);
	}
	free (inp);
	return res;
}

static int cmd_yr(R2Yara *r2yara, const char *input) {
	char *inp = strdup (input);
	char *arg = r_str_after (inp, ' ');
	int res = -1;
	if (arg) {
		arg = (char *)r_str_trim_head_ro (arg);
	}
	switch (*input) {
	case '?': // "yr?"
	case 0:
		r_core_cmd_help (r2yara->core, short_help_message);
		break;
	case 'l':
		cmd_yara_list (r2yara);
		break;
	case '/': // "yr/" <- imho makes more sense
	case 's': // "yrs"
		if (input[1] == 'q') {
			res = cmd_yara_scan (r2yara, "q");
		} else {
			res = cmd_yara_scan (r2yara, arg);
		}
		break;
	case 'g': // "yrg"
		cmd_yara_gen (r2yara, input + 1);
		break;
	case '+': // "yr+""
		cmd_yara_add_current (r2yara);
		break;
	case ' ':
		cmd_yara_add (r2yara, arg);
		break;
	case '-':
		cmd_yara_clear (r2yara);
		break;
	case 't': // "yrt"
		if (input[1]) {
			if (input[1] == '?') {
				r_core_cmd_help_contains (r2yara->core, short_help_message, "yrt");
			} else {
				cmd_yara_tag (r2yara, arg);
			}
		} else {
			cmd_yara_tags (r2yara);
		}
		break;
	case 'v': // "yrv"
		res = cmd_yara_version (r2yara);
		break;
	}
	free (inp);
	return res;
}

static int cmd_yara_load_default_rules(R2Yara *r2yara) {
	RCore* core = r2yara->core;
	RListIter* iter = NULL;
	R2YR_COMPILER* compiler = NULL;
	R2YR_RULES* yr_rules = NULL;
	char* filename;
	char* rules = NULL;
#if R2_VERSION_NUMBER < 50709
	char* y3_rule_dir = r_str_newf ("%s%s%s", r_str_home (R2_HOME_PLUGINS), R_SYS_DIR, "rules-yara3");
#else
	char* y3_rule_dir = r_xdg_datadir ("plugins/rules-yara3");
#endif
	RList* list = r_sys_dir (y3_rule_dir);

#if USE_YARAX
	if (yrx_compiler_create (0, &compiler) != SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}
#else
	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}
	yr_compiler_set_callback (compiler, compiler_callback, NULL);
#endif

	r_list_foreach (list, iter, filename) {
		if (filename[0] == '.') {
			// skip '.', '..' and hidden files
			continue;
		}
		char *rulepath = r_str_newf ("%s%s%s", y3_rule_dir, R_SYS_DIR, filename);
		if (r_str_endswith (filename, ".gz")) {
			rules = (char*)r_file_gzslurp (rulepath, NULL, true);
		} else {
			rules = (char*)r_file_slurp (rulepath, NULL);
		}
		if (rules != NULL) {
#if USE_YARAX
			if (yrx_compiler_add_source (compiler, rules) > 0) {
				logerr (compiler, NULL);
			}
#else
			if (yr_compiler_add_string (compiler, rules, rulepath) > 0) {
				logerr (compiler, NULL);
			}
#endif
			R_FREE (rules);
		} else {
			R_LOG_ERROR ("cannot load %s", rulepath);
		}
		free (rulepath);
	}
	r_list_free (list);
	list = NULL;

#if USE_YARAX
	if (yrx_compiler_build (compiler) != SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}
#else
	if (yr_compiler_get_rules (compiler, &yr_rules) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}
#endif

	r_list_append (r2yara->rules_list, yr_rules);

	if (compiler) {
		R2YR_COMPILER_DESTROY (compiler);
	}
	return true;

err_exit:
	free (y3_rule_dir);
	if (compiler) {
		R2YR_COMPILER_DESTROY (compiler);
	}
	r_list_free (list);
	free (rules);
	return false;
}

// Move to r_sys_time_ymd?
static char *yyyymmdd(void) {
	time_t current_time;
	char *ds = calloc (16, 1);
	time (&current_time);
	struct tm *time_info = localtime (&current_time);
	strftime (ds, 16, "%Y-%m-%d", time_info);
	return ds;
}

static bool yara_in_callback(void *user, void *data) {
	RCore *core = (RCore*)user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
#if R2_VERSION_NUMBER >= 50909
		r_cons_printf (core->cons,
#else
		r_cons_printf (
#endif
			"range              search between .from/.to boundaries\n"
			"flag               find boundaries in ranges defined by flags larger than 1 byte\n"
			"flag:[glob]        find boundaries in flags matching given glob and larger than 1 byte\n"
			"block              search in the current block\n"
			"io.map             search in current map\n"
			"io.maps            search in all maps\n"
			"io.maps.[rwx]      search in all r-w-x io maps\n"
			"bin.segment        search in current mapped segment\n"
			"bin.segments       search in all mapped segments\n"
			"bin.segments.[rwx] search in all r-w-x segments\n"
			"bin.section        search in current mapped section\n"
			"bin.sections       search in all mapped sections\n"
			"bin.sections.[rwx] search in all r-w-x sections\n"
			"dbg.stack          search in the stack\n"
			"dbg.heap           search in the heap\n"
			"dbg.map            search in current memory map\n"
			"dbg.maps           search in all memory maps\n"
			"dbg.maps.[rwx]     search in all executable marked memory maps\n"
			"anal.fcn           search in the current function\n"
			"anal.bb            search in the current basic-block\n");
		return false;
	}
	return true;
}

static void setup_config(R2Yara *r2yara) {
	RConfig *cfg = r2yara->core->config;
	RConfigNode *node = NULL;
	r_config_lock (cfg, false);
	char *me = r_sys_whoami ();
	node = r_config_set (cfg, "yara.author", me);
	r_config_node_desc (node, "Author of the YARA rule");
	free (me);
	node = r_config_set (cfg, "yara.description", "My first yara rule");
	r_config_node_desc (node, "YARA rule description");
	char *ymd = yyyymmdd ();
	node = r_config_set (cfg, "yara.date", ymd);
	r_config_node_desc (node, "YARA rule creation date");
	free (ymd);
	node = r_config_set (cfg, "yara.version", "0.1");
	r_config_node_desc (node, "YARA rule version");
	node = r_config_set (cfg, "yara.rule", "rulename");
	r_config_node_desc (node, "YARA rule name");
	node = r_config_set (cfg, "yara.tags", "test");
	r_config_node_desc (node, "YARA rule tags");
	node = r_config_set_i (cfg, "yara.amount", 0);
	r_config_node_desc (node, "Amount of strings to match (0 means all of them)");
	node = r_config_set_b (cfg, "yara.va", true);
	r_config_node_desc (node, "Show results in virtual or physical addresses, overrides io.va");
	node = r_config_set_cb (cfg, "yara.in", "io.map", yara_in_callback);
	r_config_node_desc (node, "Where to scan for matches (see yara.in=? for help)");
	r_config_lock (cfg, true);
}

#if R2_VERSION_NUMBER >= 50909
static bool cmd_yara_init(RCorePluginSession *cps) {
	RCore *core = cps->core;
	R2Yara *r2yara = R_NEW0 (R2Yara);
	r2yara->iova = true;
	r2yara->core = core;
	r2yara->rules_list = r_list_newf ((RListFree) R2YR_RULES_DESTROY);
	r2yara->genstrings = r_list_newf (free);
#if !USE_YARAX
	yr_initialize ();
#endif
	setup_config (r2yara);

	cmd_yara_load_default_rules (r2yara);
	r2yara->initialized = true;
	r2yara->flagidx = 0;
	cps->data = r2yara;
	return true;
}
#else
static int cmd_yara_init(void *user, const char *cmd) {
	RCmd *rcmd = (RCmd *)user;
	RCore* core = (RCore *)rcmd->data;

	R2Yara *r2yara = &Gr2yara;
	memset (r2yara, 0, sizeof (R2Yara));
	r2yara->iova = true;
	r2yara->core = core;
	r2yara->rules_list = r_list_newf ((RListFree) R2YR_RULES_DESTROY);
	r2yara->genstrings = r_list_newf (free);
#if !USE_YARAX
	yr_initialize ();
#endif
	setup_config (r2yara);

	cmd_yara_load_default_rules (r2yara);
	r2yara->initialized = true;
	r2yara->flagidx = 0;
	return true;
}
#endif

static bool yaracall(R2Yara *r2yara, const char *input) {
	if (r_str_startswith (input, "yr")) {
		cmd_yr (r2yara, input + 2);
		return true;
	}
	if (!r_str_startswith (input, "yara")) {
		return false;
	}
#if R2_VERSION_NUMBER < 50909
	if (!r2yara->initialized) {
		if (!cmd_yara_init (r2yara, NULL)) {
			return false;
		}
	}
#endif
	const char *args = input[4]? input + 5: input + 4;
	cmd_yara_process (r2yara, args);
	return true;
}

#if R2_VERSION_NUMBER >= 50909
static bool cmd_yara_call(RCorePluginSession *cps, const char *input) {
	RCore* core = cps->core;
	R2Yara *r2yara = cps->data;
	return yaracall (r2yara, input);
}
#else
static int cmd_yara_call(void *user, const char *input) {
	RCmd *rcmd = (RCmd *)user;
	RCore* core = (RCore *)rcmd->data;
	R2Yara *r2yara = &Gr2yara;
	r2yara->core = core;
	return yaracall (r2yara, input);
}
#endif

#if R2_VERSION_NUMBER >= 50909
static bool cmd_yara_fini(RCorePluginSession *cps) {
	// RCore* core = cps->core;
	R2Yara *r2yara = cps->data;
	if (r2yara->initialized) {
		r_list_free (r2yara->rules_list);
		r_list_free (r2yara->genstrings);
#if !USE_YARAX
		yr_finalize ();
#endif
		r2yara->initialized = false;
	}
	free (cps->data);
	return true;
}
#else
static int cmd_yara_fini(void *user, const char *cmd) {
	RCmd *rcmd = (RCmd *)user;
	RCore* core = (RCore *)rcmd->data;
	R2Yara *r2yara = &Gr2yara;
	if (r2yara->initialized) {
		r_list_free (r2yara->rules_list);
		r_list_free (r2yara->genstrings);
#if !USE_YARAX
		yr_finalize ();
#endif
		r2yara->initialized = false;
	}
	return true;
}
#endif

RCorePlugin r_core_plugin_yara = {
#if R2_VERSION_NUMBER < 50809
	.name = "yara",
	.desc = "YARA integration",
	.license = "LGPL",
	.version = R2Y_VERSION,
#else
	.meta = {
		.name = "yara",
		.desc = "YARA integration",
		.license = "LGPL",
		.version = R2Y_VERSION,
	},
#endif
#if R2_VERSION_NUMBER >= 50909
	.call = cmd_yara_call,
	.init = cmd_yara_init,
	.fini = cmd_yara_fini
#else
	.call = cmd_yara_call,
	.init = cmd_yara_init,
	.fini = cmd_yara_fini
#endif
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_yara,
#if R2_VERSION_NUMBER >= 50909
	.abiversion = R2_ABIVERSION,
#endif
        .version = R2_VERSION
};
#endif
