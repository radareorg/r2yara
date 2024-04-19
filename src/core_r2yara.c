/* radare - LGPLv3 - Copyright 2014-2024 - pancake, jvoisin, jfrankowski */

#include <r_core.h>
#include <yara.h>

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
	RCore *core;
} R2Yara;

// RCorePlugins have no session yet // R2_600
// TODO: remove globals when r2-6.0.0 ships RCoreSession
static R_TH_LOCAL R2Yara Gr2yara = {0};

static const char yara_rule_template[] = "rule RULE_NAME {\n  strings:\n\n  condition:\n}";

/* Because of how the rules are compiled, we are not allowed to add more
 * rules to a compiler once it has compiled. That's why we keep a list
 * of those compiled rules.
 */

#if YR_MAJOR_VERSION < 4
static int callback(int message, void *msg_data, void *user_data) {
	R2Yara *r2yara = (R2Yara *)user_data;
	RCore *core = r2yara->core;
	RPrint *print = core->print;
	unsigned int ruleidx;
	st64 offset = 0;
	ut64 n = 0;

	YR_RULE* rule = msg_data;

	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_STRING* string;
		r_cons_printf ("%s\n", rule->identifier);
		ruleidx = 0;
		yr_rule_strings_foreach (rule, string) {
			YR_MATCH* match;

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

	YR_RULE* rule = msg_data;

	if (message == CALLBACK_MSG_RULE_MATCHING) {
		YR_STRING* string;
		r_cons_printf ("%s\n", rule->identifier);
		unsigned int ruleidx = 0;
		yr_rule_strings_foreach (rule, string) {
			YR_MATCH* match;
			yr_string_matches_foreach (context, string, match) {
				n = match->base + match->offset;
				// Find virtual address if needed
				if (r2yara->iova) {
					RIOMap *map = r_io_map_get_paddr (core->io, n);
					if (map) {
						offset = r_io_map_begin (map) - map->delta;
					}
				}
				r_strf_var (flag, 256, "yara%d.%s_%d", r2yara->flagidx, rule->identifier, ruleidx);
				if (r2yara->print_strings) {
					r_cons_printf ("0x%08" PFMT64x ": %s : ", n + offset, flag);
					r_print_bytes (print, match->data, match->data_length, "%02x");
				}
				r_flag_set (core->flags, flag, n + offset, match->data_length);
				ruleidx++;
			}
		}
		r2yara->flagidx++;

	}
	return CALLBACK_CONTINUE;
}

static void compiler_callback(int error_level, const char* file_name,
		int line_number, const struct YR_RULE *rule, const char* message, void* user_data) {
	// TODO depending on error_level. use R_LOG_WARN, ERROR or INFO
	R_LOG_INFO ("file: %s line_number: %d %s", file_name, line_number, message);
	return;
}
#endif

static int cmd_yara_scan(R2Yara *r2yara, R_NULLABLE const char* option) {
	RCore *core = r2yara->core;
	RListIter* rules_it;
	YR_RULES* rules;

	r_flag_space_push (core->flags, "yara");
	const size_t to_scan_size = r_io_size (core->io);
	r2yara->iova = r_config_get_b (core->config, "io.va");

	if (to_scan_size < 1) {
		R_LOG_ERROR ("Invalid file size");
		return false;
	}

	r2yara->print_strings = true;
	if (option != NULL) {
		if (*option == 'q') {
			r2yara->print_strings = false;
		} else {
			R_LOG_ERROR ("Invalid option");
			return false;
		}
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
	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		yr_rules_scan_mem (rules, to_scan, to_scan_size, 0, callback, (void*)&r2yara, 0);
	}
	free (to_scan);

	return true;
}

static int cmd_yara_show(R2Yara *r2yara, const char * name) {
	/* List loaded rules containing name */
	RListIter* rules_it;
	YR_RULES* rules;
	YR_RULE* rule;

	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			if (r_str_casestr (rule->identifier, name)) {
				r_cons_printf ("%s\n", rule->identifier);
			}
		}
	}

	return true;
}

static int cmd_yara_tags(R2Yara *r2yara) {
	/* List tags from all the different loaded rules */
	RListIter* rules_it;
	RListIter *tags_it;
	YR_RULES* rules;
	YR_RULE* rule;
	const char* tag_name;
	RList *tag_list = r_list_new();
	tag_list->free = free;

	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		yr_rules_foreach(rules, rule) {
			yr_rule_tags_foreach(rule, tag_name) {
				if (! r_list_find (tag_list, tag_name, (RListComparator)strcmp)) {
					r_list_add_sorted (tag_list,
							strdup (tag_name), (RListComparator)strcmp);
				}
			}
		}
	}

	r_cons_printf ("[YARA tags]\n");
	r_list_foreach (tag_list, tags_it, tag_name) {
		r_cons_printf ("%s\n", tag_name);
	}

	r_list_free (tag_list);

	return true;
}

static int cmd_yara_tag(R2Yara *r2yara, const char * search_tag) {
	/* List rules with tag search_tag */
	RListIter* rules_it;
	YR_RULES* rules;
	YR_RULE* rule;
	const char* tag_name;

	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			yr_rule_tags_foreach(rule, tag_name) {
				R_LOG_WARN ("Invalid option");
				if (r_str_casestr (tag_name, search_tag)) {
					r_cons_printf ("%s\n", rule->identifier);
					break;
				}
			}
		}
	}

	return true;
}

static int cmd_yara_list(R2Yara *r2yara) {
	/* List all loaded rules */
	RListIter* rules_it;
	YR_RULES* rules;
	YR_RULE* rule;

	r_list_foreach (r2yara->rules_list, rules_it, rules) {
		yr_rules_foreach (rules, rule) {
			r_cons_printf ("%s\n", rule->identifier);
		}
	}
	return 0;
}

static int cmd_yara_clear(R2Yara *r2yara) {
	/* Clears all loaded rules */
	r_list_free (r2yara->rules_list);
	r2yara->rules_list = r_list_newf ((RListFree) yr_rules_destroy);
	R_LOG_INFO ("Rules cleared");
	return 0;
}

static void logerr(YR_COMPILER* compiler, R_NULLABLE const char *arg) {
	char buf[64];
	const char *errmsg = yr_compiler_get_error_message (compiler, buf, sizeof (buf));
	if (arg) {
		R_LOG_ERROR ("%s %s", errmsg, arg);
	} else {
		R_LOG_ERROR ("%s", errmsg);
	}
}

static int cmd_yara_add_file(R2Yara *r2yara, const char* rules_path) {
	YR_COMPILER* compiler = NULL;
	YR_RULES* rules;

	if (!rules_path) {
		R_LOG_INFO ("Please tell me what am I supposed to load");
		return false;
	}

	FILE* rules_file = r_sandbox_fopen (rules_path, "r");
	if (!rules_file) {
		R_LOG_ERROR ("Unable to open %s", rules_path);
		return false;
	}

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	int result = yr_compiler_add_file (compiler, rules_file, NULL, rules_path);
	fclose (rules_file);
	rules_file = NULL;
	if (result > 0) {
		logerr (compiler, rules_path);
		goto err_exit;
	}

	if (yr_compiler_get_rules (compiler, &rules) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	r_list_append (r2yara->rules_list, rules);

	yr_compiler_destroy (compiler);
	return true;

err_exit:
	if (compiler) {
		yr_compiler_destroy (compiler);
	}
	if (rules_file) {
		fclose (rules_file);
	}
	return false;
}

static void cmd_yara_gen_show(R2Yara *r2yara, int format) {
	RConfig *cfg = r2yara->core->config;
	const char *name = r_config_get (cfg, "yara.rule");
	const char *tags = r_config_get (cfg, "yara.tags");
	const char *auth = r_config_get (cfg, "yara.author");
	const char *desc = r_config_get (cfg, "yara.description");
	const char *date = r_config_get (cfg, "yara.date");
	const char *vers = r_config_get (cfg, "yara.version");
	const int amount = r_config_get_i (cfg, "yara.amount");
	r_cons_printf ("rule %s : %s {\n", name, tags);
	r_cons_printf ("  meta:\n");
	r_cons_printf ("    author = \"%s\"\n", auth);
	r_cons_printf ("    description = \"%s\"\n", desc);
	r_cons_printf ("    date = \"%s\"\n", date);
	r_cons_printf ("    version = \"%s\"\n", vers);
	if (r_list_empty (r2yara->genstrings)) {
		R_LOG_WARN ("Use 'yrg[sx..] subcommands to register strings, bytes to the current rule");
	} else {
		r_cons_printf ("  strings:\n");
		RListIter *iter;
		const char *s;
		r_list_foreach (r2yara->genstrings, iter, s) {
			r_cons_printf ("    $ = %s\n", s);
		}
		r_cons_printf ("  condition:\n");
		if (amount > 1) {
			r_cons_printf ("    %d of them\n", amount);
		} else {
			r_cons_printf ("    all of them\n");
		}
	}
	r_cons_printf ("}\n");
}

static int cmd_yara_gen(R2Yara *r2yara, const char* input) {
	const char arg0 = input? *input: 0;
	switch (arg0) {
	case 0:
		cmd_yara_gen_show (r2yara, 0);
		break;
	case 's':
		{
			char *s = r_core_cmd_str (r2yara->core, "psz");
			r_str_trim (s);
			char *ss = r_str_newf ("\"%s\"", s);
			r_list_append (r2yara->genstrings, ss);
			free (s);
		}
		break;
	case '-':
		if (input && input[1] == '*') {
			r_list_free (r2yara->genstrings);
			r2yara->genstrings = r_list_newf (free);
		} else {
			char *s = r_list_pop (r2yara->genstrings);
			free (s);
		}
		break;
	case 'x':
		if (input) {
			int len = r_num_math (r2yara->core->num, input + 1);
			char *s = r_core_cmd_strf (r2yara->core, "pcY %d", len);
			r_list_append (r2yara->genstrings, s);
		} else {
			char *s = r_core_cmd_str (r2yara->core, "pcY");
			r_str_trim (s);
			r_list_append (r2yara->genstrings, s);
		}
		break;
	}
	return 0;
}

static int cmd_yara_add(R2Yara *r2yara, const char* input) {
	if (!input) {
		R_LOG_ERROR ("Missing argument");
		return false;
	}
	/* Add a rule with user input */
	YR_COMPILER* compiler = NULL;
	int result, i, continue_edit;

	for (i = 0; input[i]; i++) {
		if (input[i] != ' ') {
			return cmd_yara_add_file (r2yara, input + i);
		}
	}

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		return false;
	}

	char *old_template = strdup (yara_rule_template);
	char *modified_template = NULL;
	do {
		char *modified_template = r_core_editor (r2yara->core, NULL, old_template);
		R_FREE (old_template);
		if (!modified_template) {
			R_LOG_ERROR ("Something bad happened with the temp file");
			goto err_exit;
		}

		result = yr_compiler_add_string (compiler, modified_template, NULL);
		if (result > 0) {
			logerr (compiler, NULL);
			continue_edit = r_cons_yesno ('y', "Do you want to continue editing the rule? [y]/n\n");
			if (!continue_edit) {
				goto err_exit;
			}
			old_template = modified_template;
			modified_template = NULL;
		}
	} while (result > 0);

	free (modified_template);
	if (compiler != NULL) {
		yr_compiler_destroy (compiler);
	}
	R_LOG_INFO ("Rule successfully added");
	return true;

err_exit:
	if (compiler != NULL) {
		yr_compiler_destroy (compiler);
	}
	free (modified_template);
	free (old_template);
	return false;
}

static int cmd_yara_version(R2Yara *r2yara) {
	r_cons_printf ("r2 %s\n", R2_VERSION);
	r_cons_printf ("yara %s\n", YR_VERSION);
	r_cons_printf ("r2yara %s\n", R2Y_VERSION);
	return 0;
}

const char *short_help_message[] = {
	"Usage: yr", "[action] [args..]", " load and run yara rules inside r2",
	"yr", " [file]", "add yara rules from file",
	"yr", "", "same as yr?",
	"yr", "-*", "unload all the rules",
	"yr", "?", "show this help (same as 'yara?')",
	"yrg", "-[*]", "delete last strings/bytes from generated rule or all of them (yr-*)",
	"yrg", "[-sx]", "generate yara rule, add (s)tring or (x)bytes, or (-)pop (-*) delete all",
	"yrl", "", "list loaded rules",
	"yrs", "[q]", "scan the current file, suffix with 'q' for quiet mode",
	"yrt", " ([tagname])", "list tags from loaded rules, or list rules from given tag",
	"yrv", "", "show version information about r2yara and yara",
	NULL
};

const char *long_help_message[] = {
	"Usage: yara", " [action] [args..]", " load and run yara rules inside r2",
	"yara", " add [file]", "Add yara rules from file, or open $EDITOR with yara rule template",
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
	case 'g':
		cmd_yara_gen (r2yara, input + 1);
		break;
	case '+':
	case ' ':
		cmd_yara_add (r2yara, arg);
		break;
	case '-':
		cmd_yara_clear (r2yara);
		break;
	case 't': // "yrs"
		if (input[1]) {
			cmd_yara_tag (r2yara, arg);
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
	YR_COMPILER* compiler = NULL;
	YR_RULES* yr_rules = NULL;
	char* filename;
	char* rules = NULL;
#if R2_VERSION_NUMBER < 50709
	char* y3_rule_dir = r_str_newf ("%s%s%s", r_str_home (R2_HOME_PLUGINS), R_SYS_DIR, "rules-yara3");
#else
	char* y3_rule_dir = r_xdg_datadir ("plugins/rules-yara3");
#endif
	RList* list = r_sys_dir (y3_rule_dir);

	if (yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	yr_compiler_set_callback (compiler, compiler_callback, NULL);

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
			if (yr_compiler_add_string (compiler, rules, rulepath) > 0) {
				logerr (compiler, NULL);
			}
			R_FREE (rules);
		} else {
			R_LOG_ERROR ("cannot load %s", rulepath);
		}
		free (rulepath);
	}
	r_list_free (list);

	if (yr_compiler_get_rules (compiler, &yr_rules) != ERROR_SUCCESS) {
		logerr (compiler, NULL);
		goto err_exit;
	}

	r_list_append (r2yara->rules_list, yr_rules);

	if (compiler) {
		yr_compiler_destroy (compiler);
	}
	return true;

err_exit:
	free (y3_rule_dir);
	if (compiler) {
		yr_compiler_destroy (compiler);
	}
	r_list_free (list);
	free (rules);
	return false;
}

static char *yyyymmdd(void) {
	time_t current_time;
	struct tm *time_info;
	char *ds = calloc (16, 1);

	time (&current_time);
	time_info = localtime (&current_time);

	strftime (ds, 16, "%Y-%m-%d", time_info);
	return ds;
}

static void setup_config(R2Yara *r2yara) {
	RConfig *cfg = r2yara->core->config;
	r_config_lock (cfg, false);
	char *me = r_sys_whoami ();
	r_config_set (cfg, "yara.author", me);
	free (me);
	r_config_set (cfg, "yara.description", "My first yara rule");
	char *ymd = yyyymmdd();
	r_config_set (cfg, "yara.date", ymd);
	free (ymd);
	r_config_set (cfg, "yara.version", "0.1");
	r_config_set (cfg, "yara.rule", "rulename");
	r_config_set (cfg, "yara.tags", "test");
	r_config_set_i (cfg, "yara.amount", 0);
	r_config_lock (cfg, true);
}

static int cmd_yara_init(void *user, const char *cmd) {
	RCmd *rcmd = (RCmd *)user;
	RCore* core = (RCore *)rcmd->data;

	R2Yara *r2yara = &Gr2yara;
	memset (r2yara, 0, sizeof (R2Yara));
	r2yara->iova = true;
	r2yara->core = core;
	r2yara->rules_list = r_list_newf ((RListFree) yr_rules_destroy);
	r2yara->genstrings = r_list_newf (free);

	yr_initialize ();
	setup_config (r2yara);

	cmd_yara_load_default_rules (r2yara);
	r2yara->initialized = true;
	r2yara->flagidx = 0;
	return true;
}

static int cmd_yara_call(void *user, const char *input) {
	RCmd *rcmd = (RCmd *)user;
	RCore* core = (RCore *)rcmd->data;
	R2Yara *r2yara = &Gr2yara;
	if (r_str_startswith (input, "yr")) {
		cmd_yr (r2yara, input + 2);
		return true;
	}
	if (!r_str_startswith (input, "yara")) {
		return false;
	}
	if (!r2yara->initialized) {
		if (!cmd_yara_init (r2yara, NULL)) {
			return false;
		}
	}
	const char *args = input[4]? input + 5: input + 4;
	cmd_yara_process (r2yara, args);
	return true;
}

static int cmd_yara_fini(void *user, const char *cmd) {
	RCmd *rcmd = (RCmd *)user;
	RCore* core = (RCore *)rcmd->data;
	R2Yara *r2yara = &Gr2yara;
	if (r2yara->initialized) {
		r_list_free (r2yara->rules_list);
		r_list_free (r2yara->genstrings);
		yr_finalize ();
		r2yara->initialized = false;
	}
	return true;
}

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
	.call = cmd_yara_call,
	.init = cmd_yara_init,
	.fini = cmd_yara_fini
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_yara,
        .version = R2_VERSION
};
#endif
