// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/binfmt_script.c
 *
 *  Copyright (C) 1996  Martin von Löwis
 *  original #!-checking implemented by tytso.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/binfmts.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/slab.h>

static inline bool spacetab(char c) { return c == ' ' || c == '\t'; }

static const char origin_prefix[] = "${ORIGIN}/";
#define ORIGIN_PREFIX_LEN (sizeof(origin_prefix) - 1)

/*
 * If the interpreter path starts with `origin_prefix`, expand it to the directory
 * containing the script, mirroring `${ORIGIN}` expansion in ELF RPATH/RUNPATH.
 * Resolves symlinks in the script path via bprm->file, matching ELF $ORIGIN semantics.
 * Returns a kmalloc'd string on success, ERR_PTR on failure.
 */
static char *expand_origin(const char *interp, struct linux_binprm *bprm)
{
	const char *last_slash, *suffix;
	char *path_buf, *real_path, *result;
	size_t dir_len, suffix_len, result_len;

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf)
		return ERR_PTR(-ENOMEM);

	real_path = file_path(bprm->file, path_buf, PATH_MAX);
	if (IS_ERR(real_path)) {
		kfree(path_buf);
		return ERR_CAST(real_path);
	}

	last_slash = strrchr(real_path, '/');
	dir_len = last_slash ? last_slash - real_path : 0;

	suffix = interp + ORIGIN_PREFIX_LEN;
	suffix_len = strlen(suffix);
	result_len = dir_len + 1 + suffix_len + 1;

	if (result_len > PATH_MAX) {
		kfree(path_buf);
		return ERR_PTR(-ENAMETOOLONG);
	}

	result = kmalloc(result_len, GFP_KERNEL);
	if (!result) {
		kfree(path_buf);
		return ERR_PTR(-ENOMEM);
	}

	memcpy(result, real_path, dir_len);
	result[dir_len] = '/';
	memcpy(result + dir_len + 1, suffix, suffix_len + 1);

	kfree(path_buf);
	return result;
}

static inline const char *next_non_spacetab(const char *first, const char *last)
{
	for (; first <= last; first++)
		if (!spacetab(*first))
			return first;
	return NULL;
}
static inline const char *next_terminator(const char *first, const char *last)
{
	for (; first <= last; first++)
		if (spacetab(*first) || !*first)
			return first;
	return NULL;
}

static int load_script(struct linux_binprm *bprm)
{
	const char *i_name, *i_sep, *i_arg, *i_end, *buf_end;
	char *i_name_buf = NULL;
	struct file *file;
	int retval;

	/* Not ours to exec if we don't start with "#!". */
	if ((bprm->buf[0] != '#') || (bprm->buf[1] != '!'))
		return -ENOEXEC;

	/*
	 * This section handles parsing the #! line into separate
	 * interpreter path and argument strings. We must be careful
	 * because bprm->buf is not yet guaranteed to be NUL-terminated
	 * (though the buffer will have trailing NUL padding when the
	 * file size was smaller than the buffer size).
	 *
	 * We do not want to exec a truncated interpreter path, so either
	 * we find a newline (which indicates nothing is truncated), or
	 * we find a space/tab/NUL after the interpreter path (which
	 * itself may be preceded by spaces/tabs). Truncating the
	 * arguments is fine: the interpreter can re-read the script to
	 * parse them on its own.
	 */
	buf_end = bprm->buf + sizeof(bprm->buf) - 1;
	i_end = strnchr(bprm->buf, sizeof(bprm->buf), '\n');
	if (!i_end) {
		i_end = next_non_spacetab(bprm->buf + 2, buf_end);
		if (!i_end)
			return -ENOEXEC; /* Entire buf is spaces/tabs */
		/*
		 * If there is no later space/tab/NUL we must assume the
		 * interpreter path is truncated.
		 */
		if (!next_terminator(i_end, buf_end))
			return -ENOEXEC;
		i_end = buf_end;
	}
	/* Trim any trailing spaces/tabs from i_end */
	while (spacetab(i_end[-1]))
		i_end--;

	/* Skip over leading spaces/tabs */
	i_name = next_non_spacetab(bprm->buf+2, i_end);
	if (!i_name || (i_name == i_end))
		return -ENOEXEC; /* No interpreter name found */

	/* Is there an optional argument? */
	i_arg = NULL;
	i_sep = next_terminator(i_name, i_end);
	if (i_sep && (*i_sep != '\0'))
		i_arg = next_non_spacetab(i_sep, i_end);

	/*
	 * If the script filename will be inaccessible after exec, typically
	 * because it is a "/dev/fd/<fd>/.." path against an O_CLOEXEC fd, give
	 * up now (on the assumption that the interpreter will want to load
	 * this file).
	 */
	if (bprm->interp_flags & BINPRM_FLAGS_PATH_INACCESSIBLE)
		return -ENOENT;

	/*
	 * OK, we've parsed out the interpreter name and
	 * (optional) argument.
	 * Splice in (1) the interpreter's name for argv[0]
	 *           (2) (optional) argument to interpreter
	 *           (3) filename of shell script (replace argv[0])
	 *
	 * This is done in reverse order, because of how the
	 * user environment and arguments are stored.
	 */
	retval = remove_arg_zero(bprm);
	if (retval)
		return retval;
	retval = copy_string_kernel(bprm->interp, bprm);
	if (retval < 0)
		return retval;
	bprm->argc++;
	*((char *)i_end) = '\0';
	if (i_arg) {
		*((char *)i_sep) = '\0';
		retval = copy_string_kernel(i_arg, bprm);
		if (retval < 0)
			return retval;
		bprm->argc++;
	}
	if (strncmp(i_name, origin_prefix, ORIGIN_PREFIX_LEN) == 0) {
		i_name_buf = expand_origin(i_name, bprm);
		if (IS_ERR(i_name_buf))
			return PTR_ERR(i_name_buf);
		i_name = i_name_buf;
	}

	retval = copy_string_kernel(i_name, bprm);
	if (retval)
		goto out;
	bprm->argc++;
	retval = bprm_change_interp(i_name, bprm);
	if (retval < 0)
		goto out;

	/*
	 * OK, now restart the process with the interpreter's dentry.
	 */
	file = open_exec(i_name);
	if (IS_ERR(file)) {
		retval = PTR_ERR(file);
		goto out;
	}

	bprm->interpreter = file;
	retval = 0;
out:
	kfree(i_name_buf);
	return retval;
}

static struct linux_binfmt script_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_script,
};

static int __init init_script_binfmt(void)
{
	register_binfmt(&script_format);
	return 0;
}

static void __exit exit_script_binfmt(void)
{
	unregister_binfmt(&script_format);
}

core_initcall(init_script_binfmt);
module_exit(exit_script_binfmt);
MODULE_DESCRIPTION("Kernel support for scripts starting with #!");
MODULE_LICENSE("GPL");
