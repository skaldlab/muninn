# Shared helpers for Muninn Git hooks (POSIX sh).

# hook_skip returns 0 when the named hook should not run.
# Usage: hook_skip SKIP_PRE_COMMIT
hook_skip() {
	_hook_var=$1
	# shellcheck disable=SC1083,SC2086
	eval "_hook_flag=\${${_hook_var}:-}"
	if [ "$_hook_flag" = "1" ]; then
		return 0
	fi
	if [ -f "$(git rev-parse --git-dir)/MERGE_HEAD" ]; then
		return 0
	fi
	return 1
}

# hook_setup prepares the repo root and Go toolchain for hook work.
hook_setup() {
	root=$(git rev-parse --show-toplevel) || return 1
	cd "$root" || return 1
	export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
	if ! command -v go >/dev/null 2>&1; then
		echo "hook: go not found on PATH" >&2
		return 1
	fi
}

# hook_mktemp creates a temp file portably (macOS + Linux).
hook_mktemp() {
	_hook_prefix=$1
	if _hook_tmp=$(mktemp "${TMPDIR:-/tmp}/${_hook_prefix}.XXXXXX" 2>/dev/null); then
		printf '%s\n' "$_hook_tmp"
		return 0
	fi
	mktemp -t "$_hook_prefix"
}

# staged_go_files writes staged Go source paths (added/copied/modified/renamed).
staged_go_files() {
	git diff --cached --name-only --diff-filter=ACMRTUXB -- '*.go'
}
