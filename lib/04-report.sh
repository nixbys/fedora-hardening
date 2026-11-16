# shellcheck shell=bash
# ---------- Report helpers --------------------------------------------------
# A follow-up for the post-run list, stored as "S<num>|<priority>|<tag>|<description>".
# Usage: add_action_item <section_num> <HIGH|MEDIUM|LOW> <tag> <description>
add_action_item() {
	ACTIONABLE_ITEMS+=("S${1}|${2}|${3}|${4}")
}

# Temp files registered here are removed on exit.
register_tmp() { TEMP_FILES+=("$1"); }
