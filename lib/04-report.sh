# shellcheck shell=bash
# ---------- Report helpers --------------------------------------------------
# add_action_item() - Register a finding for the post-run actionable list.
# Format stored in ACTIONABLE_ITEMS: "S<num>|<priority>|<tag>|<description>"
# Usage: add_action_item <section_num> <priority: HIGH|MEDIUM|LOW> <tag> <desc>
add_action_item() {
	ACTIONABLE_ITEMS+=("S${1}|${2}|${3}|${4}")
}

# register_tmp() - Track a temp file path for guaranteed cleanup on EXIT.
# Usage: register_tmp <path>
register_tmp() { TEMP_FILES+=("$1"); }
