## What and why

<!-- What changes, and the issue or source it comes from. -->

## Checklist

- [ ] `./tests/run-suite.sh --tier static --tier quick` passes (add `--tier full` when a section changed)
- [ ] Files the script writes go through `backup_file` / `write_new_file`, so `--rollback` undoes them
- [ ] `--dry-run` still changes nothing
- [ ] A new or changed recommendation cites its source (`# Source:`), and its mapping in `fedora/mappings/` still fits
- [ ] CHANGELOG.md and the docs are updated for user-visible changes
