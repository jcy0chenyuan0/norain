@echo off
rem Windows cannot exec a shebang script directly: forward to tests/fakes/sing-box.
rem Arguments are passed through untouched (version / check -c ... / run -c ...).
python "%~dp0sing-box" %*
