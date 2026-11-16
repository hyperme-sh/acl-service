"""Install public frozen runtime dependencies without inherited credentials."""
import os
import subprocess

env = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
           GIT_CONFIG_COUNT='0', GIT_TERMINAL_PROMPT='0',
           GIT_ASKPASS='/bin/false', GIT_SSH_COMMAND='/bin/false')
subprocess.run(['uv', 'sync', '--frozen', '--no-dev', '--no-editable', '--no-cache'], env=env, check=True)
