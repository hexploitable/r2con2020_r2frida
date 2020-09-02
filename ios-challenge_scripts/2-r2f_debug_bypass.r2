.\init
\. ./plugins/dia.js
\dia0 ptrace
\di1 getppid
s `\iE libsystem_c.dylib~sysctl:1[0]`
pd 2
wa ret @ $$
pd 2
\di0 strstr
\dc
