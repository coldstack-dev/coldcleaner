# Coldcleaner design goals

Coldcleaner keeps disk space available for builds and everyday work. It shows what it can reclaim, which files need a decision, and how to recover archived files.

1. Preview cleanup by default. Apply changes only when explicitly requested, and only to paths covered by the rules.
2. Protect in-use files, unpublished work, and paths marked to keep. Archive unique data and verify the copy before removing the source.
3. Measure free space and the size of managed data separately. Report why items were held, and keep host failures visible while checking healthy hosts.
4. Track reclaimed space, unresolved holds, and restore outcomes. Use restore drills to check that archive contents can be recovered.
