/* 最小 SQLite 执行器：给 unlock.sh 写授权表用，避免装 python / sqlite3 CLI。
 *
 * 用法与 sqlite3 CLI 的关键子集兼容：
 *   sqlite3mini [-batch] [-noheader] [-readonly] <db> "<sql>"
 *   sqlite3mini <db> ".backup '<path>'"
 *
 * 只做三件事：执行 SQL 脚本（遇错即停，返回非零）、输出查询结果、备份库。
 */
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int row_cb(void *unused, int argc, char **argv, char **col) {
  (void)unused; (void)col;
  for (int i = 0; i < argc; i++) {
    if (i) putchar('|');
    if (argv[i]) fputs(argv[i], stdout);
  }
  putchar('\n');
  return 0;
}

static int do_backup(sqlite3 *src, const char *path) {
  sqlite3 *dst = NULL;
  int rc = sqlite3_open(path, &dst);
  if (rc != SQLITE_OK) { fprintf(stderr, "cannot open backup: %s\n", path); sqlite3_close(dst); return 1; }
  sqlite3_backup *bk = sqlite3_backup_init(dst, "main", src, "main");
  if (!bk) { fprintf(stderr, "backup init failed\n"); sqlite3_close(dst); return 1; }
  do { rc = sqlite3_backup_step(bk, -1); } while (rc == SQLITE_BUSY || rc == SQLITE_LOCKED);
  sqlite3_backup_finish(bk);
  sqlite3_close(dst);
  return rc == SQLITE_DONE ? 0 : 1;
}

int main(int argc, char **argv) {
  const char *db = NULL, *sql = NULL;
  int ro = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-batch") || !strcmp(argv[i], "-noheader")) continue;
    if (!strcmp(argv[i], "-readonly")) { ro = 1; continue; }
    if (!db) db = argv[i]; else if (!sql) sql = argv[i];
  }
  if (!db) { fprintf(stderr, "usage: sqlite3mini [-readonly] <db> [sql]\n"); return 2; }

  sqlite3 *h = NULL;
  int flags = ro ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
  if (sqlite3_open_v2(db, &h, flags, NULL) != SQLITE_OK) {
    fprintf(stderr, "cannot open database: %s\n", db);
    sqlite3_close(h);
    return 1;
  }
  sqlite3_busy_timeout(h, 30000);

  if (!sql) { const char *buf = NULL; sql = buf; }
  if (!sql) {
    /* 从 stdin 读整段 SQL */
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    int c;
    while ((c = getchar()) != EOF) {
      if (len + 2 > cap) { cap *= 2; buf = realloc(buf, cap); }
      buf[len++] = (char)c;
    }
    buf[len] = 0;
    sql = buf;
  }

  while (*sql == ' ' || *sql == '\n' || *sql == '\t') sql++;

  if (!strncmp(sql, ".backup", 7)) {
    const char *p = sql + 7;
    while (*p == ' ') p++;
    char path[4096]; size_t n = 0;
    char quote = (*p == '\'' || *p == '"') ? *p++ : 0;
    while (*p && (quote ? *p != quote : *p != '\n' && *p != ' ')) {
      if (n + 1 < sizeof(path)) path[n++] = *p;
      p++;
    }
    path[n] = 0;
    int rc = do_backup(h, path);
    sqlite3_close(h);
    return rc;
  }

  /* 去掉 sqlite3 CLI 的 dot 命令行（.bail on 之类），"遇错即停" 由 exec 本身保证 */
  char *clean = malloc(strlen(sql) + 1);
  if (clean) {
    size_t o = 0; int bol = 1;
    for (const char *p = sql; *p; p++) {
      if (bol && *p == '.') { while (*p && *p != '\n') p++; continue; }
      clean[o++] = *p;
      bol = (*p == '\n');
    }
    clean[o] = 0;
    sql = clean;
  }

  char *err = NULL;
  int rc = sqlite3_exec(h, sql, row_cb, NULL, &err);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sql error: %s\n", err ? err : sqlite3_errmsg(h));
    sqlite3_free(err);
    sqlite3_close(h);
    return 1;
  }
  sqlite3_close(h);
  return 0;
}
