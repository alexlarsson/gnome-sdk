#define _GNU_SOURCE /* Required for CLONE_NEWNS */
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <stdarg.h>

#if 0
#define __debug__(x) printf x
#else
#define __debug__(x)
#endif

#ifndef MS_PRIVATE      /* May not be defined in older glibc headers */
#define MS_PRIVATE (1<<18) /* change to private */
#endif

#define RUNTIME_PREFIX "/usr"

#define N_ELEMENTS(arr)		(sizeof (arr) / sizeof ((arr)[0]))
#define READ_END 0
#define WRITE_END 1

void
fail (char *str)
{
  perror (str);
  exit (1);
}

static void
die (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);
  exit (1);
}

static void *
xmalloc (size_t size)
{
  void *res = malloc (size);
  if (res == NULL)
    die ("oom");
  return res;
}

char *
strconcat (const char *s1,
           const char *s2)
{
  size_t len = 0;
  char *res;

  if (s1)
    len += strlen (s1);
  if (s2)
    len += strlen (s2);

  res = xmalloc (len + 1);
  *res = 0;
  if (s1)
    strcat (res, s1);
  if (s2)
    strcat (res, s2);

  return res;
}

void
usage (char **argv)
{
  fprintf (stderr, "usage: %s [-a <path to app>] <path to runtime> <command..>\n", argv[0]);
  exit (1);
}

static int
pivot_root (const char * new_root, const char * put_old)
{
#ifdef __NR_pivot_root
  return syscall(__NR_pivot_root, new_root, put_old);
#else
  errno = ENOSYS;
  return -1;
#endif
}

int
main (int argc,
      char **argv)
{
  int res;
  int i;
  mode_t old_umask;
  char tmpdir[] = "/tmp/run-app.XXXXXX";
  char *newroot;
  DIR *dir;
  struct dirent *dirent;
  struct { char *name;  mode_t mode; } dirs[] = {
    { ".oldroot", 0755 },
    { "usr", 0755 },
    { "tmp", 01777 },
    { "self", 0755},
  };
  struct { char *path;  char *target; } symlinks[] = {
    { "lib", "usr/lib" },
    { "bin", "usr/bin" },
    { "sbin", "usr/sbin"},
    { "etc", "usr/etc"},
  };
  char *dont_mounts[] = {"lib", "lib64", "bin", "sbin", "usr", ".", "..", "boot", "tmp", "etc", "self"};
  int pipefd[2];
  uid_t saved_euid;
  pid_t pid;
  char *runtime_path = NULL;
  char *app_path = NULL;
  char **args;
  int n_args;
  char old_cwd[256];

  args = &argv[1];
  n_args = argc - 1;

  while (n_args > 0 && args[0][0] == '-')
    {
      switch (args[0][1])
        {
        case 'a':
          if (n_args < 2)
              usage (argv);

          app_path = args[1];
          args += 2;
          n_args -= 2;
          break;

        default:
          usage (argv);
        }
    }

  if (n_args < 2)
    usage (argv);

  runtime_path = args[0];
  args++;
  n_args--;

  /* The initial code is run with a high permission euid
     (at least CAP_SYS_ADMIN), so take lots of care. */

  __debug__(("Creating temporary dir\n"));

  saved_euid = geteuid ();

  /* First switch to the real user id so we can have the
     temp directories owned by the user */

  if (seteuid (getuid ()))
    fail ("seteuid to user");

  if (mkdtemp (tmpdir) == NULL)
    fail ("Creating temporary directory failed");

  newroot = strconcat (tmpdir, "/root");

  if (mkdir (newroot, 0755))
    fail ("Creating new root failed");

  /* Now switch back to the root user */
  if (seteuid (saved_euid))
    fail ("seteuid to privileged");

  /* We want to make the temp directory a bind mount so that
     we can ensure that it is MS_PRIVATE, so mount don't leak out
     of the namespace, and also so that pivot_root() succeeds. However
     this means if /tmp is MS_SHARED the bind-mount will be propagated
     to the parent namespace. In order to handle this we spawn a child
     in the original namespace and unmount the bind mount from that at
     the right time. */

  if (pipe (pipefd) != 0)
    fail ("pipe failed");

  pid = fork();
  if (pid == -1)
    fail ("fork failed");

  if (pid == 0)
    {
      char c;

      /* In child */
      close (pipefd[WRITE_END]);

      /* Don't die when the parent closes pipe */
      signal (SIGPIPE, SIG_IGN);

      /* Wait for parent */
      read (pipefd[READ_END], &c, 1);

      /* Unmount tmpdir bind mount */
      umount2 (tmpdir, MNT_DETACH);

      exit (0);
    }

  close (pipefd[READ_END]);

  __debug__(("creating new namespace\n"));
  res = unshare (CLONE_NEWNS);
  if (res != 0)
    fail ("Creating new namespace failed");

  old_umask = umask (0);

  /* make it tmpdir rprivate to avoid leaking mounts */
  if (mount (tmpdir, tmpdir, NULL, MS_BIND, NULL) != 0)
    fail ("Failed to make bind mount on tmpdir");
  if (mount (tmpdir, tmpdir, NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    fail ("Failed to make tmpdir rprivate");

  /* Create a tmpfs which we will use as / in the namespace */
  if (mount ("", newroot, "tmpfs", MS_NODEV|MS_NOEXEC, NULL) != 0)
    fail ("Failed to mount tmpfs");

  getcwd (old_cwd, sizeof (old_cwd));

  if (chdir (newroot) != 0)
      fail ("chdir");

  for (i = 0; i < N_ELEMENTS(dirs); i++)
    {
      if (mkdir (dirs[i].name, dirs[i].mode) != 0)
        fail ("dirs");
    }

  for (i = 0; i < N_ELEMENTS(symlinks); i++)
    {
      if (symlink (symlinks[i].target, symlinks[i].path) != 0)
        fail ("symlinks");
    }

  if (mount (runtime_path, "usr",
             NULL, MS_MGC_VAL|MS_BIND, NULL) != 0)
    fail ("mount usr");

  if (mount ("none", "usr",
             NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    fail ("mount usr private");

  if (mount ("none", "usr",
             NULL, MS_MGC_VAL|MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
    fail ("mount usr readonly");

  if (app_path != NULL)
    {
      if (mount (app_path, "self",
                 NULL, MS_MGC_VAL|MS_BIND, NULL) != 0)
        fail ("mount self");

      if (mount ("none", "self",
                 NULL, MS_REC|MS_PRIVATE, NULL) != 0)
        fail ("mount self private");

      if (mount ("none", "self",
                 NULL, MS_MGC_VAL|MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
        fail ("mount self readonly");
    }

  /* /usr now mounted private inside the namespace, tell child process to unmount the tmpfs in the parent namespace. */
  close (pipefd[WRITE_END]);

  if (mount ("/etc/passwd", "etc/passwd",
             NULL, MS_BIND|MS_MGC_VAL|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
    fail ("mount passwd");

  if (mount ("/etc/group", "etc/group",
             NULL, MS_BIND|MS_MGC_VAL|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
    fail ("mount group");

  /* Bind mount most dirs in / into the new root */
  dir = opendir("/");
  if (dir != NULL)
    {
      while ((dirent = readdir(dir)))
        {
          int dont_mount = 0;
          char *path;
          struct stat st;

          for (i = 0; i < N_ELEMENTS(dont_mounts); i++)
            {
              if (strcmp (dirent->d_name, dont_mounts[i]) == 0)
                {
                  dont_mount = 1;
                  break;
                }
            }

          if (dont_mount)
            continue;

          path = strconcat ("/", dirent->d_name);

          if (stat (path, &st) != 0)
            {
              free (path);
              continue;
            }

          if (S_ISDIR(st.st_mode))
            {
              if (mkdir (dirent->d_name, 0755) != 0)
                fail (dirent->d_name);

              if (mount (path, dirent->d_name,
                         NULL, MS_BIND|MS_REC|MS_MGC_VAL|MS_NOSUID, NULL) != 0)
                fail ("mount root subdir");
            }

          free (path);
        }
    }

  if (pivot_root (newroot, ".oldroot"))
    fail ("pivot_root");

  chdir ("/");

  /* The old root better be rprivate or we will send unmount events to the parent namespace */
  if (mount (".oldroot", ".oldroot", NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    fail ("Failed to make old root rprivate");

  if (umount2 (".oldroot", MNT_DETACH))
    fail ("unmount oldroot");

  umask (old_umask);

  /* Now we have everything we need CAP_SYS_ADMIN for, so drop setuid */
  setuid (getuid ());

  chdir (old_cwd);

  setenv ("PATH", "/self/bin:/usr/bin", 1);
  setenv ("LD_LIBRARY_PATH", "/self/lib", 1);
  setenv ("XDG_CONFIG_DIRS","/self/etc/xdg:/etc/xdg", 1);
  setenv ("XDG_DATA_DIRS", "/self/share:/usr/share", 1);

  __debug__(("launch executable %s\n", args[0]));

  return execvp (args[0], args);
}
