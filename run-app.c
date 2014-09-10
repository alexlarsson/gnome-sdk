#define _GNU_SOURCE /* Required for CLONE_NEWNS */
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
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

void
usage (char **argv)
{
  fprintf (stderr, "usage: %s [-a <path to app>] <path to runtime> <command..>", argv[0]);
  exit (1);
}

int
main (int argc,
      char **argv)
{
  int res;
  int i;
  mode_t old_umask;
  char tmpdir[] = "/tmp/run-app.XXXXXX";
  DIR *dir;
  struct dirent *dirent;
  struct { char *name;  mode_t mode; } dirs[] = {
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
  pid_t pid;
  char *runtime_path = NULL;
  char *app_path = NULL;
  char **args;
  int n_args;

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

  __debug__(("Createing tmp dir\n"));

  if (mkdtemp (tmpdir) == NULL)
    fail ("Creating temporary directory failed");

  if (chown (tmpdir, getuid (), getuid ()) != 0)
      fail ("Chowning temporary directory failed");

  if (pipe (pipefd) != 0)
    fail ("pipe failed");

  pid = fork();
  if (pid == -1)
    fail ("fork failed");

  /* When mounted private in child, make sure its not mounted in the parent,
   * in case /tmp is mounted shared, or of we exit on error */
  if (pid == 0)
    {
      char c;

      /* In child */
      close (pipefd[WRITE_END]);

      /* Don't die when the parent closes pipe */
      signal (SIGPIPE, SIG_IGN);

      /* Wait for parent */
      read (pipefd[READ_END], &c, 1);

      umount2 (tmpdir, MNT_DETACH);

      exit (0);
    }

  close (pipefd[READ_END]);

  __debug__(("creating new namespace\n"));
  res = unshare (CLONE_NEWNS);
  if (res != 0)
    fail ("Creating new namespace failed");

  old_umask = umask (0);

  /* Create a tmpfs which we will use as / in the namespace */
  if (mount ("", tmpdir, "tmpfs", MS_NODEV|MS_NOEXEC, NULL) != 0)
    fail ("Failed to mount tmpfs");

  /* make it rprivate so the parent namespace can't see it */
  if (mount (tmpdir, tmpdir,
             NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    {
      perror ("Failed to make private");

      exit (1);
    }

  if (chdir (tmpdir) != 0)
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
             NULL, MS_BIND|MS_MGC_VAL|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
    fail ("mount usr");

  if (mount ("usr", "usr",
             NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    fail ("mount usr private");

  if (app_path != NULL)
    {
      if (mount (app_path, "self",
                 NULL, MS_BIND|MS_MGC_VAL|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
        fail ("mount self");

      if (mount ("self", "self",
                 NULL, MS_REC|MS_PRIVATE, NULL) != 0)
        fail ("mount self private");
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
          char path[1024];
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

          strcpy (path, "/");
          strncat (path, dirent->d_name, sizeof(path));

          if (stat (path, &st) != 0)
            continue;

          if (S_ISDIR(st.st_mode))
            {
              if (mkdir (dirent->d_name, 0755) != 0)
                fail (dirent->d_name);

              if (mount (path, dirent->d_name,
                         NULL, MS_BIND|MS_REC|MS_MGC_VAL|MS_NOSUID, NULL) != 0)
                fail ("mount root subdir");
            }
        }
    }

  chroot (tmpdir);

  umask (old_umask);

  /* Now we have everything we need CAP_SYS_ADMIN for, so drop setuid */
  setuid (getuid ());

  setenv ("PATH", "/self/bin:/usr/bin", 1);
  setenv ("LD_LIBRARY_PATH", "/self/lib", 1);
  setenv ("XDG_CONFIG_DIRS","/self/etc/xdg:/etc/xdg", 1);
  setenv ("XDG_DATA_DIRS", "/self/share:/usr/share", 1);

  __debug__(("launch executable %s\n", args[0]));

  return execvp (args[0], args);
}
