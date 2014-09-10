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
oom ()
{
  fprintf (stderr, "Out of memory.\n");
  exit (1);
}


int
main (int argc,
      char **argv)
{
  int res;
  char *executable;
  char **child_argv;
  int i, j, fd, argv_offset;
  int mounted_tmpfs = 0;
  struct loop_info64 loopinfo;
  int loop_fd = -1;
  long offset;
  mode_t old_umask;
  char tmpdir[] = "/tmp/run-app.XXXXXX";
  char buf[1024];
  DIR *dir;
  struct dirent *dirent;
  struct { char *path;  char *target; } symlinks[] = {
    { "lib", "usr/lib" },
    { "bin", "usr/bin" },
    { "sbin", "usr/sbin"},
    { "etc", "usr/etc"},
  };
  char *dont_mounts[] = {"lib", "lib64", "bin", "sbin", "usr", ".", "..", "boot", "tmp", "etc"};
  int pipefd[2];
  pid_t pid;
  char v;

  if (argc < 3)
    {
      fprintf (stderr, "Too few arguments, need runtime and binary\n");
      return 1;
    }

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
   * in case /tmp is mounted shared */
  if (pid == 0)
    {
      char c;
      int r;

      /* In child */

      close (pipefd[WRITE_END]);

      /* Wait for parent */
      if (read (pipefd[READ_END], &c, 1) == 1)
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
      umount (tmpdir);

      exit (1);
    }

  if (chdir (tmpdir) != 0)
      fail ("chdir");

  if (mkdir ("usr", 0755) != 0)
    fail ("mkdir usr");

  if (mkdir ("tmp", 01777) != 0)
    fail ("mkdir tmp");

  if (mount (argv[1], "usr",
             NULL, MS_BIND|MS_MGC_VAL|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
    fail ("mount usr");

  /* Its now mounted private inside the namespace, tell child process to unmount it in the parent namespace. */
  v = 1;
  write (pipefd[1], &v, 1);
  close (pipefd[WRITE_END]);

  for (i = 0; i < N_ELEMENTS(symlinks); i++)
    {
      if (symlink (symlinks[i].target, symlinks[i].path) != 0)
        fail ("symlinks");
    }

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
      while (dirent = readdir(dir))
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

  executable = argv[2];
  argv_offset = 3;

  child_argv = malloc ((1 + argc - argv_offset + 1) * sizeof (char *));
  if (child_argv == NULL)
    oom();

  j = 0;
  child_argv[j++] = argv[0];
  for (i = argv_offset; i < argc; i++)
    child_argv[j++] = argv[i];
  child_argv[j++] = NULL;

  __debug__(("launch executable %s\n", executable));
  return execvp (executable, child_argv);
}
