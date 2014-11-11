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

#define N_ELEMENTS(arr)		(sizeof (arr) / sizeof ((arr)[0]))

#define READ_END 0
#define WRITE_END 1

static void
die_with_error (const char *format, ...)
{
  va_list args;
  int errsv;

  errsv = errno;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fprintf (stderr, ": %s\n", strerror (errsv));

  exit (1);
}

static void
die (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fprintf (stderr, "\n");

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

char*
strdup_printf (const char *format,
               ...)
{
  char *buffer = NULL;
  va_list args;

  va_start (args, format);
  vasprintf (&buffer, format, args);
  va_end (args);

  if (buffer == NULL)
    die ("oom");

  return buffer;
}

void
usage (char **argv)
{
  fprintf (stderr, "usage: %s [-w] [-W] [-a <path to app>] [-v <path to var>] <path to runtime> <command..>\n", argv[0]);
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

typedef enum {
  FILE_TYPE_REGULAR,
  FILE_TYPE_DIR,
  FILE_TYPE_SYMLINK,
  FILE_TYPE_BIND,
  FILE_TYPE_BIND_RO,
  FILE_TYPE_MOUNT,
  FILE_TYPE_DEVICE,
} file_type_t;

typedef enum {
  FILE_FLAGS_NONE = 0,
  FILE_FLAGS_USER_OWNED = 1 << 0,
  FILE_FLAGS_NON_FATAL = 1 << 1,
} file_flags_t;

int
main (int argc,
      char **argv)
{
  int res;
  int i;
  mode_t old_umask;
  char *newroot;
  DIR *dir;
  struct dirent *dirent;
  int pipefd[2];
  uid_t saved_euid;
  pid_t pid;
  char *runtime_path = NULL;
  char *app_path = NULL;
  char *var_path = NULL;
  char **args;
  int n_args;
  int writable = 0;
  int writable_app = 0;
  char old_cwd[256];

  char tmpdir[] = "/tmp/run-app.XXXXXX";
  static const struct {
    file_type_t type;
    const char *name;
    mode_t mode;
    const char *data;
    file_flags_t flags;
  } create[] = {
    { FILE_TYPE_DIR, ".oldroot", 0755 },
    { FILE_TYPE_DIR, "usr", 0755 },
    { FILE_TYPE_DIR, "tmp", 01777 },
    { FILE_TYPE_DIR, "self", 0755},
    { FILE_TYPE_DIR, "run", 0755},
    { FILE_TYPE_DIR, "run/user", 0755},
    { FILE_TYPE_DIR, "run/user/%1$d", 0700, NULL, FILE_FLAGS_USER_OWNED },
    { FILE_TYPE_DIR, "var", 0755},
    { FILE_TYPE_SYMLINK, "var/tmp", 0755, "/tmp"},
    { FILE_TYPE_SYMLINK, "lib", 0755, "usr/lib"},
    { FILE_TYPE_SYMLINK, "bin", 0755, "usr/bin" },
    { FILE_TYPE_SYMLINK, "sbin", 0755, "usr/sbin"},
    { FILE_TYPE_SYMLINK, "etc", 0755, "usr/etc"},
    { FILE_TYPE_DIR, "tmp/.X11-unix", 0755 },
    { FILE_TYPE_REGULAR, "tmp/.X11-unix/X0", 0755 },
    { FILE_TYPE_BIND, "tmp/.X11-unix/X0", 0755, "/tmp/.X11-unix/X0"},
    { FILE_TYPE_DIR, "proc", 0755},
    { FILE_TYPE_MOUNT, "proc"},
    { FILE_TYPE_BIND_RO, "proc/sys", 0755, "proc/sys"},
    { FILE_TYPE_DIR, "sys", 0755},
    { FILE_TYPE_MOUNT, "sys"},
    { FILE_TYPE_DIR, "dev", 0755},
    { FILE_TYPE_MOUNT, "dev"},
    { FILE_TYPE_DIR, "dev/pts", 0755},
    { FILE_TYPE_MOUNT, "dev/pts"},
    { FILE_TYPE_DIR, "dev/shm", 0755},
    { FILE_TYPE_MOUNT, "dev/shm"},
    { FILE_TYPE_DEVICE, "dev/null", S_IFCHR|0666, "/dev/null"},
    { FILE_TYPE_DEVICE, "dev/zero", S_IFCHR|0666, "/dev/zero"},
    { FILE_TYPE_DEVICE, "dev/full", S_IFCHR|0666, "/dev/full"},
    { FILE_TYPE_DEVICE, "dev/random", S_IFCHR|0666, "/dev/random"},
    { FILE_TYPE_DEVICE, "dev/urandom", S_IFCHR|0666, "/dev/urandom"},
    { FILE_TYPE_DEVICE, "dev/tty", S_IFCHR|0666, "/dev/tty"},
    { FILE_TYPE_DIR, "dev/dri", 0755},
    { FILE_TYPE_BIND, "dev/dri", 0755, "/dev/dri", FILE_FLAGS_NON_FATAL},
  };

  static const struct {
    const char *what;
    const char *where;
    const char *type;
    const char *options;
    unsigned long flags;
  }  mount_table[] = {
    { "proc",      "proc",     "proc",  NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV           },
    { "sysfs",     "sys",      "sysfs", NULL,        MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV },
    { "tmpfs",     "dev",      "tmpfs", "mode=755",  MS_NOSUID|MS_STRICTATIME               },
    { "devpts",    "dev/pts",  "devpts","newinstance,ptmxmode=0666,mode=620,gid=5", MS_NOSUID|MS_NOEXEC },
    { "tmpfs",     "dev/shm",  "tmpfs", "mode=1777", MS_NOSUID|MS_NODEV|MS_STRICTATIME      },
  };

  char *dont_mounts[] = {
    ".", "..", "lib", "lib64", "bin", "sbin", "usr", "boot",
    "tmp", "etc", "self", "run", "proc", "sys", "dev", "var"
  };

  args = &argv[1];
  n_args = argc - 1;

  while (n_args > 0 && args[0][0] == '-')
    {
      switch (args[0][1])
        {
        case 'W':
          writable = 1;
          args += 1;
          n_args -= 1;
          break;

        case 'w':
          writable_app = 1;
          args += 1;
          n_args -= 1;
          break;

        case 'a':
          if (n_args < 2)
              usage (argv);

          app_path = args[1];
          args += 2;
          n_args -= 2;
          break;

        case 'v':
          if (n_args < 2)
              usage (argv);

          var_path = args[1];
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
    die_with_error ("seteuid to user");

  if (mkdtemp (tmpdir) == NULL)
    die_with_error ("Creating %s", tmpdir);

  newroot = strconcat (tmpdir, "/root");

  if (mkdir (newroot, 0755))
    die_with_error ("Creating new root failed");

  /* Now switch back to the root user */
  if (seteuid (saved_euid))
    die_with_error ("seteuid to privileged");

  /* We want to make the temp directory a bind mount so that
     we can ensure that it is MS_PRIVATE, so mount don't leak out
     of the namespace, and also so that pivot_root() succeeds. However
     this means if /tmp is MS_SHARED the bind-mount will be propagated
     to the parent namespace. In order to handle this we spawn a child
     in the original namespace and unmount the bind mount from that at
     the right time. */

  if (pipe (pipefd) != 0)
    die_with_error ("pipe failed");

  pid = fork();
  if (pid == -1)
    die_with_error ("fork failed");

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
    die_with_error ("Creating new namespace failed");

  old_umask = umask (0);

  /* make it tmpdir rprivate to avoid leaking mounts */
  if (mount (tmpdir, tmpdir, NULL, MS_BIND, NULL) != 0)
    die_with_error ("Failed to make bind mount on tmpdir");
  if (mount (tmpdir, tmpdir, NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    die_with_error ("Failed to make tmpdir rprivate");

  /* Create a tmpfs which we will use as / in the namespace */
  if (mount ("", newroot, "tmpfs", MS_NODEV|MS_NOEXEC|MS_NOSUID, NULL) != 0)
    die_with_error ("Failed to mount tmpfs");

  getcwd (old_cwd, sizeof (old_cwd));

  if (chdir (newroot) != 0)
      die_with_error ("chdir");

  for (i = 0; i < N_ELEMENTS(create); i++)
    {
      int fd;
      char *name = strdup_printf (create[i].name, getuid());
      mode_t mode = create[i].mode;
      const char *data = create[i].data;
      file_flags_t flags = create[i].flags;
      struct stat st;
      int k;
      int found;

      switch (create[i].type)
        {
        case FILE_TYPE_DIR:
          if (mkdir (name, mode) != 0)
            die_with_error ("creating dir %s", name);
          break;

        case FILE_TYPE_REGULAR:
          fd = creat (name, mode);
          if (fd == -1)
            die_with_error ("creating file %s", name);
          close (fd);
          break;

        case FILE_TYPE_SYMLINK:
          if (symlink (data, name) != 0)
            die_with_error ("creating symlink %s", name);
          break;

        case FILE_TYPE_BIND:
        case FILE_TYPE_BIND_RO:
          if (mount (data, name, NULL, MS_MGC_VAL|MS_BIND, NULL) != 0)
            {
              if ((flags & FILE_FLAGS_NON_FATAL) == 0)
                die_with_error ("mounting bindmount %s", name);
            }
          else if (create[i].type == FILE_TYPE_BIND_RO)
            {
              if (mount ("none", name,
                         NULL, MS_MGC_VAL|MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) != 0)
                die_with_error ("making bindmount %s readonly", name);
            }

          break;

        case FILE_TYPE_MOUNT:
          found = 0;
          for (k = 0; k < N_ELEMENTS(mount_table); k++)
            {
              if (strcmp (mount_table[k].where, name) == 0)
                {
                  if (mount(mount_table[k].what,
                            mount_table[k].where,
                            mount_table[k].type,
                            mount_table[k].flags,
                            mount_table[k].options) < 0)
                    die_with_error ("Mounting %s", name);
                  found = 1;
                }
            }

          if (!found)
            die ("Unable to find mount %s\n", name);

          break;

        case FILE_TYPE_DEVICE:
          if (stat (data, &st) < 0)
            die_with_error ("stat node %s", data);

          if (!S_ISCHR (st.st_mode) && !S_ISBLK (st.st_mode))
            die_with_error ("node %s is not a device", data);

          if (mknod (name, mode, st.st_rdev) < 0)
            die_with_error ("mknod %s", name);

          break;

        default:
          die ("Unknown create type %d\n", create[i].type);
        }

      if (flags & FILE_FLAGS_USER_OWNED)
        {
          if (chown (name, getuid(), -1))
            die_with_error ("chown to user");
        }

      free (name);
    }

  if (mount (runtime_path, "usr",
             NULL, MS_MGC_VAL|MS_BIND, NULL) != 0)
    die_with_error ("mount usr");

  if (mount ("none", "usr",
             NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    die_with_error ("mount usr private");

  if (mount ("none", "usr",
             NULL, MS_MGC_VAL|MS_BIND|MS_REMOUNT|MS_NODEV|MS_NOSUID|(writable?0:MS_RDONLY), NULL) != 0)
    die_with_error ("mount usr readonly");

  if (app_path != NULL)
    {
      if (mount (app_path, "self",
                 NULL, MS_MGC_VAL|MS_BIND, NULL) != 0)
        die_with_error ("mount self");

      if (mount ("none", "self",
                 NULL, MS_REC|MS_PRIVATE, NULL) != 0)
        die_with_error ("mount self private");

      if (mount ("none", "self",
                 NULL, MS_MGC_VAL|MS_BIND|MS_REMOUNT|MS_NODEV|MS_NOSUID|(writable_app?0:MS_RDONLY), NULL) != 0)
        die_with_error ("mount self readonly");
    }

  if (var_path != NULL)
    {
      if (mount (var_path, "var",
                 NULL, MS_MGC_VAL|MS_BIND, NULL) != 0)
        die_with_error ("mount self");

      if (mount ("none", "var",
                 NULL, MS_REC|MS_PRIVATE, NULL) != 0)
        die_with_error ("mount self private");

      if (mount ("none", "self",
                 NULL, MS_MGC_VAL|MS_BIND|MS_REMOUNT|MS_NODEV|MS_NOSUID, NULL) != 0)
        die_with_error ("mount self readonly");
    }

  /* /usr now mounted private inside the namespace, tell child process to unmount the tmpfs in the parent namespace. */
  close (pipefd[WRITE_END]);

  if (mount ("/etc/passwd", "etc/passwd",
             NULL, MS_BIND|MS_MGC_VAL|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
    die_with_error ("mount passwd");

  if (mount ("/etc/group", "etc/group",
             NULL, MS_BIND|MS_MGC_VAL|MS_RDONLY|MS_NODEV|MS_NOSUID, NULL) != 0)
    die_with_error ("mount group");

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
                die_with_error (dirent->d_name);

              if (mount (path, dirent->d_name,
                         NULL, MS_BIND|MS_REC|MS_MGC_VAL|MS_NOSUID, NULL) != 0)
                die_with_error ("mount root subdir %s", dirent->d_name);
            }

          free (path);
        }
    }

  if (pivot_root (newroot, ".oldroot"))
    die_with_error ("pivot_root");

  chdir ("/");

  /* The old root better be rprivate or we will send unmount events to the parent namespace */
  if (mount (".oldroot", ".oldroot", NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    die_with_error ("Failed to make old root rprivate");

  if (umount2 (".oldroot", MNT_DETACH))
    die_with_error ("unmount oldroot");

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
