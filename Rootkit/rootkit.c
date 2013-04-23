#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.H>

static int
load (struct module * module, int cmd, void * arg) {
  int error = 0;

  switch (cmd) {
    case MOD_LOAD:
      uprintf ("Rootkit: Loaded\n");
      break;

    case MOD_UNLOAD:
      uprintf ("Rootkit: Removed\n");
      break;

    default:
      error = EOPNOTSUPP;
      break;
  }

  return error;
}

static moduledata_t rootkit_mod = {
  "rootkit",
  load,
  0
};

DECLARE_MODULE(rootkit, rootkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
