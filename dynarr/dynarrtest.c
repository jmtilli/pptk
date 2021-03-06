#include "dynarr.h"

int main(int argc, char **argv)
{
  DYNARR(int) ar = DYNARR_INITER;
  size_t i;
  for (i = 0; i < 32; i++)
  {
    if (!DYNARR_PUSH_BACK(&ar, i))
    {
      abort();
    }
  }
  for (i = 0; i < DYNARR_SIZE(&ar); i++)
  {
    if (DYNARR_GET(&ar, i) != (int)i)
    {
      abort();
    }
  }
  return 0;
}
