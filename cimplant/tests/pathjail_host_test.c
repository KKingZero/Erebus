/* Host unit tests for path jail pure validators (no Windows APIs). */
#include <stdio.h>
#include <string.h>

#include "erebus/pathjail.h"

/* Compile pathjail.c with -DEREBUS_PATHJAIL_HOST_TEST and link pure helpers. */

static int fails;

static void expect_true(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

static void expect_false(const char *name, int cond) {
    expect_true(name, !cond);
}

int main(void) {
    expect_false("rel notes", erebus_path_is_absolute("notes.txt"));
    expect_false("rel nested", erebus_path_is_absolute("data\\file.bin"));
    expect_true("unix abs", erebus_path_is_absolute("/etc/passwd"));
    expect_true("win drive", erebus_path_is_absolute("C:\\Windows\\system32"));
    expect_true("win root slash", erebus_path_is_absolute("\\Windows"));
    expect_true("unc", erebus_path_is_absolute("\\\\server\\share"));

    expect_false("no escape rel", erebus_path_has_dotdot_escape("notes.txt"));
    expect_false("no escape nested", erebus_path_has_dotdot_escape("data\\file.bin"));
    expect_false("dot segment ok", erebus_path_has_dotdot_escape("foo\\.\\bar"));
    expect_true("parent alone", erebus_path_has_dotdot_escape(".."));
    expect_true("parent prefix", erebus_path_has_dotdot_escape("..\\secret"));
    expect_true("nested escape", erebus_path_has_dotdot_escape("sub\\..\\..\\etc\\passwd"));
    expect_false("up then down stays", erebus_path_has_dotdot_escape("a\\..\\b"));

    if (fails) {
        fprintf(stderr, "%d pathjail host tests failed\n", fails);
        return 1;
    }
    printf("pathjail host tests ok\n");
    return 0;
}
