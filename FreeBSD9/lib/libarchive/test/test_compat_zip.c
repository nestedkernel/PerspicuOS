/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "test.h"
__FBSDID("$FreeBSD: release/9.0.0/lib/libarchive/test/test_compat_zip.c 214905 2010-11-07 03:40:37Z kientzle $");

/* Copy this function for each test file and adjust it accordingly. */
static void
test_compat_zip_1(void)
{
	char name[] = "test_compat_zip_1.zip";
	struct archive_entry *ae;
	struct archive *a;
	int r;

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_compression_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_zip(a));
	extract_reference_file(name);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, name, 10240));

	/* Read first entry. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("META-INF/MANIFEST.MF", archive_entry_pathname(ae));

	/* Read second entry. */
	r = archive_read_next_header(a, &ae);
	if (r != ARCHIVE_OK) {
		if (strcmp(archive_error_string(a),
		    "libarchive compiled without deflate support (no libz)") == 0) {
			skipping("Skipping ZIP compression check: %s",
			    archive_error_string(a));
			goto finish;
		}
	}
	assertEqualIntA(a, ARCHIVE_OK, r);
	assertEqualString("tmp.class", archive_entry_pathname(ae));

	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));

	assertEqualInt(archive_compression(a), ARCHIVE_COMPRESSION_NONE);
	assertEqualInt(archive_format(a), ARCHIVE_FORMAT_ZIP);

	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
finish:
#if ARCHIVE_VERSION_NUMBER < 2000000
	archive_read_finish(a);
#else
	assertEqualInt(ARCHIVE_OK, archive_read_finish(a));
#endif
}

/*
 * Verify that we skip junk between entries.  The compat_zip_2.zip file
 * has several bytes of junk between 'file1' and 'file2'.  Such
 * junk is routinely introduced by some Zip writers when they manipulate
 * existing zip archives.
 */
static void
test_compat_zip_2(void)
{
	char name[] = "test_compat_zip_2.zip";
	struct archive_entry *ae;
	struct archive *a;

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_compression_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_zip(a));
	extract_reference_file(name);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, name, 10240));

	/* Read first entry. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("file1", archive_entry_pathname(ae));

	/* Read first entry. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("file2", archive_entry_pathname(ae));

	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}


DEFINE_TEST(test_compat_zip)
{
	test_compat_zip_1();
	test_compat_zip_2();
}


