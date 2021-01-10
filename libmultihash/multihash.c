/***************************************************************************
 *   Copyright (C) 2007 by SukkoPera   *
 *   sukkopera@sukkology.net   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include "multihash.h"
#include <stdio.h>

#define READBUF_SIZE 8192


void multihash_init (multihash *mh) {
#ifdef USE_CRC32
	(mh -> crc32_s)[0] = '\0';
	mh -> crc32 = 0xffffffff;
#endif
#ifdef USE_MD4
	(mh -> md4_s)[0] = '\0';
	md4_starts (&(mh -> md4));
#endif
#ifdef USE_MD5
	(mh -> md5_s)[0] = '\0';
	MD5Init (&(mh -> md5));
#endif
#ifdef USE_ED2K
	(mh -> ed2k_s)[0] = '\0';
	ed2khash_starts (&(mh -> ed2k));
#endif
#ifdef USE_SHA1
	(mh -> sha1_s)[0] = '\0';
	Sha1Initialise (&(mh -> sha1));
#endif
#ifdef USE_SHA2
	(mh -> sha2_s)[0] = '\0';
	Sha256Initialise (&(mh -> sha2));
#endif

	return;
}


void multihash_update (multihash *mh, unsigned char *data, int bytes) {
#ifdef USE_CRC32
	mh -> crc32 = CrcUpdate (mh -> crc32, data, bytes);
#endif
#ifdef USE_MD4
	md4_update (&(mh -> md4), data, bytes);
#endif
#ifdef USE_MD5
	MD5Update (&(mh -> md5), data, bytes);
#endif
#ifdef USE_ED2K
	ed2khash_update (&(mh -> ed2k), data, bytes);
#endif
#ifdef USE_SHA1
	Sha1Update (&(mh -> sha1), data, bytes);		/* WARNING: SHA1Update() destroys data! */
#endif
#ifdef USE_SHA2
	Sha256Update (&(mh -> sha2), data, bytes);
#endif

	return;
}


void multihash_finish (multihash *mh) {
	unsigned char buf[MAX_DIGESTSIZE];
	int bytes;

#ifdef USE_CRC32
	mh -> crc32 ^= 0xffffffff;
	snprintf (mh -> crc32_s, LEN_CRC32 + 1, "%08x", mh -> crc32);
#endif
#ifdef USE_MD4
	md4_finish (&(mh -> md4), buf);
	for (bytes = 0; bytes < LEN_MD4 / 2; bytes++)
		sprintf (mh -> md4_s + 2*bytes, "%02x", buf[bytes]);
	(mh -> md4_s)[LEN_MD4] = '\0';
#endif
#ifdef USE_MD5
	MD5Final (&(mh -> md5));
	for (bytes = 0; bytes < LEN_MD5 / 2; bytes++)
		sprintf (mh -> md5_s + 2*bytes, "%02x", (mh -> md5).digest[bytes]);
	(mh -> md5_s)[LEN_MD5] = '\0';
#endif
#ifdef USE_ED2K
	ed2khash_finish (&(mh -> ed2k), buf);
	for (bytes = 0; bytes < LEN_ED2K / 2; bytes++)
		sprintf (mh -> ed2k_s + 2*bytes, "%02x", buf[bytes]);
	(mh -> ed2k_s)[LEN_ED2K] = '\0';
#endif
#ifdef USE_SHA1
  /* SHA1_HASH struct that receives the finalised sha1 hash */
  SHA1_HASH sha1_hash;
	Sha1Finalise (&(mh -> sha1), &sha1_hash);
  /* copy the final sha1 hash as hex string to the multihash struct */
	for (bytes = 0; bytes < LEN_SHA1 / 2; bytes++)
		sprintf (mh -> sha1_s + 2*bytes, "%02x", sha1_hash.bytes[bytes]);
	(mh -> sha1_s)[LEN_SHA1] = '\0';
#endif
#ifdef USE_SHA2
  /* SHA256_HASH struct that receives the finalised sha2-256 hash */
  SHA256_HASH sha2_hash;
	Sha256Finalise (&(mh -> sha2), &sha2_hash);
  /* copy the final sha2 hash as hex string to the multihash struct */
	for (bytes = 0; bytes < LEN_SHA2 / 2; bytes++)
		sprintf (mh -> sha2_s + 2*bytes, "%02x", sha2_hash.bytes[bytes]);
	(mh -> sha2_s)[LEN_SHA2] = '\0';
#endif

	return;
}


int multihash_file (multihash *mh, char *filename) {
	FILE *fp;
	int bytes, out;
	unsigned char data[READBUF_SIZE];

	multihash_init (mh);
	if ((fp = fopen (filename, "r"))) {
		while ((bytes = fread (data, 1, READBUF_SIZE, fp)) != 0)
			multihash_update (mh, data, bytes);
		multihash_finish (mh);
		fclose (fp);
		out = 0;
	} else {
		/* Cannot open file */
		out = -1;
	}

	return (out);
}
