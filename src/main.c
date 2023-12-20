// SPDX-License-Identifier: GPL-3.0-or-later
/*
 *      This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 *    This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 *    You should have received a copy of the GNU General Public License along
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <ctype.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  char input[BUFSIZ];
  char buffer[BUFSIZ];
  unsigned char hashed[BUFSIZ];
  size_t bytesRead;
  char filename[BUFSIZ];

  EVP_MD_CTX *md_ctx;
  const EVP_MD *md;
  unsigned int md_len;

  OpenSSL_add_all_algorithms();

  md = EVP_sha512();

  md_ctx = EVP_MD_CTX_new();

  EVP_DigestInit_ex(md_ctx, md, NULL);

  printf("What is the file you want to hash? ");

  if (fgets(filename, sizeof(filename), stdin) == NULL) {
    perror("filename");
    exit(-1);
  }

  filename[strlen(filename) - 1] = '\0';

  FILE *file = fopen(filename, "rb");

  if (!file) {
    perror("file");
    exit(-1);
  }

  while ((bytesRead = fread(buffer, 1, sizeof(buffer), file))) {
    EVP_DigestUpdate(md_ctx, buffer, bytesRead);
  }

  EVP_DigestFinal_ex(md_ctx, hashed, &md_len);

  fclose(file);

  printf("Your hash is: ");
  for (int i = 0; i < md_len; i++) {
    printf("%02x", hashed[i]);
  }
  printf("\n");

  bool not_answered = true;

  while (not_answered) {
    printf("Want to write the hash to a file? ");

    if (fgets(input, sizeof(input), stdin) == NULL) {
      perror("input");
      exit(-1);
    }

    for (int i = 0; i < strlen(input); i++) {
      input[i] = tolower(input[i]);
    }

    input[strlen(input) - 1] = '\0';

    if (strcmp("yes", input) == 0) {
      file = fopen("hashes.txt", "a");

      fprintf(file, "Filename: %s | Hash: ", filename);
      for (int i = 0; i < md_len; i++) {
        fprintf(file, "%02x", hashed[i]);
      }
      fprintf(file, "\n");
      printf("Wrote to the file...\n");
      not_answered = false;
    } else if (strcmp("no", input) == 0) {
      printf("Not writing to the file...\n");
      not_answered = false;
    } else {
      printf("Incorrect input, write either yes or no.\n");
    }
  }

  EVP_MD_CTX_free(md_ctx);
  EVP_cleanup();

  not_answered = true;

  while (not_answered) {
    printf("Want to hash another file? ");

    if (fgets(input, sizeof(input), stdin) == NULL) {
      perror("input");
      exit(-1);
    }

    for (int i = 0; i < strlen(input); i++) {
      input[i] = tolower(input[i]);
    }

    input[strlen(input) - 1] = '\0';

    if (strcmp("yes", input) == 0) {
      printf("\e[1;1H\e[2J");
      main();
      not_answered = false;
    } else if (strcmp("no", input) == 0) {
      printf("See you next time.\n");
      not_answered = false;
    } else {
      printf("Incorrect input, write either yes or no.\n");
    }
  }

  return 0;
}
