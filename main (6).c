#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAILLE_BUFFER 1024
#define MAX_SIGNATURES 100

int rechercher_signature(const unsigned char *buffer, size_t taille, const unsigned char *signature, size_t signature_len, size_t *position) {
    for (size_t i = 0; i <= taille - signature_len; i++) {
        if (memcmp(&buffer[i], signature, signature_len) == 0) {
            *position = i;
            return 1;
        }
    }
    return 0;
}

int lire_fichier_config(const char *nom_fichier, unsigned char signatures[MAX_SIGNATURES][TAILLE_BUFFER], size_t *signature_lens, int *nombre_signatures) {
    FILE *fichier = fopen(nom_fichier, "r");
    if (fichier == NULL) {
        perror("Erreur lors de l'ouverture du fichier de configuration");
        return 0;
    }

    char ligne[256];
    *nombre_signatures = 0;

    while (fgets(ligne, sizeof(ligne), fichier) != NULL) {
        if (*nombre_signatures >= MAX_SIGNATURES) {
            fprintf(stderr, "Trop de signatures dans le fichier de configuration\n");
            fclose(fichier);
            return 0;
        }

        char *ptr = ligne;
        while (*ptr && *ptr == ' ') {
            ptr++;
        }

        size_t i = 0;
        while (ptr[i] && ptr[i] != '\n' && i < TAILLE_BUFFER) {
            sscanf(&ptr[i], "%2hhx", &signatures[*nombre_signatures][i / 2]);
            i += 2;
        }

        signature_lens[*nombre_signatures] = i / 2;
        (*nombre_signatures)++;
    }

    fclose(fichier);
    return 1;
}

int analyser_fichier(const char *nom_fichier, unsigned char signatures[MAX_SIGNATURES][TAILLE_BUFFER], size_t signature_lens[MAX_SIGNATURES], int nombre_signatures) {
    FILE *fichier = fopen(nom_fichier, "rb");
    if (fichier == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        return 0;
    }

    unsigned char buffer[TAILLE_BUFFER];
    size_t bytes_lus;
    int failles_trouvees = 0;

    while ((bytes_lus = fread(buffer, 1, TAILLE_BUFFER, fichier)) > 0) {
        for (int i = 0; i < nombre_signatures; i++) {
            size_t position = 0;
            if (rechercher_signature(buffer, bytes_lus, signatures[i], signature_lens[i], &position)) {
                printf("Signature trouvée à la position %zu pour la signature %d\n", position, i + 1);
                failles_trouvees++;
            }
        }
    }

    fclose(fichier);
    printf("Potentielles failles trouvées = %d\n", failles_trouvees);
    return 1;
}

int main() {
    int nombre_signatures = 0;
    unsigned char signatures[MAX_SIGNATURES][TAILLE_BUFFER];
    size_t signature_lens[MAX_SIGNATURES];
    char nom_fichier_config[256] = "rule.txt";
    char nom_fichier_a_analyser[256] = "a.mp4";

    if (!lire_fichier_config(nom_fichier_config, signatures, signature_lens, &nombre_signatures)) {
        fprintf(stderr, "Échec de la lecture du fichier de configuration.\n");
        return EXIT_FAILURE;
    }

    if (!analyser_fichier(nom_fichier_a_analyser, signatures, signature_lens, nombre_signatures)) {
        fprintf(stderr, "Échec de l'analyse du fichier.\n");
        return EXIT_FAILURE;
    }

    printf("Analyse terminée avec succès.\n");

    return EXIT_SUCCESS;
}