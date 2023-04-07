#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct virus{
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
}virus;

typedef struct link link;

struct link {
    link *nextVirus;
    virus *vir;
};

struct fun_desc {
    char* name;
    void (*fun)();
};

link * list = NULL;

int min(int a, int b){
    if (a < b) return a;
    return b;
}

virus* readVirus(FILE* file){
    virus *v = malloc(sizeof(virus));
    fread(&v->SigSize, sizeof(short), 1, file);
    fread(v->virusName, sizeof(char), 16, file);
    v->sig = malloc(v->SigSize);
    size_t maybeEnd = fread(v->sig, sizeof(char), v->SigSize, file);
    if (maybeEnd == 0){
        free(v);
        return NULL;
    }

    return v;
}

void printVirus(virus* virus, FILE* output){
    fprintf(output, "Virus name: %s\n", virus->virusName);
    fprintf(output, "Virus size: %d\n", virus->SigSize);
    fprintf(output, "signature:\n");
    for (int i = 0; i < virus->SigSize; i++){
        fprintf(output, "%02X ", (unsigned char) virus->sig[i]);
    }
    fprintf(output, "\n");
    // free(virus->sig);
    // free(virus);
}

void list_print(link *virus_list, FILE* output){
    if (virus_list != NULL){
        list_print(virus_list->nextVirus, output);
        printVirus(virus_list->vir, output);
        fprintf(output, "\n");
    }
}

link* list_append(link* virus_list, virus* data){
    link* new_link = malloc(sizeof(link));
    if (virus_list == NULL){
        new_link->nextVirus = NULL;
        new_link->vir = data;
    }
    else{
        new_link->vir = data;
        new_link->nextVirus = virus_list;
    }
    return new_link;
}

void list_free(link *virus_list){
    if (virus_list != NULL){
        if (virus_list->nextVirus != NULL){
            list_free(virus_list->nextVirus);
        }
        free(virus_list);
    }
}

void load_signatures(){
    char str[256];
    char vir[4];
    //char buff[20];
    printf("%s", "Enter a file name: ");
    fgets(str, 256, stdin);
    str[strcspn(str, "\r\n")] = '\0';
    // sscanf(buff, "%s",str);
    FILE *file = fopen(str, "r");
    if (file == NULL){
        printf("%s", "No such file!\n");
        exit(1);
    }
    fread(vir, sizeof(vir), 1, file);
    printf("%s\n", vir);
    //printf("%02X", (char) vir);
    if ((strcmp(vir,"VISBsignatures-B") != 0) & (strcmp(vir,"VISLsignatures-L") != 0)){ ///?!
        printf("%s", "Incorrect magic number!!!!\n");
        exit(0);
    }
    virus *v = malloc(sizeof(virus));
    list = malloc(sizeof(link));
    list->vir = readVirus(file);
    list->nextVirus = NULL;
    while ((v = readVirus(file)) != NULL)
    {
        list = list_append(list, v);
    }
    //free(v);
    fclose(file);
}

void print_signatures(){
    if (list != NULL){
        list_print(list, stdout);
    }
}

void detect_virus(char *buffer, unsigned int size, link *virus_list) {
    int i;
   // while (virus_list != NULL) {
        for (i = 0; i < size; i++) {
            if (memcmp(buffer + i, virus_list->vir->sig, virus_list->vir->SigSize) == 0) {
                printf("Virus found starting at byte location 0x%02X\n", i);
                printf("Virus name: %s\n", virus_list->vir->virusName);
                printf("Virus signature size: %d\n", virus_list->vir->SigSize);
                printf("\n");
            }
        }
        //virus_list = virus_list->nextVirus;
//    }
}

void detect_viruses(){
    char str[256];
    int bufSize = 10000;
    char * buffer = malloc(bufSize);
    printf("%s", "Enter a file name: ");
    fgets(str, 256, stdin);
    str[strcspn(str, "\r\n")] = '\0';
    FILE * fileToDetectVirusesFrom = fopen(str, "r");
    if (fileToDetectVirusesFrom == NULL){
        printf("%s", "No such file!\n");
        list_free(list);
        exit(1);
    }
    fread(buffer, bufSize, 1, fileToDetectVirusesFrom);
    link * virus = list;
    while(virus != NULL){
        detect_virus(buffer, bufSize, virus);
        virus = virus->nextVirus;
    }
    fclose(fileToDetectVirusesFrom);
    free(buffer);
}

void neutralize_virus(char *fileName, int signatureOffset){
    unsigned char RET_near = 0xC3;
    FILE * fileToClean = fopen(fileName, "r+");
    fseek(fileToClean, signatureOffset, SEEK_SET);
    fwrite(&RET_near, 1, 1, fileToClean);
    fclose(fileToClean);
}

void fix_file(){
    char str[256];
    int bufSize = 10000;
    char * buffer = malloc(bufSize);
    printf("%s", "Enter a file name: ");
    fgets(str, 256, stdin);
    str[strcspn(str, "\r\n")] = '\0';
    FILE * fileToClean = fopen(str, "r");
    if (fileToClean == NULL){
        printf("%s", "No such file!\n");
        list_free(list);
        exit(1);
    }
    fread(buffer, bufSize, 1, fileToClean);
    link *virus_list = list;
    int i;
    while (virus_list != NULL) {
        for (i = 0; i < bufSize; i++) {
            if (memcmp(buffer + i, virus_list->vir->sig, virus_list->vir->SigSize) == 0) {
                neutralize_virus(str, i);
            }
        }
        virus_list = virus_list->nextVirus;
    }
    free(buffer);
    fclose(fileToClean);
}

void quit(){
    list_free(list);
    exit(0);
}

struct fun_desc menu[] = {{"Load signatures", load_signatures}, {"Print signatures", print_signatures}, {"Detect viruses", detect_viruses}, {"Fix file", fix_file}, {"Quit", quit}, {NULL,NULL}};

int main(int argc, char **argv){
    //FILE *out = fopen(argv[2], "w");
    int menu_size = sizeof(menu)/sizeof(menu[0])-1; // Exclude the NULL
    char buffer[menu_size];
    char choice;
    // char* carray = (char*) malloc(menu_size);
    while(1){
      fprintf(stdout, "%s", "Select operation from the following menu:\n");
      for(int i = 0; i < menu_size; i++){
            printf("%d) %s\n", i, menu[i].name);
        }
      fgets(buffer, menu_size, stdin);  
      sscanf(buffer, "%c",&choice);
      if (choice == EOF){
        break;
      }
      //choice = input[0];

      if ((choice >= '0') & (choice < (menu_size + '0'))){
            printf("%s\n", "Within bounds");
            menu[choice-48].fun();
            // char* temp = carray;
            // carray = map(carray, menu_size, menu[choice-48].fun);
            // free(temp);
        } else {
            printf("%s\n", "Not within bounds");
            break;
        }
    }
    //free(carray);

    // char vir[4];
    // if (argc < 2){
    //     printf("%s", "Not Enogh Arguments!\n");
    //     exit(0);
    // }
    // FILE * file = fopen(argv[1], "r");
    // if (file == NULL){
    //     printf("%s", "Failed to open output file!\n");
    //     exit(0);
    // }
    // fread(vir, sizeof(vir), 1, file);
    // printf("%s\n", vir);
    // //printf("%02X", (char) vir);
    // if ((strcmp(vir,"VISB") != 0) & (strcmp(vir,"VISL") != 0)){
    //     printf("%s", "Incorrect magic number!!!!\n");
    //     exit(0);
    // }
    // virus *v;
    // while ((v = readVirus(file)) != NULL)
    // {
    //     //v = readVirus(file);
    //     printVirus(v, stdout);
    // }
    // fclose(file);
    //fclose(out);
    return 0;
}
