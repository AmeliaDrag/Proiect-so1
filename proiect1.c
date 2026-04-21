#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

// constante

#define MAX      200
#define MAX_PATH 300
#define MAX_LOG  500

//bitii de la permisiuni
#define PERM_DIR     0750
#define PERM_REPORTS 0664
#define PERM_CFG     0640
#define PERM_LOG     0644

//structura mea principala
typedef struct {
    int    report_id;
    char   inspector_name[100];
    float  lat;
    float  longi;
    char   category[50];
    int    severity_level;    
    time_t Timestamp;
    char   description_text[100];
} Report;

//le declar ca variabile globale ca sa nu trb sa le tot plasez ca argumente 
char role[MAX]      = "";
char user_name[MAX] = "";
char district[MAX]  = "";
 
char path_reports[MAX_PATH] = "";
char path_cfg[MAX_PATH]     = "";
char path_log[MAX_PATH]     = "";

//Functia cu permisiuni

void mode_to_string(mode_t mode, char *str)
{
    strcpy(str, "---------");
 
    if (mode & S_IRUSR) str[0] = 'r';
    if (mode & S_IWUSR) str[1] = 'w';
    if (mode & S_IXUSR) str[2] = 'x';
 
    if (mode & S_IRGRP) str[3] = 'r';
    if (mode & S_IWGRP) str[4] = 'w';
    if (mode & S_IXGRP) str[5] = 'x';
 
    if (mode & S_IROTH) str[6] = 'r';
    if (mode & S_IWOTH) str[7] = 'w';
    if (mode & S_IXOTH) str[8] = 'x';
}


//Aceasta "lipsește" numele districtului de numele fișierului, creând o cale completă pe care sistemul de operare o poate înțelege.
void construieste_cai(const char *dist)
{
    snprintf(path_reports, MAX_PATH, "%s/reports.dat",     dist);
    snprintf(path_cfg,     MAX_PATH, "%s/district.cfg",    dist);
    snprintf(path_log,     MAX_PATH, "%s/logged_district", dist);
}

//verificarea permisiunilor
//Verifica daca fisierul 'path' are bitul 'bit_necesar' setat.
// manager  = owner  → testam bitii USER  (ex: S_IWUSR)
// inspector = group → testam bitii GROUP (ex: S_IWGRP)
// Returneaza 1 daca are acces, 0 daca nu.

int verifica_permisiune(const char *path, mode_t bit_necesar, const char *actiune)
{
    struct stat st;
    if (stat(path, &st) == -1) {
      return 1; //fisierul nu exista inca, il vom crea 
    }
 
    if ((st.st_mode & bit_necesar) != bit_necesar) {
        char perm_str[10];
        mode_to_string(st.st_mode, perm_str);
        fprintf(stderr,
            "Rolul '%s' nu poate %s fisierul '%s'\n"
            " Permisiuni actuale: %s\n",
            role, actiune, path, perm_str);
        return 0;
    }
    return 1;
}

/*
  Scrie o linie in logged_district.
  Doar managerul poate scrie (permisiuni 644 = owner write).
  Inspectorul sare peste in mod silentios.
 */

void scrie_in_log(const char *actiune)
{
    if (strcmp(role, "inspector") == 0) {
      return; //inspectorul nu poate scrie in log 
    }
 
    if (!verifica_permisiune(path_log, S_IWUSR, "scrie in log")) {
        return;
    }
 
    int fd = open(path_log, O_WRONLY | O_APPEND | O_CREAT, PERM_LOG);
    if (fd == -1) {
        perror("Eroare la deschiderea log-ului");
        return;
    }
 
    // Folosim strftime in loc de ctime() deoarece ctime() adauga \n automat 
    char timp[64];
    time_t acum = time(NULL);
    struct tm *tm_info = localtime(&acum);
    strftime(timp, sizeof(timp), "%Y-%m-%d %H:%M:%S", tm_info);
 
    char linie[MAX_LOG];
    snprintf(linie, MAX_LOG, "[%s] role=%s user=%s action=%s\n",
             timp, role, user_name, actiune);
 
    write(fd, linie, strlen(linie));
    close(fd);
    chmod(path_log, PERM_LOG);
}
// punctul 5: crearea de fisiere si directore

 

int main(int argc, char* argv[]){
  if(argc <2){
    printf("utilizati %s ", argv[0]);
    return 1;
  }
    // Construim caile o singura data
    construieste_cai(district);

    
    return 0;
    
}
