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


//Aceasta lipsește cumva numele districtului de numele fișierului, creând o cale completă pe care sistemul de operare o poate înțelege.
void construieste_cai(const char *dist)
{
  //in path reports se salveaza destinatia finala, daca nu trece de max path
    snprintf(path_reports, MAX_PATH, "%s/reports.dat",     dist);
    snprintf(path_cfg,     MAX_PATH, "%s/district.cfg",    dist);
    snprintf(path_log,     MAX_PATH, "%s/logged_district", dist);
}

//verificarea permisiunilor
//Verifica daca fisierul 'path' are bitul 'bit_necesar' setat.
// manager  = owner  - testam bitii USER  (ex: S_IWUSR)
// inspector = group - testam bitii GROUP (ex: S_IWGRP)
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
    //flaguri care ne arata cum vrem sa se deschida fisierul
    int fd = open(path_log, O_WRONLY | O_APPEND | O_CREAT, PERM_LOG);
    if (fd == -1) {
        perror("Eroare la deschiderea log-ului");
        return;
    }
 
    // Folosim strftime in loc de ctime() deoarece ctime() adauga \n automat 
    char timp[64];
    time_t acum = time(NULL);
    struct tm *tm_info = localtime(&acum);
    //strftime legat de timp.
    strftime(timp, sizeof(timp), "%Y-%m-%d %H:%M:%S", tm_info);
 
    char linie[MAX_LOG];
    snprintf(linie, MAX_LOG, "[%s] role=%s user=%s action=%s\n",
             timp, role, user_name, actiune);
 
    write(fd, linie, strlen(linie));
    close(fd);
    chmod(path_log, PERM_LOG);
}
// punctul 5: crearea de fisiere si directore

//din enunt:
//Each district corresponds to a separate directory. Inside each district directory there is:
//A binary report file (reports.dat) storing fixed-size records. asa face creaza_reports

void creaza_reports(){
  //e o strcutura specifica definita in <sys/stat.h> care va fi completată de sistem cu informații despre fișier: dimensiune, permisiuni, data modificării
  struct stat st;
  //apelam functia start
  //path_reports — calea fișierului (ex: "downtown/reports.dat")
  //&st e adres unde scriem 
  if (stat(path_reports, &st) == 0){
    return;
  }

  //cum deschidem:
  //O_creat daca nu exista il creaza
  //O_rdwr deschide pentru citire si scrie
  //perm iniiale gen biti 0664 adica rw-rw-r--
  int fd = open(path_reports, O_CREAT | O_RDWR, PERM_REPORTS);
  
  //verificarea 
  if (fd == -1) {
    perror("Eroare creare reports.dat");
    exit(EXIT_FAILURE);
  }

  close(fd);
  //path_reports --> e calea catre fisier
  //PERM_REPORTS --> permisiunile dormite adica modul
  //chmod e din biblioteca sys..
  //chmod() este un apel de sistem care spune să schimbe permisiunile unui fișier. 
  chmod(path_reports, PERM_REPORTS);
 
}
void creaza_cfg()
{
    struct stat st;
    if (stat(path_cfg, &st) == 0){
      return;
    }

    int fd = open(path_cfg, O_CREAT | O_RDWR, PERM_CFG);
    
    if (fd == -1) {
      perror("Eroare creare district.cfg");
      exit(EXIT_FAILURE);
    }

    //diferenta dintre functia creaza raport
    //"threshold=1\n" — șirul în sine, stocat în memoria read-only a programului


    //implicit pointeaza la primul caracter din sir
    const char *implicit = "threshold=1\n";
    // fd da fisierului ce nr sa deschida fisier
    //implicit adresa de memorie de unde incepe citirea
    //strelen nr exact de bytes scriti
    write(fd, implicit, strlen(implicit));

    
    close(fd);
    chmod(path_cfg, PERM_CFG);
}

void creaza_log()
{
    struct stat st;
    if (stat(path_log, &st) == 0){
      return;
    }

    int fd = open(path_log, O_CREAT | O_RDWR, PERM_LOG);
    if (fd == -1) {
      perror("Eroare creare logged_district");
      exit(EXIT_FAILURE);
    }
    close(fd);
    chmod(path_log, PERM_LOG);
}

//Creeaza directorul si fisierele daca nu exista deja.
// Caile TREBUIE sa fie deja construite cu construieste_cai() inainte.

void creaza_district_daca_lipseste()
{
  //daca nu exista il fac cu mkdir adica make directory
    struct stat st;
    if (stat(district, &st) == -1) {
        if (mkdir(district, PERM_DIR) == -1) {
            perror("Eroare la crearea directorului district");
            exit(EXIT_FAILURE);
        }
        chmod(district, PERM_DIR);
        printf("Director '%s' creat.\n", district);
    }
    creaza_reports();
    creaza_cfg();
    creaza_log();
}

//Creeaza sau actualizeaza legatura simbolica:
//Dangling înseamnă o legătură simbolică a cărei destinație nu mai există.
//  active_reports-<district>  <district>/reports.dat
// Folosim lstat() pentru a detecta legatura in sine (nu o urmam).
// Daca e "dangling" (destinatie disparuta), o stergem si o refacem.
//Detectarea dangling links dacă ștergi un district dar symlink-ul rămâne, programul trebuie să afișeze warning în loc să crape

void gestioneaza_symlink()
{
    char nume_symlink[MAX_PATH];
    snprintf(nume_symlink, MAX_PATH, "active_reports-%s", district);

    struct stat lst;
    //Verificăm dacă există ceva cu numele "active_reports-downtown"
    if (lstat(nume_symlink, &lst) == 0) {
        
        if (S_ISLNK(lst.st_mode)) {
            struct stat st;
            if (stat(nume_symlink, &st) == -1) {
	      //Dacă legătura e dangling, afișăm un warning pe stderr și o ștergem cu unlink(). unlink() șterge legătura în sine, nu destinația
                fprintf(stderr, "ATENTIE: '%s' e dangling. Refacem \n", nume_symlink);
                unlink(nume_symlink);
                
            } else {
                return; 
            }
        }
	//Dacă S_ISLNK() a returnat fals înseamnă că există un fișier normal sau director cu același nume ca symlink-ul nostru
	else {
            fprintf(stderr, "ATENTIE: '%s' exista dar nu e symlink!\n", nume_symlink);
            return;
        }
    }

    
    if (symlink(path_reports, nume_symlink) == -1) {
        perror("Eroare la crearea legaturii simbolice");
    } 
}

//fara functia citeste threshold programul nu ar ști care e pragul setat de manager și nu ar putea decide dacă să afișeze alerta sau nu gen extrage o valoare dintr-un fișier , dar numai dacă utilizatorul curent are drepturile necesare.
int citeste_threshold()
{
    mode_t bit = (strcmp(role, "manager") == 0) ? S_IRUSR : S_IRGRP;
    if (!verifica_permisiune(path_cfg, bit, "citi district.cfg")) return 1;
    FILE *f = fopen(path_cfg, "r");
    if (!f) return 1;
    int threshold = 1;
    char linie[64];
    while (fgets(linie, sizeof(linie), f)) {
        if (sscanf(linie, "threshold=%d", &threshold) == 1) break;
    }
    fclose(f);
    return threshold;

//urmatorul punct: 


//operations
//add
void comanda_add(){
  creaza_district_daca_lipseste();
  //determinam ce bit de permisiune trebuie verificat in functie de rol.
  //group verifica, s_iwgrp
  //owner verificam s_iwusr
  mode_t bit = (strcmp(role, "manager") == 0) ? S_IWUSR : S_IWGRP;

  //verifica daca rolul curent are drept de scriere
  if (!verifica_permisiune(path_reports, bit, "scrie in reports.dat")) {
        exit(EXIT_FAILURE);
    }
  
}



int main(int argc, char* argv[]){
  if(argc <2){
    printf("utilizati %s ", argv[0]);
    return 1;
  }
    // Construim caile o singura data
    construieste_cai(district);

    
    return 0;
    
}
