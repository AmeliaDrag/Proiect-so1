#define _POSIX_C_SOURCE 200809L

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
}

void comanda_add()
{
  creaza_district_daca_lipseste();
  //determinam ce bit de permisiune trebuie verificat in functie de rol.
  //group verifica, s_iwgrp
  //owner verificam s_iwusr
  mode_t bit = (strcmp(role, "manager") == 0) ? S_IWUSR : S_IWGRP;

  //verifica daca rolul curent are drept de scriere
  if (!verifica_permisiune(path_reports, bit, "scrie in reports.dat")) {
    exit(EXIT_FAILURE);
  }
  struct stat st;
  int nr_rapoarte = 0;

  //calculam cate raoarte exista deja
  if (stat(path_reports, &st) == 0) {
    nr_rapoarte = (int)(st.st_size / sizeof(Report));
  }

  //declaram structura pt noul rap
  Report r;
  memset(&r, 0, sizeof(Report));

  r.report_id = nr_rapoarte + 1;
  strncpy(r.inspector_name, user_name, sizeof(r.inspector_name) - 1);
  r.Timestamp = time(NULL);
  printf("=== Adaugare raport #%d in districtul '%s' ===\n", r.report_id, district);
  printf("Latitudine GPS  : ");
  fflush(stdout); // fflush(stdout) forțează afișarea textului înainte ca scanf să aștepte input 
  scanf("%f", &r.lat);

  printf("Longitudine GPS : ");
  fflush(stdout);
  scanf("%f", &r.longi);

  printf("Categorie (road/lighting/flooding/other): ");
  fflush(stdout);
  scanf("%49s", r.category);

  printf("Severitate (1=minor, 2=moderat, 3=critic): ");
  fflush(stdout);
  scanf("%d", &r.severity_level);

  if (r.severity_level < 1 || r.severity_level > 3) {
    fprintf(stderr, "EROARE: Severitatea trebuie sa fie 1, 2 sau 3.\n");
    exit(EXIT_FAILURE);
  }

  int c;
  while ((c = getchar()) != '\n' && c != EOF);

  printf("Descriere: ");
  fflush(stdout);
  if (fgets(r.description_text, sizeof(r.description_text), stdin)) {
    size_t len = strlen(r.description_text);
    if (len > 0 && r.description_text[len - 1] == '\n')
      r.description_text[len - 1] = '\0';
  }

  int fd = open(path_reports, O_WRONLY | O_APPEND);
  if (fd == -1) {
    perror("Eroare open reports.dat");
    exit(EXIT_FAILURE);
  }

  if (write(fd, &r, sizeof(Report)) != (ssize_t)sizeof(Report)) {
    perror("Eroare la scriere");
    close(fd);
    exit(EXIT_FAILURE);
  }

  close(fd);
  chmod(path_reports, PERM_REPORTS);

  printf("Raportul #%d a fost adaugat cu succes.\n", r.report_id);

  int threshold = citeste_threshold();
  if (r.severity_level >= threshold) {
    printf("* ALERTA: Raportul #%d are severitate %d >= prag %d *\n",
	   r.report_id, r.severity_level, threshold);
  }
  // Enutul cere ca fiecare acțiune să fie înregistrată cu timestamp rol și utilixator.
  char mesaj_log[MAX_LOG];
  snprintf(mesaj_log, MAX_LOG, "add district=%s report_id=%d", district, r.report_id);
  scrie_in_log(mesaj_log);

  gestioneaza_symlink();
}

void comanda_list()
{
    struct stat st;
    if (stat(path_reports, &st) == -1) {
        fprintf(stderr, "ERROR: reports.dat nu exista in districtul '%s'.\n", district);
        exit(EXIT_FAILURE);
    }

    mode_t bit = (strcmp(role, "manager") == 0) ? S_IRUSR : S_IRGRP;
    if (!verifica_permisiune(path_reports, bit, "citi reports.dat")) {
        exit(EXIT_FAILURE);
    }

    //Convertim biții de permisiuni în text
    char perm_str[10];
    mode_to_string(st.st_mode, perm_str);
    
    //Obținem data ultimei modificări a fișierului:
    char data_modif[64];
    struct tm *tm_info = localtime(&st.st_mtime);
    strftime(data_modif, sizeof(data_modif), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("=== District: %s ===\n", district);
    printf("Fisier: reports.dat  Permisiuni: %s  Dimensiune: %lld bytes  Modificat: %s\n",
           perm_str, (long long)st.st_size, data_modif);

    int nr_rapoarte = (int)(st.st_size / sizeof(Report));
    printf("Total rapoarte: %d\n\n", nr_rapoarte);

    if (nr_rapoarte == 0) {
        printf("(nu exista rapoarte)\n");
        scrie_in_log("list");
        return;
    }

    int fd = open(path_reports, O_RDONLY);
    if (fd == -1) { perror("Eroare open reports.dat"); exit(EXIT_FAILURE); }

    printf("%-5s %-20s %-12s %-10s %-12s %s\n",
           "ID", "Inspector", "Categorie", "Severitate", "Data", "Descriere");
    printf("%-5s %-20s %-12s %-10s %-12s %s\n",
           "----", "--------------------", "------------",
           "----------", "------------", "--------------------");
    //Citim înregistrările una câte una cu read()
    Report r;
    ssize_t n;
    while ((n = read(fd, &r, sizeof(Report))) == (ssize_t)sizeof(Report)) {
        char data_ts[16];
        struct tm *t = localtime(&r.Timestamp);
        strftime(data_ts, sizeof(data_ts), "%Y-%m-%d", t);

        const char *sev = (r.severity_level == 1) ? "minor" :
                          (r.severity_level == 2) ? "moderat" : "critic";

        char desc[21];
        strncpy(desc, r.description_text, 20);
        desc[20] = '\0';

        printf("%-5d %-20s %-12s %-10s %-12s %s\n",
               r.report_id, r.inspector_name, r.category, sev, data_ts, desc);
    }
    close(fd);
    scrie_in_log("list");
}

void comanda_view(int id_cautat)
{
    struct stat st;
    if (stat(path_reports, &st) == -1) {
        fprintf(stderr, "EROARE: reports.dat nu exista in districtul '%s'.\n", district);
        exit(EXIT_FAILURE);
    }

    mode_t bit = (strcmp(role, "manager") == 0) ? S_IRUSR : S_IRGRP;
    if (!verifica_permisiune(path_reports, bit, "citi reports.dat")) {
        exit(EXIT_FAILURE);
    }

    int fd = open(path_reports, O_RDONLY);
    if (fd == -1) { perror("Eroare open reports.dat"); exit(EXIT_FAILURE); }

    Report r;
    ssize_t n;
    int gasit = 0;
    while ((n = read(fd, &r, sizeof(Report))) == (ssize_t)sizeof(Report)) {
        if (r.report_id == id_cautat) { gasit = 1; break; }
    }
    close(fd);

    if (!gasit) {
        fprintf(stderr, "EROARE: Raportul ID=%d nu exista in '%s'.\n",
                id_cautat, district);
        exit(EXIT_FAILURE);
    }

    char data_ts[64];
    struct tm *t = localtime(&r.Timestamp);
    strftime(data_ts, sizeof(data_ts), "%Y-%m-%d %H:%M:%S", t);

    const char *sev = (r.severity_level == 1) ? "minor (1)" :
                      (r.severity_level == 2) ? "moderat (2)" : "critic (3)";

    printf("=== Raport #%d - District: %s ===\n", r.report_id, district);
    printf("Inspector    : %s\n",        r.inspector_name);
    printf("GPS          : %.6f, %.6f\n", r.lat, r.longi);
    printf("Categorie    : %s\n",        r.category);
    printf("Severitate   : %s\n",        sev);
    printf("Timestamp    : %s\n",        data_ts);
    printf("Descriere    : %s\n",        r.description_text);

    char mesaj_log[MAX_LOG];
    snprintf(mesaj_log, MAX_LOG, "view district=%s report_id=%d", district, id_cautat);
    scrie_in_log(mesaj_log);
}

void comanda_remove_report(int id_de_sters)
{
    if (strcmp(role, "manager") != 0) {
        fprintf(stderr, "ACCES REFUZAT: Doar managerul poate sterge rapoarte.\n");
        exit(EXIT_FAILURE);
    }

    if (!verifica_permisiune(path_reports, S_IWUSR, "scrie in reports.dat")) {
        exit(EXIT_FAILURE);
    }

    struct stat st;
    if (stat(path_reports, &st) == -1) {
        perror("Eroare stat reports.dat"); exit(EXIT_FAILURE);
    }

    int nr = (int)(st.st_size / sizeof(Report));
    if (nr == 0) {
        fprintf(stderr, "EROARE: Nu exista rapoarte in '%s'.\n", district);
        exit(EXIT_FAILURE);
    }

    //Citim toate inregistrarile in memorie 
    Report *rapoarte = malloc(nr * sizeof(Report));
    if (!rapoarte) { perror("malloc"); exit(EXIT_FAILURE); }

    int fd = open(path_reports, O_RDWR);
    if (fd == -1) { perror("Eroare open"); free(rapoarte); exit(EXIT_FAILURE); }

    if (read(fd, rapoarte, nr * sizeof(Report)) != (ssize_t)(nr * sizeof(Report))) {
        perror("Eroare citire"); free(rapoarte); close(fd); exit(EXIT_FAILURE);
    }

    int idx = -1;
    for (int i = 0; i < nr; i++) {
        if (rapoarte[i].report_id == id_de_sters) { idx = i; break; }
    }
    if (idx == -1) {
        fprintf(stderr, "EROARE: Raportul ID=%d nu exista.\n", id_de_sters);
        free(rapoarte); close(fd); exit(EXIT_FAILURE);
    }

    // Mutam fiecare inregistrare de dupa cea stearsa cu o pozitie mai in fata.
    // lseek() pozitioneaza exact unde trebuie sa scriem.
    for (int i = idx; i < nr - 1; i++) {
        off_t pozitie = (off_t)i * (off_t)sizeof(Report);
        if (lseek(fd, pozitie, SEEK_SET) == -1) {
            perror("Eroare lseek"); free(rapoarte); close(fd); exit(EXIT_FAILURE);
        }
        if (write(fd, &rapoarte[i + 1], sizeof(Report)) != (ssize_t)sizeof(Report)) {
            perror("Eroare write"); free(rapoarte); close(fd); exit(EXIT_FAILURE);
        }
    }

    /// Trunchiem pentru a elimina ultimul duplicat
    off_t dim_noua = (off_t)(nr - 1) * (off_t)sizeof(Report);
    if (ftruncate(fd, dim_noua) == -1) {
        perror("Eroare ftruncate"); free(rapoarte); close(fd); exit(EXIT_FAILURE);
    }

    free(rapoarte);
    close(fd);

    struct stat st2;
    stat(path_reports, &st2);
    printf("Raportul #%d sters din '%s'. Rapoarte ramase: %d\n",
           id_de_sters, district, nr - 1);
    printf("Dimensiune fisier: %lld bytes (asteptat: %lld)\n",
           (long long)st2.st_size, (long long)dim_noua);

    char mesaj_log[MAX_LOG];
    snprintf(mesaj_log, MAX_LOG, "remove_report district=%s report_id=%d",
             district, id_de_sters);
    scrie_in_log(mesaj_log);
}

void comanda_update_threshold(int valoare_noua)
{
    if (strcmp(role, "manager") != 0) {
        fprintf(stderr, "ACCES REFUZAT: Doar managerul poate modifica threshold-ul.\n");
        exit(EXIT_FAILURE);
    }
    if (valoare_noua < 1 || valoare_noua > 3) {
        fprintf(stderr, "EROARE: Threshold-ul trebuie sa fie 1, 2 sau 3.\n");
        exit(EXIT_FAILURE);
    }

    struct stat st;
    if (stat(path_cfg, &st) == -1) {
        perror("Eroare stat district.cfg"); exit(EXIT_FAILURE);
    }

    //Verificam ca permisiunile sunt EXACT 640 
    mode_t perm = st.st_mode & 0777;
    if (perm != PERM_CFG) {
        char perm_str[10];
        mode_to_string(st.st_mode, perm_str);
        fprintf(stderr,
            "EROARE: district.cfg are permisiuni %s (%03o), asteptat %03o.\n"
            "Refuzam scrierea.\n",
            perm_str, (unsigned)perm, (unsigned)PERM_CFG);
        exit(EXIT_FAILURE);
    }

    if (!verifica_permisiune(path_cfg, S_IWUSR, "scrie in district.cfg")) {
        exit(EXIT_FAILURE);
    }

    int fd = open(path_cfg, O_WRONLY | O_TRUNC);
    if (fd == -1) { perror("Eroare open district.cfg"); exit(EXIT_FAILURE); }

    char buf[32];
    snprintf(buf, sizeof(buf), "threshold=%d\n", valoare_noua);
    write(fd, buf, strlen(buf));
    close(fd);
    chmod(path_cfg, PERM_CFG);

    printf("Threshold pentru '%s' actualizat la %d.\n", district, valoare_noua);

    char mesaj_log[MAX_LOG];
    snprintf(mesaj_log, MAX_LOG, "update_threshold district=%s valoare=%d",
             district, valoare_noua);
    scrie_in_log(mesaj_log);
}

int parse_condition(const char *input, char *field, char *op, char *value) {
    if (!input) return 0;

    const char *p1 = strchr(input, ':');
    if (!p1) return 0;

    size_t field_len = p1 - input;
    if (field_len == 0 || field_len >= 50) return 0;
    
    strncpy(field, input, field_len);
    field[field_len] = '\0';

    const char *op_start = p1 + 1;
    int op_len = 0;

   
    if (strncmp(op_start, "==", 2) == 0 || strncmp(op_start, "!=", 2) == 0 ||
        strncmp(op_start, "<=", 2) == 0 || strncmp(op_start, ">=", 2) == 0) {
        op_len = 2;
    } 
    else if (*op_start == '<' || *op_start == '>') {
        op_len = 1;
    } else {
        return 0; 
    }

    strncpy(op, op_start, op_len);
    op[op_len] = '\0';

    const char *p2 = op_start + op_len;
    if (*p2 != ':' || *(p2 + 1) == '\0') return 0;

    strncpy(value, p2 + 1, 99);
    value[99] = '\0';

    return 1;
}

int match_condition(Report *r, const char *field, const char *op, const char *value) {
    
    if (strcmp(field, "severity") == 0) {
        long val = strtol(value, NULL, 10);
        if (strcmp(op, "==") == 0) return r->severity_level == (int)val;
        if (strcmp(op, "!=") == 0) return r->severity_level != (int)val;
        if (strcmp(op, ">=") == 0) return r->severity_level >= (int)val;
        if (strcmp(op, "<=") == 0) return r->severity_level <= (int)val;
        if (strcmp(op, ">")  == 0) return r->severity_level >  (int)val;
        if (strcmp(op, "<")  == 0) return r->severity_level <  (int)val;
    } 
    else if (strcmp(field, "category") == 0) {
        int cmp = strcmp(r->category, value);
        if (strcmp(op, "==") == 0) return cmp == 0;
        if (strcmp(op, "!=") == 0) return cmp != 0;
    }
    else if (strcmp(field, "inspector") == 0) {
        int cmp = strcmp(r->inspector_name, value);
        if (strcmp(op, "==") == 0) return cmp == 0;
        if (strcmp(op, "!=") == 0) return cmp != 0;
    }
    else if (strcmp(field, "report_id") == 0) {
        long val = strtol(value, NULL, 10);
        if (strcmp(op, "==") == 0) return r->report_id == (int)val;
        if (strcmp(op, "!=") == 0) return r->report_id != (int)val;
    }

    return 0; 
}

void comanda_filter(int nr_conditii, char **conditii)
{
    mode_t bit = (strcmp(role, "manager") == 0) ? S_IRUSR : S_IRGRP;
    if (!verifica_permisiune(path_reports, bit, "citire rapoarte")) {
        return;
    }

    int fd = open(path_reports, O_RDONLY);
    if (fd == -1) {
        perror("Eroare deschidere reports.dat");
        return;
    }

    printf("=== Filtrare District: %s ===\n", district);
    
    Report r;
    int gasite = 0;
    int total = 0;

    while (read(fd, &r, sizeof(Report)) == (ssize_t)sizeof(Report)) {
        total++;
        int ok = 1;

        
        for (int i = 0; i < nr_conditii; i++) {
            char f[50], o[10], v[100];
            
            if (parse_condition(conditii[i], f, o, v)) {
                if (!match_condition(&r, f, o, v)) {
                    ok = 0;
                    break; 
                }
            } else {
                fprintf(stderr, "Filtru invalid ignorat: %s\n", conditii[i]);
            }
        }

        if (ok) {
            char data_str[20];
            struct tm *info = localtime(&r.Timestamp);
            strftime(data_str, sizeof(data_str), "%Y-%m-%d %H:%M", info);

            printf("[%d] %-10s | Sev: %d | Data: %s | Desc: %s\n",
                   r.report_id, r.category, r.severity_level, data_str, r.description_text);
            gasite++;
        }
    }

    printf("\nRezultat: %d rapoarte gasite dintr-un total de %d analizate.\n", gasite, total);
    
    close(fd);

    char log_msg[MAX_LOG];
    snprintf(log_msg, MAX_LOG, "FILTER: district=%s, matches=%d, filters=%d", 
             district, gasite, nr_conditii);
    scrie_in_log(log_msg);
}

void afiseaza_utilizare(const char *prog)
{
    fprintf(stderr,
        "Utilizare: %s --role <manager|inspector> --user <nume> <comanda> [args]\n"
        "Comenzi:\n"
        "  --add              <district>\n"
        "  --list             <district>\n"
        "  --view             <district> <id>\n"
        "  --remove_report    <district> <id>\n"
        "  --update_threshold <district> <valoare>\n"
        "  --filter           <district> <cond1> [cond2 ...]\n"
        "Format conditie: camp:operator:valoare\n"
        "  Campuri: severity, category, inspector, report_id\n"
        "  Operatori: ==, !=, <, <=, >, >=\n", prog);
}

int main(int argc, char* argv[]){
  if(argc <2){
    printf("utilizati %s ", argv[0]);
    return 1;
  }
 
  char comanda[MAX] = "";
  int  arg_extra    = 0;  

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--role") == 0 && i+1 < argc) {
      strncpy(role, argv[++i], MAX-1);
    } else if (strcmp(argv[i], "--user") == 0 && i+1 < argc) {
      strncpy(user_name, argv[++i], MAX-1);
    } else if (strcmp(argv[i], "--add") == 0 && i+1 < argc) {
      strncpy(comanda, "add", MAX-1);
      strncpy(district, argv[++i], MAX-1);
      arg_extra = i + 1;
    } else if (strcmp(argv[i], "--list") == 0 && i+1 < argc) {
      strncpy(comanda, "list", MAX-1);
      strncpy(district, argv[++i], MAX-1);
      arg_extra = i + 1;
    } else if (strcmp(argv[i], "--view") == 0 && i+1 < argc) {
      strncpy(comanda, "view", MAX-1);
      strncpy(district, argv[++i], MAX-1);
      arg_extra = i + 1;
    } else if (strcmp(argv[i], "--remove_report") == 0 && i+1 < argc) {
      strncpy(comanda, "remove_report", MAX-1);
      strncpy(district, argv[++i], MAX-1);
      arg_extra = i + 1;
    } else if (strcmp(argv[i], "--update_threshold") == 0 && i+1 < argc) {
      strncpy(comanda, "update_threshold", MAX-1);
      strncpy(district, argv[++i], MAX-1);
      arg_extra = i + 1;
    } else if (strcmp(argv[i], "--filter") == 0 && i+1 < argc) {
      strncpy(comanda, "filter", MAX-1);
      strncpy(district, argv[++i], MAX-1);
      arg_extra = i + 1;
    }
  }

  //Verifică că utilizatorul a dat toate argumentele obligatorii și că rolul e valid.
  if (strlen(role) == 0) {
    fprintf(stderr, "EROARE: --role este obligatoriu.\n"); return 1;
  }
  if (strcmp(role,"manager") != 0 && strcmp(role,"inspector") != 0) {
    fprintf(stderr, "EROARE: --role trebuie sa fie 'manager' sau 'inspector'.\n"); return 1;
  }
  if (strlen(user_name) == 0) {
    fprintf(stderr, "EROARE: --user este obligatoriu.\n"); return 1;
  }
  if (strlen(comanda) == 0) {
    fprintf(stderr, "EROARE: Nicio comanda specificata.\n");
    afiseaza_utilizare(argv[0]); return 1;
  }

  // Construim caile o singura data 
  construieste_cai(district);

  if (strcmp(comanda, "add") == 0) {
    comanda_add();
  } else if (strcmp(comanda, "list") == 0) {
    comanda_list();
  } else if (strcmp(comanda, "view") == 0) {
    if (arg_extra >= argc) { fprintf(stderr, "EROARE: lipseste report_id.\n"); return 1; }
    comanda_view(atoi(argv[arg_extra]));
  } else if (strcmp(comanda, "remove_report") == 0) {
    if (arg_extra >= argc) { fprintf(stderr, "EROARE: lipseste report_id.\n"); return 1; }
    comanda_remove_report(atoi(argv[arg_extra]));
  } else if (strcmp(comanda, "update_threshold") == 0) {
    if (arg_extra >= argc) { fprintf(stderr, "EROARE: lipseste valoarea.\n"); return 1; }
    comanda_update_threshold(atoi(argv[arg_extra]));
  } else if (strcmp(comanda, "filter") == 0) {
    int nr = argc - arg_extra;
    if (nr <= 0) { fprintf(stderr, "EROARE: lipseste conditia.\n"); return 1; }
    comanda_filter(nr, argv + arg_extra);
  }

  return 0;
}

//comenzi rurale:
/*
  compilare: gcc -Wall -Wextra -std=c99 -o city_manager proiect1.c

  rurale:
  2 districte: 
  ./city_manager --role manager --user alice --add downtown
  ./city_manager --role manager --user alice --add northside

  verificarea functilor:
  ./city_manager --role inspector --user bob --list downtown
  ./city_manager --role manager --user alice --view downtown 1
  ./city_manager --role inspector --user bob --filter downtown 'severity:>=:2'
  ./city_manager --role manager --user alice --update_threshold downtown 2
  ./city_manager --role manager --user alice --remove_report downtown 1

  
