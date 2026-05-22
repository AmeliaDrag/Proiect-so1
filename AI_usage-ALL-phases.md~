Ce tool am folosit?

Toolul de care m-am folosit in crearea celor 2 functii a fost Gemini, insa nu am fost multumita de rezultat si am ajuns sa folosesc si Claude.ai.

Care au fost prompturile date?

"Buna gemini, am un proiect. Am construit un program în C pe Linux care gestionează rapoarte de infrastructură urbană organizate pe districte.

Programul stochează rapoartele în fișiere binare cu înregistrări de dimensiune fixă, gestionează permisiunile fișierelor prin apeluri de sistem (chmod, stat), și implementează două roluri manager și inspector cu drepturi diferite de acces. Are comenzi pentru adăugare, listare, vizualizare, ștergere și filtrare de rapoarte, plus un sistem de jurnalizare a acțiunilor și legături simbolice către fișierele de rapoarte ale fiecărui district.t momentan am codul asta scris: *insert la tot codul copiat scris pana atunci*"

ulterior i-am sugerat o versiune mai robusta, a modificat folosirea strtokului, insa dupa ce am copiat functiile aveam destul de multe warrninguri asa ca am copiat tot codul iarasi si am incercat Claude.ai pe care l-am rugat sa-mi explice de unde apar warrningurile, in urma sugestilor oferite de Claude.ai am incercat sa modific codul astfel incat sa compileze.

Ce a fost generat?
acestea au fost versiunile generate initial de Gemini:
int parse_condition(const char *input, char *field, char *op, char *value) {
    if (!input || !field || !op || !value) return 0;

    // Copiem input intr-un buffer temporar pentru a folosi strtok (care modifica sirul)
    char temp[MAX_PATH];
    strncpy(temp, input, MAX_PATH - 1);
    temp[MAX_PATH - 1] = '\0';

    char *f = strtok(temp, ":");
    char *o = strtok(NULL, ":");
    char *v = strtok(NULL, ":");

    if (f && o && v) {
        strcpy(field, f);
        strcpy(op, o);
        strcpy(value, v);
        return 1;
    }

    return 0; // Format invalid
}
int match_condition(Report *r, const char *field, const char *op, const char *value) {
    if (strcmp(field, "severity_level") == 0) {
        int val = atoi(value);
        if (strcmp(op, "==") == 0) return r->severity_level == val;
        if (strcmp(op, ">=") == 0) return r->severity_level >= val;
        if (strcmp(op, "<=") == 0) return r->severity_level <= val;
        if (strcmp(op, ">")  == 0) return r->severity_level > val;
        if (strcmp(op, "<")  == 0) return r->severity_level < val;
    } 
    else if (strcmp(field, "category") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->category, value) == 0;
    }
    else if (strcmp(field, "inspector_name") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->inspector_name, value) == 0;
    }
    else if (strcmp(field, "report_id") == 0) {
        int val = atoi(value);
        if (strcmp(op, "==") == 0) return r->report_id == val;
    }
    else if (strcmp(field, "lat") == 0 || strcmp(field, "longi") == 0) {
        float val = atof(value);
        float r_val = (strcmp(field, "lat") == 0) ? r->lat : r->longi;
        if (strcmp(op, ">") == 0) return r_val > val;
        if (strcmp(op, "<") == 0) return r_val < val;
        // La float nu e recomandat == direct, dar am putea folosi o marja de eroare
    }

    return 0; // Camp sau operator necunoscut
}


Ce ai schimbat și de ce?
Am incercat sa fac codul mai robust, sa fie mai sigur, si pentru asta am facut anumite schimbari precum folosirea lui strtol() in loc de atoi() etc 


Ce ai învățat?
Am aflat niste detalii care pot face diferenta legate de programarea defensiva si securitate, maipularea robusta a sirurilor de caractere, eficenta si am mai invatat ca integrarea functiilor generate cu  ajutorul LLM-urilor poate dura cateva ore bune, nu e doar un copy-paste.