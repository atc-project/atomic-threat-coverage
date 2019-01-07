🇬🇧 [English version](README.md)  |   🇷🇺 [Русская версия](README_RU.md)  

# Atomic Threat Coverage

Automatycznie generowana analityczna baza wiedzy zaprojektowana, aby zwalczać zagrożenia na podstawie MITRE ATT&CK.

![](images/logo_v1.png)
<!-- ![](images/atc_description_v01.png) -->

Atomic Threat Coverage jest narzędziem, które pozwala na automatyczne generowanie analitycznej bazy wiedzy zaprojektowanej, aby zwalczać zagrożenia (na podstawie modelu "przeciwnika" przygotowanego przez [MITRE ATT&CK](https://attack.mitre.org/)) poprzez Detekcje, Reakcje, Przeciwdziałanie oraz Symulacje:

- **Detection Rules** — Reguły Wykrywania w oparciu o [Sigme](https://github.com/Neo23x0/sigma) — Generic Signature Format for SIEM Systems
- **Data Needed** — Wymagane Dane w celu odtworzenia konkretnego Zagrożenia
- **Logging Policies** — Polityki Logowania jakie muszą być skonfigurowane na urządzeniach wysyłające logi, aby móc zbierać Wymagane Dane
- **Triggers** — Wyzwalacze na podstawie [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — testy wykrywające Zagrożenie na podstawie MITRE ATT&CK
- **Response Playbooks** — Playbooki Reakcyjne aby reagować, gdy Reguła Wyzwalania zostanie wyzwolona przez konkretne Zagrożenie
- **Hardening Policies** — Polityki Hardeningu które muszą zostać zaimplementowane, aby przeciwdziałać konkretnemu Zagrożeniu
- **Mitigation Systems** — Systemy do Przeciwdziałania które muszą zostać wdrożone, aby przeciwdziałać konkretnemu Zagrożeniu

Atomic Threat Coverage jest wysoko zautomatyzowanym frameworkiem służącym do gromadzenia, rozwijania, wyjaśniania oraz dzielenia się odpowiednią analizą.

## Opis

### Motywacja

Istnieje wiele projektów, które dostarczają analizy (lub funkcjonalność) skupiającą się na konkretnych zagadnieniach ([Sigma](https://github.com/Neo23x0/sigma), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [MITRE CAR](https://car.mitre.org). Wszystkie z nich posiadają jedną słabość - istnieją we własnej przestrzeni. W rzeczywistości wszystko jest ściśle powiązane - dane do alertów nie biorą się znikąd, wygnerowane alerty nie idą w próżnię. Każda funkcja, jak dla przykładu zbieranie danych, administracja systemów, detekcji zagrożeń, reakcji na incydent itp są częścią kompleksowego procesu implementowanego przez wiele działów oraz wymagającego ich ścisłej współpracy.

Zdarza się, że problemy jednej funkcji mogą być w tańszy, prostszy i bardziej efektywny sposób rozwiązane przy pomocy metod stosowanych dla innej funkcji. Większość zadań nie może być rozwiązanych jedynie przy pomocy wyłącznie jednej funkcji. Każda z funkcji opiera się na możliwościach oraz jakości drugiej. Nie jest możliwa efektywna detekcja zagrożeń bez poprawnej kolekcji danych i wzbogacania ich. Nie możliwa jest także prawidłowa odpowiedź na zagrożenia bez zrozumienia, których technologii/systemów/środków można użyć do zablokowania konkretnego zagrożenia. Przeprowadzanie testów penetracyjnych lub ćwiczeń Red Team nie przynosi korzyści, jeśli nieznane są możliwości procesów, personelu i systemów do blokowania, wykrywania oraz reagowania na incydenty. Wszystko to wymaga bliskiej interakcji i zrozumienia między działami.

W praktyce problemy w kolaboracji wynikają z:

- Braku wspólnego modelu/klasyfikacji zagrożenia, wspólnej terminologii oraz języka do opisu zagrożeń
- Braku jednomyślnego pojmowania celu
- Braku prostego wyjaśnienia konkretnych wymogów
- Różnicy w kompetencjach 

Dlatego zdecydowaliśmy się stworzyć Atomic Threat Coverage - projekt mający na celu połączenie różnych funkcji w ramach jednej metodologii ([Lockheed Martin Intelligence Driven Defense®](https://www.lockheedmartin.com/en-us/capabilities/cyber/intelligence-driven-defense.html) lub [MITRE Threat-based Security](https://mitre.github.io/unfetter/about/)), modelu zagrożenia ([MITRE ATT&CK](https://attack.mitre.org/)) oraz dostarczenie efektywnego narzędzia do kolaboracji nad wspólnym wyzwaniem - zwalczaniem zagrożeń. 

### Dlaczego Atomic Threat Coverage 

Praca z wieloma <sup>[\[1\]](https://car.mitre.org)[\[2\]](https://eqllib.readthedocs.io/en/latest/)[\[3\]](https://github.com/palantir/alerting-detection-strategy-framework)[\[4\]](https://github.com/ThreatHuntingProject/ThreatHunting)</sup> repozytoriami analizy/detekcji często przypomina niekończącą się procedurę kopiuj/wklej, manualną adaptację informacji do formatu wewnętrzej bazy wiedzy, modeli detekcji czy mapowania na wewnętrzne metryki.

Postanowiliśmy zrobić to inaczej.

Atomic Threat Coverage jest narzędziem, które pozwala na stworzenie i utrzymywania **własnego** repozytorium analitycznego, importowanie danych z innych projektów (przykładowo [Sigma](https://github.com/Neo23x0/sigma), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) jak również z prywantej kopii tych projektów z **własnymi** analizami, oraz wyeksportowanie wszystkich informacje do czytelnego dla człowieka formatu, w stylu wiki, na dwa (jak dotąd) sposoby:

1. [Atlassian Confluence](https://www.atlassian.com/software/confluence) ([tutaj](https://atomicthreatcoverage.atlassian.net/wiki/spaces/DEMO/pages/10944874/win+susp+powershell+hidden+b64+cmd) znajduje się demo bazy wiedzy automatycznie wygenerowanej przez Atomic Threat Coverage)
2. [To repozytorium samo w sobie](Atomic_Threat_Coverage) — wiki stworzona przy użyciu plików markdown

Innymi słowy, nie potrzeba już samodzielenie pracować nad warstwą prezentacji manualnie. Wystarczy skupić się na wartościowej pracy (np. tworzenie reguł Sigma), a Atomic Threat Coverage automatycznie wygeneruje analityczną bazę danych ze wszystkimi danymi, mapując wszystkie wartościowe metryki. Gotowe do użycia, udostępniania i prezentowania kierownictwu, klientowi i kolegom repozytorium.

### Zasada działania

Wszystko zaczyna się od reguł Sigma, a kończy na czytelnym dla człowieka formacie w stylu wiki. Atomic Threat Coverage parsuje regułe oraz:

1. Mapuje Regułe Wykrywania do taktyki ATT&CK używając `tags` z reguły Sigma
2. Mapuje Regułe Wykrywania do tachniki ATT&CK używając `tags` z reguły Sigma
3. Mapuje Regułe Wykrywania do Wymaganych Danych używając `logsource` i sekcji `detection` z reguły Sigma
4. Mapuje Regułe Wykrywania do Wyzwalania (testy od Atomic Read Team) używając `tags` z reguły Sigma
5. Mapuje Politykę Logowania do Wymaganych Danych używając istniejącej już mapy w Wymaganych Danych
6. Za pomocą szablonów jinja (`scripts/templates`) konwertuje wszystko w strony Confluence oraz pliki Markdown
7. Zapisuje wszystkie pliki do lokalnego repozytorium oraz na serwer Confluence (w zależności od konfiguracji w `scripts/config.py`)
8. Tworzy plik `analytics.csv` do prostej analizy istniejących danych

### Od zaplecza

Dane w repozytorium:

```
├── analytics.csv
├── dataneeded
│   ├── DN_0001_windows_process_creation_4688.yml
│   ├── DN_0002_windows_process_creation_with_commandline_4688.yml
│   ├── DN_0003_windows_sysmon_process_creation_1.yml
│   ├── DN_0004_windows_account_logon_4624.yml
│   └── dataneeded_template.yml
├── detectionrules
│   └── sigma
├── enrichments
│   ├── EN_0001_cache_sysmon_event_id_1_info.yml
│   ├── EN_0002_enrich_sysmon_event_id_1_with_parent_info.yaml
│   └── EN_0003_enrich_other_sysmon_events_with_event_id_1_data.yml
├── loggingpolicies
│   ├── LP_0001_windows_audit_process_creation.yml
│   ├── LP_0002_windows_audit_process_creation_with_commandline.yml
│   ├── LP_0003_windows_sysmon_process_creation.yml
│   ├── LP_0004_windows_audit_logon.yml
│   └── loggingpolicy_template.yml
└── triggering
    └── atomic-red-team
```

#### Detection Rules

Detection Rules — Reguły Wykrywania są niezmodyfikowanymi [regułami Sigma](https://github.com/Neo23x0/sigma/tree/master/rules). Domyślnie Atomic Threat Coverage używa reguł z oficjalnego repozytorium aczkolwiek nic nie stoi na przeszkodzie, aby dołożyć reguły z własnego rezpotyrium.

<details>
  <summary>Plik yaml Detection Rule (kliknij aby rozwinąć)</summary>
  <img src="images/sigma_rule.png" />
</details>

<details>
  <summary>Strona confluence stworzona w pełni automatycznie (kliknij aby rozwinąć)</summary>
  <img src="images/dr_confluence_v1.png" />
</details>

<details>
  <summary>Strona markdown (Gitlab) stworzona w pełni automatycznie (kliknij aby rozwinąć)</summary>
  <img src="images/dr_markdown_v1.png" />
</details>

<br>
Linki do Wymaganych Danych, Wyzwalaczy oraz artykułów na stronie ATT&CK są generowane automatycznie.  
Reguła Sigma, zapytanie dla Kibany, X-Pack Watcher oraz GrayLog są generowane oraz dodawane automatycznie (istnieje możliwość rozszerzenia generowanych zapytań na podstawie wspieranych przez projekt Sigma platform [Sigma Supported Targets](https://github.com/Neo23x0/sigma#supported-targets) )

#### Data Needed

<details>
  <summary>Plik yaml Data Needed (kliknij aby rozwinąć)</summary>
  <img src="images/dataneeded_v1.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona confluence (kliknij aby rozwinąć)</summary>
  <img src="images/dn_confluence_v1.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona markdown (kliknij aby rozwinąć)</summary>
  <img src="images/dn_markdown_v1.png" />
</details>

<br>
Ten moduł ma na celu ułatwienie komunikacji z zespołami SIEM/LM/Data Engineering. Zawiera następujęce dane:

- Przykładowy czysty log aby opisać jakich danych należy się spodziewać lub zbierać
- Opis danych do zebrania (Platform/Type/Channel/etc) - wymagany do wyznaczenia mapowania Polityk Logowania
- Listę pól wymaganą do wyznaczenia mapowania Reguł Wykrywania, Playbooki Reakcyjnych oraz wygenerowania pliku `analytics.csv`

#### Logging Policies

<details>
  <summary>Plik yaml Polityki Logowania (kliknij aby rozwinąć)</summary>
  <img src="images/loggingpolicy.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona confluence (kliknij aby rozwinąć)</summary>
  <img src="images/lp_confluence_v1.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona markdown (kliknij aby rozwinąć)</summary>
  <img src="images/lp_markdown_v1.png" />
</details>

<br>
Ten moduł ma na celu wyjaśnienie zespołom SIEM/LM/Data Engineering, lub ogólnie działom IT jakie polityki logowania muszą być skonfigurowane, aby odpowiednie dane (Wymagane Dane) były wysyłane w celu poprawnego działania Reguł Wykrywania by wykryć konkretne Zagrożenia. Dodatkowo zawarto w nim instrukcje jak krok po kroku należy takie polityki skonfigurować.

#### Wyzwalacze

Wyzwalacze to niezmodyfikowane [testy Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics). Domyślnie Atomic Threat Coverage używa "atomics" z oficjalnego repozytorium, ale nic nie stoi na przeszkodzie by dodać "atomics" z własnego repozytorium.

<details>
  <summary>Plik yaml Wyzwalacza (kliknij aby rozwinąć)</summary>
  <img src="images/trigger.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona confluence (kliknij aby rozwinąć)</summary>
  <img src="images/trigger_confluence_v1.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona markdown (kliknij aby rozwinąć)</summary>
  <img src="images/tg_markdown_v1.png" />
</details>

<br>
Ten moduł pozwala na techniczne przetestowanie systemu. Szczegółowy opis można znaleźć na oficjalnej [stronie](https://atomicredteam.io). 

#### Analytics.csv

Atomic Threat Coverage generuje plik [analytics.csv](analytics.csv) z listą wszystkich zmapowanych danych do filtrowania i prostej analizy. Ten plik powinien odpowiedzień na następujące pytania:

- W jakich zródłach danych można znaleźć konkrente typy danych (przykładowo nazwa domeny, nazwa użytkownika, hash etc.) podczas fazy identyfikacji?
- Jakie dane potrzebuje zbierać, aby wykryć konkretne zagrożenie?
- Które Polityki Logowania potrzebuję wdrożyć, aby zbierać dane do wykrywania konkretnego zagrożenia?
- Które Polityki Logowania mogę wdrożyć wszędzie, a które tylko na urządzeniach "krytycznych"?
- Które dane pozwalają mi na alarmy high-fidelity? (Priorytetyzacja wdrażania polityk logowania, itd.)
- itd

Takie mapowanie powinno pomóc organizacji priorytetyzować wykrywanie zagrożeń w przełożeniu na *pieniądze*, np:

- Jeśli zbieramy wszystkie Wymagane Dane ze wszystkich urządzen dla wszystkich Reguł Wykrywania, oznacza to _X_ EPS (Events Per Second) z określonymi środkami na magazynowanie danych i ich procesowanie. 
- Jeśli zbieramy Wymagane Dane tylko dla alarmów high-fidelity i tylko na "krytycznych" urządzeniach, oznacza to _Y_ EPS (Events Per Second) z określonymi środkami na magazynowanie danych i ich procesowanie
- itd

## Nasze cele

1. Zachęcenie społeczności do używania formatu plików [Sigma](https://github.com/Neo23x0/sigma)
2. Zachęcenie społeczności do używania formatu testów [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) 
3. Promować dzielenie się informacją na temat zagrożeń
4. Zautomatyzować większość ręcznej pracy
5. Dostarczenie społeczności bezpieczeństwa informacji framework, który poprawi komunikacje z innymi działami, ogólną analizę, dewelopowanie i udostępnianie workflow'u

## Workflow

1. Dodaj swoje własne reguły [Sigma](https://github.com/Neo23x0/sigma) (jeśli posiadasz) do folderu `detectionrules`
2. Dodac folder z własnymi testami [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (jeśli posiadasz) do folderu `triggering`
3. Dodaj odpowiednie Wymagane Dane związane z regułami Sigma do folderu `dataneeded` (szablon dostępny jest w `dataneeded/dataneeded_template.yml`)
4. Dodaj odpowiednie Polityki Logowania związane z Wymaganymi Danymi do folderu `loggingpolicies` (szablon dostępny jest w `loggingpolicies/loggingpolicy_template.yml`)
5. Skonfiguruj ustawienia eksportowania (markdown/confluence) - `scripts/config.py`
6. Wykonaj polecenie `make` w głównym katalogu repozytorium

## Aktualny status: Proof of Concept

Ten projekt jest aktualnie w fazie Proof of Concept i został napisany w kilka wieczorów. Nie działa dla wszystkich reguł Sigma. Przepiszemy większość skryptów, dopiszemy obsługę wszytkich oryginalnych reguł [Sigma](https://github.com/Neo23x0/sigma) oraz dodamy inne moduły (jak Playbook'i). Aktualnie chcemy pokazać dzaiałający przykład procesowania danych (reguł, itd), aby podyskutować ze społecznością, otrzymać feedback i jakiekolwiek sugestie.

## Wymagania

- Unix OS lub [Windows Subsystem for Linux (WSL)](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux) (wymagane do wykonania polecenia `make`)
- Python 3.7.1
- Biblioteka python - [jinja2](https://pypi.org/project/Jinja2/)
- (Darmowy) Plugin do Confluence'a - [Render Markdown](https://marketplace.atlassian.com/apps/1212654/render-markdown) (open-source)

## Autorzy

- Daniil Yugoslavskiy, [@yugoslavskiy](https://github.com/yugoslavskiy)
- Jakob Weinzettl, [@mrblacyk](https://github.com/mrblacyk)
- Mateusz Wydra, [@sn0w0tter](https://github.com/sn0w0tter)
- Mikhail Aksenov, [@AverageS](https://github.com/AverageS)

## TODO

- [ ] Fix `analytics.csv` generation
- [ ] Develop Polish and Russian version of the README
- [ ] Rewrite `make` and all bash scripts in python for compatibility with Windows
- [ ] Rewrite main codebase in a proper way
- [ ] Add contribution description
- [ ] Create developer guide (how to create custom fields)
- [ ] Implement consistent Data Model (fields naming)
- [ ] Add the rest of Data Needed for default Sigma rules
- [ ] Add the rest of Logging Policies for all Data Needed
- [ ] Define new Detection Rule naming scheme (separate Events and Alerts)
- [ ] Develop docker container for the tool
- [ ] Create [MITRE ATT&CK Navigator](https://mitre.github.io/attack-navigator/enterprise/) profile generator per data type
- [ ] Create new entity called "Enrichments" which will define how to enrich specific Data Needed
- [ ] Implement new entity — "Visualisation" with Kibana visualisations/dashboards stored in yaml files and option to convert them into curl commands for uploading them into Elasticsearch
- [ ] Implement "Playbook" entity (based on Detection Rule and Data Needed) with automatic TheHive Case Templates generation (actionable Playbook)

## Linki

[\[1\]](https://car.mitre.org) MITRE Cyber Analytics Repository  
[\[2\]](https://eqllib.readthedocs.io/en/latest/) Endgame EQL Analytics Library  
[\[3\]](https://github.com/palantir/alerting-detection-strategy-framework) Palantir Alerting and Detection Strategy Framework  
[\[4\]](https://github.com/ThreatHuntingProject/ThreatHunting) The ThreatHunting Project  

## Licencja

Dostępna w pliku [LICENSE](LICENSE).
