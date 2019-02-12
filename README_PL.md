🇬🇧 [English version](README.md)  |   🇷🇺 [Русская версия](README_RU.md)  

# Atomic Threat Coverage

Automatycznie generowana analityczna baza wiedzy zaprojektowana, aby zwalczać zagrożenia na podstawie MITRE ATT&CK.

![](images/logo_v1.png)

Atomic Threat Coverage jest narzędziem, które pozwala na automatyczne generowanie analitycznej bazy wiedzy zaprojektowanej, aby zwalczać zagrożenia (na podstawie modelu "przeciwnika" przygotowanego przez [MITRE ATT&CK](https://attack.mitre.org/)) poprzez Detekcje, Reakcje, Przeciwdziałanie oraz Symulacje:

- **Detection Rules** — Reguły Wykrywania w oparciu o [Sigma](https://github.com/Neo23x0/sigma) — Generic Signature Format for SIEM Systems
- **Data Needed** — Wymagane Dane w celu odtworzenia konkretnego Zagrożenia
- **Logging Policies** — Polityki Logowania jakie muszą być skonfigurowane na urządzeniach wysyłające logi, aby móc zbierać Wymagane Dane
- **Enrichments** — Wzbogacenia dla konkretnych Wymaganych Danych, które wymagane są dla niektórych Reguł Wykrywania
- **Triggers** — Wyzwalacze na podstawie [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — testy wykrywające Zagrożenie na podstawie MITRE ATT&CK
- **Response Actions** — Akcje, które zostają wykonane podczas incydent bezpieczeństwa
- **Response Playbooks** — Playbooki Reakcyjne, aby reagować, gdy Reguła Wyzwalania zostanie wyzwolona przez konkretne Zagrożenie
- **Hardening Policies** — Polityki Hardeningu, które muszą zostać zaimplementowane, aby przeciwdziałać konkretnemu Zagrożeniu
- **Mitigation Systems** — Systemy do Przeciwdziałania, które muszą zostać wdrożone, aby przeciwdziałać konkretnemu Zagrożeniu

Atomic Threat Coverage jest wysoko zautomatyzowanym frameworkiem służącym do gromadzenia, rozwijania, wyjaśniania oraz dzielenia się odpowiednią analizą.

## Opis

### Motywacja

Istnieje wiele projektów, które dostarczają analizy (lub funkcjonalność) skupiającą się na konkretnych zagadnieniach ([Sigma](https://github.com/Neo23x0/sigma), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [MITRE CAR](https://car.mitre.org)). Wszystkie z nich posiadają jedną słabość - istnieją we własnej przestrzeni. W rzeczywistości wszystko jest ściśle powiązane - dane do alertów nie biorą się znikąd, wygnerowane alerty nie idą w próżnię. Każda funkcja, jak dla przykładu zbieranie danych, administracja systemów, detekcji zagrożeń, reakcji na incydent itp są częścią kompleksowego procesu implementowanego przez wiele działów oraz wymagającego ich ścisłej współpracy.

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

1. Mapuje **Detection Rule** do taktyki i techniki ATT&CK używając `tags` z reguły Sigma
2. Mapuje **Detection Rule** do **Data Needed** używając `logsource` i sekcji `detection` z reguły Sigma
3. Mapuje **Detection Rule** do **Triggers** (testy od Atomic Read Team) używając `tags` z reguły Sigma
4. Mapuje **Detection Rule** do **Enrichments** używając istniejącego już mapowania wewnątrz **Detection Rule**
5. Mapuje **Playbooki Reakcyjne** do taktyki i techniki ATT&CK używając istniejącego już mapowania wewnątrz **Detection Rule**
6. Mapuje **Playbooki Reakcyjne** do **Response Actions** używając istniejącego już mapowania wewnątrz **Detection Rule**
7. Mapuje **Logging Policies** do **Data Needed** używając istniejącej już mapy w Wymaganych Danych
8. Za pomocą szablonów jinja (`scripts/templates`) konwertuje wszystko w strony Confluence oraz pliki Markdown
9. Zapisuje wszystkie pliki do lokalnego repozytorium oraz na serwer Confluence (w zależności od konfiguracji w `scripts/config.py`)
10. Tworzy pliki `analytics.csv` oraz `pivoting.csv` do prostej analizy istniejących danych
11. Tworzy plik `atc_export.json` - profil [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/) do wizualizacji aktualnie zdolności wykrywania zagrożeń

### Od zaplecza

Dane w repozytorium:

```
├── analytics.csv
├── pivoting.csv
├── data_needed
│   ├── DN_0001_4688_windows_process_creation.yml
│   ├── DN_0002_4688_windows_process_creation_with_commandline.yml
│   └── dataneeded.yml.template
├── detection_rules
│   └── sigma/
├── enrichments
│   ├── EN_0001_cache_sysmon_event_id_1_info.yml
│   ├── EN_0002_enrich_sysmon_event_id_1_with_parent_info.yaml
│   └── enrichment.yml.template
├── logging_policies
│   ├── LP_0001_windows_audit_process_creation.yml
│   ├── LP_0002_windows_audit_process_creation_with_commandline.yml
│   └── loggingpolicy_template.yml
├── response_actions
│   ├── RA_0001_identification_get_original_email.yml
│   ├── RA_0002_identification_extract_observables_from_email.yml
│   └── respose_action.yml.template
├── response_playbooks
│   ├── RP_0001_phishing_email.yml
│   ├── RP_0002_generic_response_playbook_for_postexploitation_activities.yml
│   └── respose_playbook.yml.template
└── triggering
    └── atomic-red-team/
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

Linki do Data Needed, Trigger oraz artykułów na stronie ATT&CK są generowane automatycznie.  
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
- Opis danych do zebrania (Platform/Type/Channel/etc) - wymagany do mapowania Detection Rules
- Listę pól wymaganą do mapowania Detection Rules, Response Playbooks oraz wygenerowania pliku `analytics.csv`

#### Logging Policies

<details>
  <summary>Plik yaml Logging Policy (kliknij aby rozwinąć)</summary>
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

Ten moduł ma na celu wyjaśnienie zespołom SIEM/LM/Data Engineering, lub ogólnie działom IT jakie polityki logowania muszą być skonfigurowane, aby odpowiednie dane (Data Needed) były wysyłane w celu poprawnego działania reguł (Detection Rules) by wykryć konkretne Zagrożenia. Dodatkowo zawarto w nim instrukcje jak krok po kroku należy takie polityki skonfigurować.

#### Enrichments

<details>
  <summary>Plik yaml Enrichments (kliknij aby rozwinąć)</summary>
  <img src="images/enrichment.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona confluence (kliknij aby rozwinąć)</summary>
  <img src="images/enrichment_confluence.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona markdown (kliknij aby rozwinąć)</summary>
  <img src="images/enrichment_markdown.png" />
</details>

<br>

Ten moduł ma za zadanie uprościć komunikacje z zespołami SIEM/LM/Data Engineering lub ogólnie z działami IT. Zawiera następujące informacje:

- Lista danych (Data Needed), które mogłby by być "wzbogacone"
- Opis wzbogacenia (nowe pola, tłumaczenie/zmiana nazw pól, rozwiązywanie nazw DNS, itd)
- Przykład implementacji (na przykład, konfiguracja Logstash)

W ten sposób będzie można w prosty sposób wyjaśnić dlaczego wzbogacenie (logów/danych) jest potrzebne (mapowanie do Detection Rules) jak i wskazanie konkretnych platform do wzbogacania danych (na przykład Logstash).

#### Triggers

Wyzwalacze to niezmodyfikowane [testy Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics). Domyślnie Atomic Threat Coverage używa "atomics" z oficjalnego repozytorium, ale nic nie stoi na przeszkodzie by dodać "atomics" z własnego repozytorium.

<details>
  <summary>Plik yaml Trigger (kliknij aby rozwinąć)</summary>
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

#### Response Actions

<details>
  <summary>Plik yaml Response Actions (kliknij aby rozwinąć)</summary>
  <img src="images/response_action.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona confluence (kliknij aby rozwinąć)</summary>
  <img src="images/response_action.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona markdown (kliknij aby rozwinąć)</summary>
  <img src="images/response_action.png" />
</details>

<br>

Ten moduł używany jest do budowania Response Playbooks.

#### Response Playbooks

<details>
  <summary>Plik yaml Response Playbooks (kliknij aby rozwinąć)</summary>
  <img src="images/response_playbook.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona confluence (kliknij aby rozwinąć)</summary>
  <img src="images/response_playbook.png" />
</details>

<details>
  <summary>Automatycznie wygenerowana strona markdown (kliknij aby rozwinąć)</summary>
  <img src="images/response_playbook.png" />
</details>

<br>

Ten moduł używany jest jako plan reakcji na incydent bezpieczeństwa dla konkretnego zagrożenia.

#### analytics.csv

Atomic Threat Coverage generuje plik [analytics.csv](analytics.csv) z listą wszystkich zmapowanych danych do filtrowania i prostej analizy. Ten plik powinien odpowiedzień na następujące pytania:

- W jakich zródłach danych można znaleźć konkrente typy danych (przykładowo nazwa domeny, nazwa użytkownika, hash etc.) podczas fazy identyfikacji?
- Które polityki logowania (Logging Policies) potrzebuję wdrożyć, aby zbierać dane do wykrywania konkretnego zagrożenia?
- Które polityki logowania (Logging Policies) mogę wdrożyć wszędzie, a które tylko na urządzeniach "krytycznych"?
- Które dane pozwalają mi na alarmy high-fidelity? (Priorytetyzacja wdrażania polityk logowania, itd.)
- itd

Takie mapowanie powinno pomóc organizacji priorytetyzować wykrywanie zagrożeń w przełożeniu na *pieniądze*, np:

- Jeśli zbieramy wszystkie dane (Data Needed) ze wszystkich urządzen dla wszystkich reguł (Detection Rules), oznacza to _X_ EPS (Events Per Second) z określonymi środkami na magazynowanie danych i ich procesowanie. 
- Jeśli zbieramy dane (Data Needed) tylko dla alarmów high-fidelity i tylko na "krytycznych" urządzeniach, oznacza to _Y_ EPS (Events Per Second) z określonymi środkami na magazynowanie danych i ich procesowanie
- itd

#### pivoting.csv

Atomic Threat Coverage generuje plik [pivoting.csv](pivoting.csv) z listą wszystkich pól (z Data Needed) zmapowane do opisu Data Needed dla konkretnego zastosowania - dostarcza to informacje na temat urządzeń końcowych, gdzie można znaleźć jakieś konkretne dane, na przykład nazwa domenowa, nazwa użytkownika, hash, itd.

## Nasze cele

1. Zachęcenie społeczności do używania formatu plików [Sigma](https://github.com/Neo23x0/sigma) (więcej osób wnoszących wkład, więcej i lepsze konwertery)
2. Zachęcenie społeczności do używania formatu testów [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (więcej osób wnoszących wkład - więcej testów)
3. Promować dzielenie się informacją na temat zagrożeń
4. Zautomatyzować większość ręcznej pracy
5. Dostarczenie społeczności bezpieczeństwa informacji framework, który poprawi komunikacje z innymi działami, ogólną analizę, dewelopowanie i udostępnianie workflow'u

## Workflow

1. Dodaj swoje własne reguły [Sigma](https://github.com/Neo23x0/sigma) (jeśli posiadasz) do folderu `detectionrules`
2. Dodaj folder z własnymi testami [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (jeśli posiadasz) do folderu `triggering`
3. Dodaj odpowiednie Data Needed związane z regułami Sigma do folderu `dataneeded` (szablon do tworzenia nowych dostępny jest w [tutaj](dataneeded/dataneeded_template.yml))
4. Dodaj odpowiednie Logging Policies związane z Data Needed do folderu `loggingpolicies` (szablon do tworzenia nowych dostępny jest [tutaj](loggingpolicies/loggingpolicy_template.yml`))
5. Dodaj odpowiednie Enrichments do folderu `enrichments` (szablon do tworzenia nowych dostępny jest [tutaj](enrichments/enrichment.yml.template))
6. Dodaj odpowiednie Response Actions do folderu `response_actions` (szablon do tworzenia nowych dostępny jest [tutaj](response_actions/respose_action.yml.template))
7. Dodaje odpowiednie Response Playbooks do folderu `response_playbooks` (szablon do tworzenia nowych dostępny jest [tutaj](response_playbooks/respose_playbook.yml.template))
8. Skonfiguruj ustawienia eksportowania (markdown/confluence) - `scripts/config.py`
9. Wykonaj polecenie `make` w głównym katalogu repozytorium

## Aktualny status: Alfa

Projekt aktualnie jest w fazie Alfa. Nie wspiera wszystkich istniejących reguł Sigma (aktualne pokrycie to ~80%). Są też inne moduły, które muszą zostać wydewelopowane (na przykład Systemy do Przeciwdziałania). Ciepło przyjmujemy jakikolwiek feedback i sugestie w celu udoskonalenia projektu.

## Wymagania

- Unix OS lub [Windows Subsystem for Linux (WSL)](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux) (wymagane do wykonania polecenia `make`)
- Python 3.7.1
- Biblioteka python - [jinja2](https://pypi.org/project/Jinja2/)
- (Darmowy) Plugin do Confluence'a - [Render Markdown](https://marketplace.atlassian.com/apps/1212654/render-markdown) (open-source)

## FAQ

#### Czy moje prywatne dane (Detection Rules, Logging Policies, itd) są gdzieś wysyłane?

Nie. Jedynie do instancji confluence, która została wskazana w pliku konfiguracyjnym `scripts/config.py`. Atomic Threat Coverage nie łączy się do żadnego innego zdalnego urządzenia. Jest to łatwo weryfikowalne - kod w całości udostępniony.

#### Co macie na myśli pisząc "promować dzielenie się informacją na temat zagrożeń"?

Chcemy, żeby używane były formaty promowane przez społeczeństwo dla (przynajmniej) Detection Rules ([Sigma](https://github.com/Neo23x0/sigma)) oraz Triggers ([Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)). W przyszłości mamy nadzieje, że użytkownicy będą skłonni i chętni, aby podzielić się ze społeczeństwem ciekawymi informacjami na temat zagrożeń. Natomiast zero presji, to tylko i wyłącznie Twoja decyzja.

#### Jak mogę dodać nowy Trigger, Detection Rule lub czegokolwiek innego do mojego prywatnego repozytorium Atomic Threat Coverage?

Najprościej jest podążać krokami zdefiniowanymi w [workflow](#workflow). Po prostu dodaj swoje reguły do już skonfigurowanych folderów dla danego typu informacji.

Bardziej "produkcyjnym" podejściem jest skonfigurowanie prywatnych repozytoriów [Sigma](https://github.com/Neo23x0/sigma) i [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) jako projektów [submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) prywatnego repozytorium Atomic Threat Coverage. Po zrobieniu tego pozostaje jedynie skonfigurowanie odpowiednio ścieżek do nich w `scripts/config.py`. Po skonfigurowaniu, Atomic Threat Coverage zacznie korzystać z nich do tworzenia bazy wiedzy.

#### Sigma nie wspiera paru moich reguł (Detection Rules). Czy używać w takim razie Atomic Threat Coverage?

Oczywiście. My również mamy kilka reguł, które nie są automatycznie konwertowane przez Sigma do zapytań SIEM/LM. Dalej używamy formatu Sigma dla takich reguł używając niewspieranej logiki detekcji w sekcji "condition". Następnie zespoły SIEM/LM manulanie tworzą reguły bazując na opisie tego pola. Atomic Threat Coverage to nie tylko automatyczne generowania zapytań oraz dokumentacji, Atomic Threat Coverage dalej przynosi parę pozytywów dla analizy, których nie dałoby się wykorzystać z regułami w innym formacie niż Sigma.

## Autorzy

- Daniil Yugoslavskiy, [@yugoslavskiy](https://github.com/yugoslavskiy)
- Jakob Weinzettl, [@mrblacyk](https://github.com/mrblacyk)
- Mateusz Wydra, [@sn0w0tter](https://github.com/sn0w0tter)
- Mikhail Aksenov, [@AverageS](https://github.com/AverageS)

## Podziękowania

- Igor Ivanov, [@lctrcl](https://github.com/lctrcl) za współpracę nad początkowymi typami danych oraz regułami mapowania
- Andrey, [Polar_Letters](https://www.behance.net/Polar_Letters) za logo
- [Sigma](https://github.com/Neo23x0/sigma), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [TheHive](https://blog.thehive-project.org) oraz [Elastic Common Schema](https://github.com/elastic/ecs) za inspitacje do stworzenia tego projektu
- MITRE [ATT&CK](https://attack.mitre.org/) za umożliwienie stworzenia tego wszystkiego

## TODO

- [ ] Wydewelopowanie generowania szablonów TheHive Case bazując na Response Playbooks
- [ ] Wydewelopowanie kontenera docker dla tego narzędzia
- [ ] Implementacja modułu "Mitigation Systems"
- [ ] Implementacja modułu "Hardening Policies" 
- [ ] Implementacja jednolitego Modelu Danych (nazwy pól)
- [ ] Implementacja nowego modułu - "Visualisation" jako pliki yaml z wizaulizacją/dashboardami Kibana z możliwością przekonwertowania do komend curl w celu wrzucenia ich do Elasticsearch

## Linki

[\[1\]](https://car.mitre.org) MITRE Cyber Analytics Repository  
[\[2\]](https://eqllib.readthedocs.io/en/latest/) Endgame EQL Analytics Library  
[\[3\]](https://github.com/palantir/alerting-detection-strategy-framework) Palantir Alerting and Detection Strategy Framework  
[\[4\]](https://github.com/ThreatHuntingProject/ThreatHunting) The ThreatHunting Project  

## Licencja

Dostępna w pliku [LICENSE](LICENSE).
