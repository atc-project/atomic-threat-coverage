🇷🇺 [Русская версия](README_RU.md)  | 🇵🇱 [Polska wersja](README_PL.md)

# Atomic Threat Coverage

Actionable analytics designed to combat threats based on MITRE's [ATT&CK](https://attack.mitre.org/).

![](images/logo_v1.png)

Atomic Threat Coverage is tool which allows you to automatically generate actionable analytics, designed to combat
threats (based on the [MITRE ATT&CK](https://attack.mitre.org/) adversary model) from Detection, Response, Mitigation
and Simulation perspectives:

- **Detection Rules** based on [Sigma](https://github.com/Neo23x0/sigma) — Generic Signature Format for SIEM Systems
- **Data Needed** to be collected to produce detection of specific Threat
- **Logging Policies** need to be configured on data source to be able to collect Data Needed
- **Enrichments** for specific Data Needed which required for some Detection Rules
- **Triggers** based on [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — detection tests based on
  MITRE's ATT&CK
- **Response Playbooks** based on [atc-react](https://github.com/atc-project/atc-react) — Security Incident Response
  Playbooks for reacting on specific Threat
- **Mitigation Policies** based on [atc-mitigation](https://github.com/atc-project/atc-mitigation) need to be deployed
  and/or configured to mitigate specific Threat
- **Visualisations** for creating Threat Hunting / Triage Dashboards
- **Customers** of the analytics — could be internal or external. This entity needed to tracking the implementation

Atomic Threat Coverage is highly automatable framework for accumulation, development and sharing actionable analytics.

## Description

Atomic Threat Coverage is a framework that provides you with ability to automatically generate Confluence and Markdown
knowledge bases (as well as the [other analytics](https://github.com/atc-project/atomic-threat-coverage#how-it-works)),
with a mapping of different entities to each other using MITRE ATT&CK techniques IDs.

Here are links to our demo environment where you can see the outcome of the framework usage:

- Automatically
  generated [Atlassian Confluence knowledge base](https://atomicthreatcoverage.atlassian.net/wiki/spaces/ATC/pages/126025996/WMI+Persistence+-+Script+Event+Consumer)
- Automatically generated [Markdown knowledge base](Atomic_Threat_Coverage)

### Motivation

There are plenty decent projects which provide analytics (or functionality) of specific focus (
i.e. [Sigma](https://github.com/Neo23x0/sigma) -
Detection, [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Simulation, etc). All of them have one
weakness — they exist in the vacuum of their area. In reality everything is tightly connected — data for alerts doesn't
come from nowhere, and generated alerts don't go nowhere. Data collection, security systems administration, threat
detection, incident response etc are parts of bigger and more comprehensive process which requires close collaboration
of various departments.

Sometimes problems of one function could be solved by methods of other function in a cheaper, simpler and more efficient
way. Most of the tasks couldn't be solved by one function at all. Each function is based on abilities and quality of
others. There is no efficient way to detect and respond to threats without proper data collection and enrichment. There
is no efficient way to respond to threats without understanding of which technologies/systems/measures could be used to
block specific threat. There is no reason to conduct penetration test or Red Team exercise without understanding of
abilities of processes, systems and personal to combat cyber threats. All of these require tight collaboration and
mutual understanding of multiple departments.

In practice there are difficulties in collaboration due to:

- Absence of common threat model/classification, common terminology and language to describe threats
- Absence common goals understanding
- Absence of simple and straightforward way to explain specific requirements
- Difference in competence level (from both depth and areas perspectives)

That's why we decided to create Atomic Threat Coverage — project which connects different functions/processes under
unified Threat Centric
methodology ([Lockheed Martin Intelligence Driven Defense®](https://www.lockheedmartin.com/en-us/capabilities/cyber/intelligence-driven-defense.html)
aka [MITRE Threat-based Security](https://mitre.github.io/unfetter/about/)), threat
model ([MITRE ATT&CK](https://attack.mitre.org/)) and provide security teams an efficient tool for collaboration on one
main challenge — combating threats.

### Why Atomic Threat Coverage

Work with
existing <sup>[\[1\]](https://car.mitre.org)[\[2\]](https://eqllib.readthedocs.io/en/latest/)[\[3\]](https://github.com/palantir/alerting-detection-strategy-framework)[\[4\]](https://github.com/ThreatHuntingProject/ThreatHunting)</sup>
analytics/detections repositories looks like endless copy/pasting job, manual adaptation of the information into
internal analytics knowledge base format, detections data model, mappings to internal valuable metrics and entities etc.

We decided to make it different.

Atomic Threat Coverage is a framework which allows you to create and maintain **your own** analytics repository, import
analytics from other projects (like [Sigma](https://github.com/Neo23x0/sigma)
, [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), as well as private forks of these projects with **
your own** analytics) and do export into human-readable wiki-style pages in two (for now) platforms:

1. [Atlassian Confluence](https://www.atlassian.com/software/confluence)
   pages ([here](https://atomicthreatcoverage.atlassian.net/wiki/spaces/ATC/pages/126025996/WMI+Persistence+-+Script+Event+Consumer)
   is the demo of automatically generated knowledge base)
2. [This repo itself](Atomic_Threat_Coverage) — automatically generated markdown formated wiki-style pages

In other words, you don't have to work on data representation layer manually, you work on meaningful atomic pieces of
information (like Sigma rules), and Atomic Threat Coverage will automatically create analytics database with all
entities, mapped to all meaningful, actionable metrics, ready to use, ready to share and show to leadership, customers
and colleagues.

### How it works

![](images/atc_scheme_v2.jpg)

Everything starts from Sigma rule and ends up with human-readable wiki-style pages and other valuable analytics. Atomic
Threat Coverage parses it and:

1. Maps Detection Rule to ATT&CK Tactic and Technique using `tags` from Sigma rule
2. Maps Detection Rule to Data Needed using `logsource` and `detection` sections from Sigma rule
3. Maps Detection Rule to Triggers (Atomic Red Team tests) using `tags` from Sigma rule
4. Maps Detection Rule to Enrichments using references inside Detection Rule
5. Maps Response Playbooks to ATT&CK Tactic and Technique using references inside Response Playbooks
6. Maps Response Actions to Response Playbooks using references inside Response Playbooks
7. Maps Logging Policies to Data Needed using references inside Data Needed
8. Maps Detection Rules, Data Needed and Logging Policies into Customers using references inside Customers entity
9. Converts everything into Confluence and Markdown wiki-style pages using jinja templates (`scripts/templates`)
10. Pushes all pages to local repo and Confluence server (according to configuration provided in `config.yml`)
11. Creates [Elasticsearch](https://www.elastic.co/products/elasticsearch) index for visualisation and analysis of
    existing data in [Kibana](https://www.elastic.co/products/kibana)
12. Creates [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/) profile for visualisation of
    current detection abilities per Customer
13. Creates [TheHive](https://thehive-project.org) Case Templates, build on top of Response Playbooks
14. Creates `analytics.csv` and `pivoting.csv` files for simple analysis of existing data
15. Creates Dashboards json files for uploading to Kibana

### Under the hood

Data in the repository:

```
├── analytics/
│   ├── generated/
│   │   ├── analytics.csv
│   │   ├── pivoting.csv
│   │   ├── atc_es_index.json
│   │   ├── thehive_templates/
│   │   │   └── RP_0001_phishing_email.json
│   │   └── attack_navigator_profiles/
│   │   │   ├── atc_attack_navigator_profile.json
│   │   │   ├── atc_attack_navigator_profile_CU_0001_TESTCUSTOMER.json
│   │   │   └── atc_attack_navigator_profile_CU_0002_TESTCUSTOMER2.json
│   │   └── visualizations/
│   │   │   └── os_hunting_dashboard.json
│   └── predefined/
│   │   ├── atc-analytics-dashboard.json
│   │   ├── atc-analytics-index-pattern.json
│   │   └── atc-analytics-index-template.json
├── customers/
│   ├── CU_0001_TESTCUSTOMER.yml
│   ├── CU_0002_TESTCUSTOMER2.yml
│   └── customer.yml.template
├── data_needed/
│   ├── DN_0001_4688_windows_process_creation.yml
│   ├── DN_0002_4688_windows_process_creation_with_commandline.yml
│   └── dataneeded.yml.template
├── detection_rules/
│   └── sigma/
├── enrichments/
│   ├── EN_0001_cache_sysmon_event_id_1_info.yml
│   ├── EN_0002_enrich_sysmon_event_id_1_with_parent_info.yaml
│   └── enrichment.yml.template
├── logging_policies/
│   ├── LP_0001_windows_audit_process_creation.yml
│   ├── LP_0002_windows_audit_process_creation_with_commandline.yml
│   └── loggingpolicy_template.yml
├── response
│   └── atc-react/
├── mitigation
│   └── atc-mitigation/
├── triggers/
│   └── atomic-red-team/
└── visualizations/
    ├── dashboards/
    │   ├── examples/
    │   │   └── test_dashboard_document.yml
    │   └── os_hunting_dashboard.yml
    └── visualizations/
        ├── examples/
        │   └── vert_bar.yml
        └── wmi_activity.yml
```

#### Detection Rule

Detection Rules are unmodified [Sigma rules](https://github.com/Neo23x0/sigma/tree/master/rules). By default Atomic
Threat Coverage uses rules from official repository but you can (*should*) use rules from your own private fork with
analytics relevant for you.

<details>
  <summary>Detection Rule yaml (click to expand)</summary>
  <img src="images/sigma_rule.png" />
</details>

<details>
  <summary>Automatically created confluence page (click to expand)</summary>
  <img src="images/dr_confluence_v1.png" />
</details>

<details>
  <summary>Automatically created markdown (GitLab) page (click to expand)</summary>
  <img src="images/dr_markdown_v1.png" />
</details>

<br>

Links to Data Needed, Trigger, and articles in ATT&CK are generated automatically.
Sigma rule, Kibana query, X-Pack Watcher and GrayLog query generated and added automatically (this list could be
expanded and depends on [Sigma Supported Targets](https://github.com/Neo23x0/sigma#supported-targets))

#### Data Needed

<details>
  <summary>Data Needed yaml (click to expand)</summary>
  <img src="images/dataneeded_v1.png" />
</details>

<details>
  <summary>Automatically created confluence page (click to expand)</summary>
  <img src="images/dn_confluence_v1.png" />
</details>

<details>
  <summary>Automatically created markdown page (click to expand)</summary>
  <img src="images/dn_markdown_v1.png" />
</details>

<br>

This entity expected to simplify communication with SIEM/LM/Data Engineering teams. It includes the next data:

- Sample of the raw log to describe what data they could expect to receive/collect
- Description of data to collect (Platform/Type/Channel/etc) — needed for calculation of mappings to Detection Rules and
  general description
- List of fields also needed for calculation of mappings to Detection Rules and Response Playbooks, as well as
  for `pivoting.csv` generation

#### Logging Policy

<details>
  <summary>Logging Policy yaml (click to expand)</summary>
  <img src="images/loggingpolicy.png" />
</details>

<details>
  <summary>Automatically created confluence page (click to expand)</summary>
  <img src="images/lp_confluence_v1.png" />
</details>

<details>
  <summary>Automatically created markdown page (click to expand)</summary>
  <img src="images/lp_markdown_v1.png" />
</details>

<br>

This entity expected to explain SIEM/LM/Data Engineering teams and IT departments which logging policies have to be
configured to have proper Data Needed for Detection and Response to specific Threat. It also explains how exactly this
policy can be configured.

#### Enrichment

<details>
  <summary>Enrichments yaml (click to expand)</summary>
  <img src="images/en_yaml_v1.png" />
</details>

<details>
  <summary>Automatically created confluence page (click to expand)</summary>
  <img src="images/en_confluence_v1.png" />
</details>

<details>
  <summary>Automatically created markdown page (click to expand)</summary>
  <img src="images/en_markdown_v1.png" />
</details>

<br>

This entity expected to simplify communication with SIEM/LM/Data Engineering teams. It includes the next data:

- List of Data Needed which could be enriched
- Description of the goal of the specific Enrichment (new fields, translation, renaming etc)
- Example of implementation (for example, Logstash config)

This way you will be able to simply explain why you need specific enrichments (mapping to Detection Rules) and specific
systems for data enrichment (for example, Logstash).

#### Customer

<details>
  <summary>Customers yaml (click to expand)</summary>
  <img src="images/cu_yaml_v1.png" />
</details>

<details>
  <summary>Automatically created confluence page (click to expand)</summary>
  <img src="images/cu_confluence_v1.png" />
</details>

<details>
  <summary>Automatically created markdown page (click to expand)</summary>
  <img src="images/cu_markdown_v1.png" />
</details>

<br>

This entity used to track Logging Policies configuration, Data Needed collection and Detection Rules implementation per
customer. Customer could be internal (for example, remote site) or external (in case of Service Providers). It even
could be a specific host. There are no limitations for definition of the entity.

This entity expected to simplify communication with SIEM/LM/Data Engineering teams, provide visibility on implementation
for Leadership. It used to generate `analytics.csv`, `atc_attack_navigator_profile.json` (per customer)
and `atc_es_index.json`.

#### Triggers

Triggers are unmodified [Atomic Red Team tests](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics). By
default Atomic Threat Coverage uses atomics from official repository but you can (*should*) use atomics from your own
private fork with analytics relevant for you.

<details>
  <summary>Triggers yaml (click to expand)</summary>
  <img src="images/trigger.png" />
</details>

<details>
  <summary>Automatically created confluence page (click to expand)</summary>
  <img src="images/trigger_confluence_v1.png" />
</details>

<details>
  <summary>Automatically created markdown page (click to expand)</summary>
  <img src="images/tg_markdown_v1.png" />
</details>

<br>

This entity needed to test specific technical controls and detections. Detailed description could be found in
official [site](https://atomicredteam.io).

#### Mitigation Policy

is a measure that has to be executed to mitigate a specific threat.
For more information, please refer to the [atc-mitigation](https://github.com/atc-project/atc-mitigation) repository.

#### Response Playbook

is an Incident Response plan that represents a complete list of procedures/tasks that has to be executed to respond to a
specific threat.
For more information, please refer to the [atc-react](https://github.com/atc-project/atc-react) repository.

#### Visualization

<details>
  <summary>Visualization yaml (click to expand)</summary>
  <img src="images/visualisation_yaml_v1.png" />
</details>

<details>
  <summary>Dashboard yaml (click to expand)</summary>
  <img src="images/dashboard_yaml_v1.png" />
</details>

<details>
  <summary>Dashboard in Kibana (click to expand)</summary>
  <img src="images/dashboard_v1.png" />
</details>

<br>

Visualisations include separate Visualisations / Saved searches and Dashboards, built on top of them.  
Basically, atomic visualisations represent building blocks for Dashboards of different purposes.

For now we only support export to Kibana. But we are targeting multiple platforms export (Splunk being the nearest
future).  
This entity could be described as a Sigma for Visualisations.

Detailed HowTo could be found [here](scripts/atc_visualizations/README.md).

#### atc_es_index.json

Atomic Threat Coverage
generates [Elasticsearch](https://www.elastic.co/products/elasticsearch) [index](analytics/generated/atc_es_index.json)
with all data mapped to each other for visualisation and analysis of existing data
in [Kibana](https://www.elastic.co/products/kibana).

<details>
  <summary>ATC Analytics Dashboard in Kibana (click to expand)</summary>
  <img src="images/atc_analytics_dashboard.png" />
</details>

<br>

This way it can help to answer these questions:

- What data do I need to collect to detect specific threats?
- Which Logging Policies do I need to implement to collect the data I need for detection of specific threats?
- Which data provided me most of the high fidelity alerts? (prioritisation of data collection implementation)
- etc

<!-- - What threats can I respond to with existing Response Playbooks? -->

Ideally, these visualisations could provide organizations with the ability to connect Threat Coverage from detection
perspective to *money*. Like:

- if we will collect all Data Needed from all hosts for all Detection Rules we have it would be X Events Per Second (
  EPS) (do calculation for a couple of weeks or so) with these resources for storage/processing (some more or less
  concrete number)
- if we will collect Data Needed only for high fidelity alerts and only on critical hosts, it will be Y EPS with these
  resources for storage/processing (again, more or less concrete number)
- etc

If you don't have Elasticsearch and Kibana deployed, you can use `analytics.csv` for the same purposes.

#### atc_attack_navigator_profile.json

Atomic Threat Coverage generates [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/)
common [profile](analytics/generated/attack_navigator_profiles/atc_attack_navigator_profile.json) (for all existing
Detection Rules) as well as per Customer profiles for visualisation of current detection abilities, gap analysis,
development prioritisation, planning etc. You only need to upload it to public or (better) private Navigator site, click
New Tab -> Open Existing Layer -> Upload from local. Here is how it looks like for default ATC dataset (
original [Sigma](https://github.com/Neo23x0/sigma) repository rules, Windows only):

<details>
  <summary>Navigator profile for original Sigma Rules (click to expand)</summary>
  <img src="images/navigator_v1.png" />
</details>

#### analytics.csv

Atomic Threat Coverage generates [analytics.csv](analytics/generated/analytics.csv) with list of all data mapped to each
other for simple analysis.

<details>
  <summary>Example of lookup for "pass the hash" technique (click to expand)</summary>
  <img src="images/analytics_pth_v1.png" />
</details>

<br>

It could be used for the same purposes as `atc_es_index.json`.

#### pivoting.csv

Atomic Threat Coverage generates [pivoting.csv](analytics/generated/pivoting.csv) with list of all fields (from Data
Needed) mapped to description of Data Needed for very specific purpose — it provides information about data sources
where some specific data type could be found, for example domain name, username, hash etc:

<details>
  <summary>Example of lookup for "hash" field (click to expand)</summary>
  <img src="images/pivoting_hash_v1.png" />
</details>

<br>

At the same time it highlights which fields could be found only with specific enrichments:

<details>
  <summary>Example of lookup for "ParentImage" field (click to expand)</summary>
  <img src="images/pivoting_parent_v1.png" />
</details>

## Goals

1. Evangelize MITRE [ATT&CK](https://attack.mitre.org/) framework
2. Stimulate community to use [Sigma](https://github.com/Neo23x0/sigma)
   and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) projects
3. Evangelize threat information sharing
4. Automate most of manual work
5. Provide information security community framework which will improve communication with other departments, general
   analytics accumulation, developing and sharing

## Workflow

### Demo with Docker

If you just want to try it with default dataset, you can use docker:

1. Clone the repository or download
   an [archive](https://github.com/atc-project/atomic-threat-coverage/archive/master.zip) with it
2. Go to the project directory
3. Download and update Sigma and Atomic Red Team projects using git submodules:

```bash
git submodule init
git submodule update
git submodule foreach git pull origin master
```

4. Copy `scripts/config.default.yml` to `config.yml`
5. Update `config.yml` with links to your own Confluence node (following instructions inside the default config)
3. Build the container using `docker build . -t atc`
4. Run the container using `docker run -it atc`
5. Provide login and password to Confluence node when script will ask for it

That's all. Confluence will be populated with the data and all analytics will be generated on your side (elasticsearch
index, csv files, thehive templates, navigator profiles etc).

We do not recommend to use this type of deployment for production.

If you just want to make yourself familiar with final result with default dataset you can also use
online [demo](https://atomicthreatcoverage.atlassian.net/wiki/spaces/ATC/pages/126025996/WMI+Persistence+-+Script+Event+Consumer)
of automatically generated Confluence knowledge base.

### Production use

1. Add your own custom [Sigma](https://github.com/Neo23x0/sigma) fork to `detection_rules` directory
2. Add your own custom [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) fork to `triggering` directory
3. Add Data Needed into `data_needed` directory (you can create new one
   using [template](data_needed/dataneeded.yml.template))
4. Add Logging Policies into `logging_policies` directory (you can create new one
   using [template](logging_policies/loggingpolicy.yml.template))
5. Add Enrichments into `enrichments` directory (you can create new one
   using [template](enrichments/enrichment.yml.template))
6. Add Customers into `customers` directory (you can create new one using [template](customers/customer.yml.template))
7. Add Response Actions into `response_actions` directory (you can create new one
   using [template](response_actions/respose_action.yml.template))
8. Add Response Playbooks into `response_playbooks` directory (you can create new one
   using [template](response_playbooks/respose_playbook.yml.template))
9. Change output templates to fit your needs. Just copy our templates from `scripts/templates/` and
   adjust `templates_directory` in your `config.yml`
10. Configure your export settings and paths using `config.yml` (create it from `scripts/config.default.yml` and adjust
    settings)
11. Execute `make` in root directory of the repository
12. Provide login and password to Confluence node when script will ask for it

If you want to partially regenerate/update analytics you can investigate `Makefile` options or `main.py` help.

### Uploading ATC Analytics Dashboard

You need both Elasticsearch and Kibana up and running (relevant for version 7.3.1).

Define variables:

```bash
ELASTICSEARCH_URL="http://<es ip/domain>:<es port>"
KIBANA_URL="http://<kibana ip/domain>:<kibana port>"
USER=""
PASSWORD=""
```

Then upload index pattern to Kibana:

```bash
curl -k --user ${USER}:${PASSWORD} -H "Content-Type: application/json"\
  -H "kbn-xsrf: true"\
  -XPOST "${KIBANA_URL}/api/saved_objects/index-pattern/42272fa0-cde5-11e9-667e-6f37d60dcef0"\
  -d@analytics/predefined/atc-analytics-index-pattern.json
```

Then upload Dashboard to Kibana:

```bash
curl -k --user ${USER}:${PASSWORD} -H "Content-Type: application/json"\
  -H "kbn-xsrf: true"\
  -XPOST "${KIBANA_URL}/api/kibana/dashboards/import?exclude=index-pattern&force=true"\
  -d@analytics/predefined/atc-analytics-dashboard.json
```

Then upload index to Elasticsearch:

```bash
curl -k --user ${USER}:${PASSWORD} -H "Content-Type: application/json"\
  -XPOST "${ELASTICSEARCH_URL}/atc-analytics/_doc/_bulk?pretty"\
  --data-binary @analytics/generated/atc_es_index.json
```

You can automate index uploading adding last command to Makefile in your private fork.  
This way each time you will add new analytics, Dashboard will be automatically updated.

## Current Status: Alpha

The project is currently in an alpha stage. It doesn't support all existing Sigma rules (current coverage is ~95%), also
have some entities to develop (like Mitigation Systems). We warmly welcome any feedback and suggestions to improve the
project.

## Requirements

- Unix-like OS or [Windows Subsystem for Linux (WSL)](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux) (it
  required to execute `make`)
- Python 3.7.1
- [requests](https://pypi.org/project/requests/), [PyYAML](https://pypi.org/project/PyYAML/)
  and [jinja2](https://pypi.org/project/Jinja2/) Python libraries
- [Render Markdown](https://marketplace.atlassian.com/apps/1212654/render-markdown) app for Confluence (free open
  source)

## FAQ

#### Will my private analytics (Detection Rules, Logging Policies, etc) be transferred somewhere?

No. Only to your confluence node, according to configuration provided in `config.yml`.

#### What do you mean saying "evangelize threat information sharing" then?

We mean that you will use community compatible formats for (at least) Detection
Rules ([Sigma](https://github.com/Neo23x0/sigma)) and
Triggers ([Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)), and on some maturity level you will (
hopefully) have willingness to share some interesting analytics with community. It's totally up to you.

#### How can I add new Trigger, Detection Rule, or anything else to my private fork of Atomic Threat Coverage?

Simplest way is to follow [workflow](#workflow) chapter, just adding your rules into pre-configured folders for specific
type of analytics.

More "production" way is to configure your private forks of [Sigma](https://github.com/Neo23x0/sigma)
and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) projects
as [submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) of your Atomic Threat Coverage private fork. After
that you only will need to configure path to them in `config.yml`, this way Atomic Threat Coverage will start using it
for knowledge base generation.

#### Sigma doesn't support some of my Detection Rules. Does it still make sense to use Atomic Threat Coverage?

Absolutely. We also have some Detection Rules which couldn't be automatically converted to SIEM/LM queries by Sigma. We
still use Sigma format for such rules putting unsupported detection logic into "condition" section. Later SIEM/LM teams
manually create rules based on description in this field. ATC is not only about automatic queries
generation/documentation, there are still a lot of advantages for analysis. You wouldn't be able to utilise them without
Detection Rules in Sigma format.

## Contacts

- Folow us on [Twitter](https://twitter.com/atc_project) for updates
- Join discussions
  in [Slack](https://join.slack.com/t/atomicthreatcoverage/shared_invite/zt-6ropl01z-wIdiq3M0AEZPj_HiKfbiBg)
  or [Telegram](https://t.me/atomic_threat_coverage)

## Authors

- Daniil Yugoslavskiy, [@yugoslavskiy](https://twitter.com/yugoslavskiy)
- Jakob Weinzettl, [@mrblacyk](https://github.com/mrblacyk)
- Mateusz Wydra, [@sn0w0tter](https://github.com/sn0w0tter)
- Mikhail Aksenov, [@AverageS](https://github.com/AverageS)

## Thanks to

- Igor Ivanov, [@lctrcl](https://github.com/lctrcl) for collaboration on initial data types and mapping rules
  development
- Andrey, [Polar_Letters](https://www.behance.net/Polar_Letters) for the logo
- [Sigma](https://github.com/Neo23x0/sigma), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  , [TheHive](https://blog.thehive-project.org) and [Elastic Common Schema](https://github.com/elastic/ecs) projects for
  inspiration
- MITRE [ATT&CK](https://attack.mitre.org/) for making this possible

## TODO

- [x] Develop TheHive Case Templates generation based on Response Playbooks
- [x] Develop docker container for the project
- [ ] Develop specification for custom ATC data entities (Data Needed, Logging Policies etc)
- [x] Implement "Mitigation Systems" entity
- [x] Implement "Hardening Policies" entity
- [x] Implement new entity — "Visualisation" with Kibana visualisations/dashboards stored in yaml files and option to
  convert them into curl commands for uploading them into Elasticsearch

## Links

[\[1\]](https://car.mitre.org) MITRE Cyber Analytics Repository  
[\[2\]](https://eqllib.readthedocs.io/en/latest/) Endgame EQL Analytics Library  
[\[3\]](https://github.com/palantir/alerting-detection-strategy-framework) Palantir Alerting and Detection Strategy
Framework  
[\[4\]](https://github.com/ThreatHuntingProject/ThreatHunting) The ThreatHunting Project

## License

See the [LICENSE](LICENSE) file.
