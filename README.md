🇷🇺 [Русская версия](README_RU.md)  |   🇵🇱 [Polska wersja](README_PL.md)  

# Atomic Threat Coverage

Automatically generated knowledge base of analytics designed to combat threats based on MITRE's [ATT&CK](https://attack.mitre.org/).

![](images/logo_v1.png)

Atomic Threat Coverage is tool which allows you to automatically generate knowledge base of analytics, designed to combat threats (based on the [MITRE ATT&CK](https://attack.mitre.org/) adversary model) from Detection, Response, Mitigation and Simulation perspectives:

- **Detection Rules** based on [Sigma](https://github.com/Neo23x0/sigma) — Generic Signature Format for SIEM Systems
- **Data Needed** to be collected to produce detection of specific Threat
- **Logging Policies** need to be configured on data source to be able to collect Data Needed
- **Enrichments** for specific Data Needed which required for some Detection Rules
- **Triggers** based on [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — detection tests based on MITRE's ATT&CK
- **Response Actions** which executed during Incident Response
- **Response Playbooks** for reacting on specific threat, constructed from atomic Response Actions
- **Hardening Policies** need to be implemented to mitigate specific Threat
- **Mitigation Systems** need to be deployed and configured to mitigate specific Threat

Atomic Threat Coverage is highly automatable framework for accumulation, developing, explanation and sharing actionable analytics.

## Description

### Motivation

There are plenty decent projects which provide analytics (or functionality) of specific focus ([Sigma](https://github.com/Neo23x0/sigma), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [MITRE CAR](https://car.mitre.org)). All of them have one weakness — they exist in the vacuum of their area. In reality everything is tightly connected — data for alerts doesn't come from nowhere, and generated alerts don't go nowhere. Each function, i.e. data collection, security systems administration, threat detection, incident response etc are parts of big and comprehensive process, implemented by multiple departments, which demands their close collaboration.

Sometimes problems of one function could be solved by methods of other function in a cheaper, simpler and more efficient way. Most of the tasks couldn't be solved by one function at all. Each function is based on abilities and quality of others. There is no efficient way to detect and respond to threats without proper data collection and enrichment. There is no efficient way to respond to threats without understanding of which technologies/systems/measures could be used to block specific threat. There is no reason to conduct penetration test or Red Team exercise without understanding of abilities of processes, systems and personal to combat cyber threats. All of these require tight collaboration and mutual understanding of multiple departments. 

In practice there are difficulties in collaboration due to:

- Absence of common threat model/classification, common terminology and language to describe threats
- Absence common goals understanding
- Absence of simple and straightforward way to explain specific requirements
- Difference in competence level (from both depth and areas perspectives)

That's why we decided to create Atomic Threat Coverage — project which connects different functions/processes under unified Threat Centric methodology ([Lockheed Martin Intelligence Driven Defense®](https://www.lockheedmartin.com/en-us/capabilities/cyber/intelligence-driven-defense.html) aka [MITRE Threat-based Security](https://mitre.github.io/unfetter/about/)), threat model ([MITRE ATT&CK](https://attack.mitre.org/)) and provide security teams an efficient tool for collaboration on one main challenge — combating threats.

### Why Atomic Threat Coverage 

Work with existing <sup>[\[1\]](https://car.mitre.org)[\[2\]](https://eqllib.readthedocs.io/en/latest/)[\[3\]](https://github.com/palantir/alerting-detection-strategy-framework)[\[4\]](https://github.com/ThreatHuntingProject/ThreatHunting)</sup> analytics/detections repositories looks like endless copy/pasting job, manual adaptation of the information into internal analytics knowledge base format, detections data model, mappings to internal valuable metrics and entities etc.

We decided to make it different.

Atomic Threat Coverage is a framework which allows you to create and maintain **your own** analytics repository, import analytics from other projects (like [Sigma](https://github.com/Neo23x0/sigma), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), as well as private forks of these projects with **your own** analytics) and do export into human-readable wiki-style pages in two (for now) platforms:

1. [Atlassian Confluence](https://www.atlassian.com/software/confluence) pages ([here](https://atomicthreatcoverage.atlassian.net/wiki/spaces/ATC/pages/126025996/WMI+Persistence+-+Script+Event+Consumer) is the demo of automatically generated knowledge base)
2. [This repo itself](Atomic_Threat_Coverage) — automatically generated markdown formated wiki-style pages

In other words, you don't have to work on data representation layer manually, you work on meaningful atomic pieces of information (like Sigma rules), and Atomic Threat Coverage will automatically create analytics database with all entities, mapped to all meaningful, actionable metrics, ready to use, ready to share and show to leadership, customers and colleagues.

### How it works

Everything starts from Sigma rule and ends up with human-readable wiki-style pages. Atomic Threat Coverage parses it and:

1. Maps **Detection Rule** to ATT&CK Tactic and Technique using `tags` from Sigma rule
2. Maps **Detection Rule** to **Data Needed** using `logsource` and `detection` sections from Sigma rule
3. Maps **Detection Rule** to **Triggers** (Atomic Red Team tests) using `tags` from Sigma rule
4. Maps **Detection Rule** to **Enrichments** using existing mapping inside **Detection Rule**
5. Maps **Response Playbooks** to ATT&CK Tactic and and Technique using existing mapping inside **Response Playbooks**
6. Maps **Response Playbooks** to **Response Actions** using existing mapping inside **Response Playbooks**
7. Maps **Logging Policies** to **Data Needed** using existing mapping inside **Data Needed**
8. Converts everything into Confluence and Markdown wiki-style pages using jinja templates (`scripts/templates`)
9. Pushes all pages to local repo and Confluence server (according to configuration provided in `scripts/config.yml`)
10. Creates `analytics.csv` and `pivoting.csv` files for simple analysis of existing data
11. Creates `atc_export.json` — [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/) profile for visualisation of current detection abilities

### Under the hood

Data in the repository:

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

Detection Rules are unmodified [Sigma rules](https://github.com/Neo23x0/sigma/tree/master/rules). By default Atomic Threat Coverage uses rules from official repository but you can (*should*) use rules from your own private fork with analytics relevant for you.  

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
Sigma rule, Kibana query, X-Pack Watcher and GrayLog query generated and added automatically (this list could be expanded and depends on [Sigma Supported Targets](https://github.com/Neo23x0/sigma#supported-targets))

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
- Description of data to collect (Platform/Type/Channel/etc) — needed for calculation of mappings to Detection Rules and general description
- List of fields also needed for calculation of mappings to Detection Rules and Response Playbooks, as well as for `pivoting.csv` generation

#### Logging Policies

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

This entity expected to explain SIEM/LM/Data Engineering teams and IT departments which logging policies have to be configured to have proper Data Needed for Detection and Response to specific Threat. It also explains how exactly this policy can be configured.

#### Enrichments

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

This way you will be able to simply explain why you need specific enrichments (mapping to Detection Rules) and specific systems for data enrichment (for example, Logstash).

#### Triggers

Triggers are unmodified [Atomic Red Team tests](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics). By default Atomic Threat Coverage uses atomics from official repository but you can (*should*) use atomics from your own private fork with analytics relevant for you.  

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

This entity needed to test specific technical controls and detections. Detailed description could be found in official [site](https://atomicredteam.io).

#### Response Actions

<details>
  <summary>Response Action yaml (click to expand)</summary>
  <img src="images/ra_yaml_v1.png" />
</details>

<details>
  <summary>Automatically created confluence page (click to expand)</summary>
  <img src="images/ra_confluence_v1.png" />
</details>

<details>
  <summary>Automatically created markdown page (click to expand)</summary>
  <img src="images/ra_markdown_v1.png" />
</details>

<br>

This entity used to build Response Playbooks.

#### Response Playbooks

<details>
  <summary>Response Playbook yaml (click to expand)</summary>
  <img src="images/rp_yaml_v1.png" />
</details>

<details>
  <summary>Automatically created confluence page (click to expand)</summary>
  <img src="images/rp_confluence_v1.png" />
</details>

<details>
  <summary>Automatically created markdown page (click to expand)</summary>
  <img src="images/rp_markdown_v1.png" />
</details>

<br>

This entity used as an Incident Response plan for specific threat.

#### analytics.csv

Atomic Threat Coverage generates [analytics.csv](analytics.csv) with list of all data mapped to each other for simple analysis. This file is suppose to answer these questions:

- What data do I need to collect to detect specific threats?
- What threats can I respond to with existing Response Playbooks?
- Which Logging Policies do I need to implement to collect the data I need for detection of specific threats?
- Which Logging Policies I can install everywhere (event volume low/medium) and which only on critical hosts (high/extremely high)?
- Which data provided me most of the high fidelity alerts? (prioritisation of data collection implementation)
- etc

<details>
  <summary>Example of lookup for "pass the hash" technique (click to expand)</summary>
  <img src="images/analytics_pth_v1.png" />
</details>

<br>

Ideally, this kind of mapping could provide organizations with the ability to connect Threat Coverage from detection perspective to *money*. Like:

- if we will collect all Data Needed from all hosts for all Detection Rules we have it would be X Events Per Second (EPS) (do calculation for a couple of weeks or so) with these resources for storage/processing (some more or less concrete number)
- if we will collect Data Needed only for high fidelity alerts and only on critical hosts, it will be Y EPS with these resources for storage/processing (again, more or less concrete number)
- etc

#### pivoting.csv

Atomic Threat Coverage generates [pivoting.csv](pivoting.csv) with list of all fields (from Data Needed) mapped to description of Data Needed for very specific purpose — it provides information about data sources where some specific data type could be found, for example domain name, username, hash etc:

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

1. Stimulate community to use [Sigma](https://github.com/Neo23x0/sigma) rule format (so we will have more contributors, more and better converters)
2. Stimulate community to use [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests format (so we will have more contributors and execution frameworks)
3. Evangelize threat information sharing
4. Automate most of manual work
5. Provide information security community framework which will improve communication with other departments, general analytics accumulation, developing and sharing

## Workflow

1. Add your own custom [Sigma](https://github.com/Neo23x0/sigma) rules/fork (if you have any) to `detection_rules` directory
2. Add your own custom [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests/fork (if you have any) to `triggering` directory
3. Add Data Needed into `data_needed` directory (you can create new one using [template](data_needed/dataneeded.yml.template))
4. Add Logging Policies into `logging_policies` directory (you can create new one using [template](logging_policies/loggingpolicy.yml.template))
5. Add Enrichments into `enrichments` directory (you can create new one using [template](enrichments/enrichment.yml.template))
6. Add Response Actions into `response_actions` directory (you can create new one using [template](response_actions/respose_action.yml.template))
7. Add Response Playbooks into `response_playbooks` directory (you can create new one using [template](response_playbooks/respose_playbook.yml.template))
8. Configure your export settings using `scripts/config.yml`
9. Execute `make` in root directory of the repository

You don't have to add anything to make it work in your environment, you can just configure export settings using `scripts/config.yml` and utilise default dataset.
At the same time you can access [demo](https://atomicthreatcoverage.atlassian.net/wiki/spaces/ATC/pages/126025996/WMI+Persistence+-+Script+Event+Consumer) of automatically generated knowledge base in Confluence to make yourself familiar with final result with default dataset.

## Current Status: Alpha

The project is currently in an alpha stage. It doesn't support all existing Sigma rules (current coverage is ~80%), also have some entities to develop (like Mitigation Systems). We warmly welcome any feedback and suggestions to improve the project.

## Requirements

- Unix-like OS or [Windows Subsystem for Linux (WSL)](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux) (it required to execute `make`)
- Python 3.7.1
- [requests](https://pypi.org/project/requests/), [PyYAML](https://pypi.org/project/PyYAML/) and [jinja2](https://pypi.org/project/Jinja2/) Python libraries
- [Render Markdown](https://marketplace.atlassian.com/apps/1212654/render-markdown) app for Confluence (free open source)

## FAQ

#### Will my private analytics (Detection Rules, Logging Policies, etc) be transferred somewhere?

No. Only to your confluence node, according to configuration provided in `scripts/config.yml`. Atomic Threat Coverage doesn't connect to any other remote hosts, you can easily check it.

#### What do you mean saying "evangelize threat information sharing" then?

We mean that you will use community compatible formats for (at least) Detection Rules ([Sigma](https://github.com/Neo23x0/sigma)) and Triggers ([Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)), and on some maturity level you will (hopefully) have willingness to share some interesting analytics with community. It's totally up to you.

#### How can I add new Trigger, Detection Rule, or anything else to my private fork of Atomic Threat Coverage?

Simplest way is to follow [workflow](#workflow) chapter, just adding your rules into pre-configured folders for specific type of analytics.

More "production" way is to configure your private forks of [Sigma](https://github.com/Neo23x0/sigma) and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) projects as [submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) of your Atomic Threat Coverage private fork. After that you only will need to configure path to them in `scripts/config.yml`, this way Atomic Threat Coverage will start using it for knowledge base generation.

#### Sigma doesn't support some of my Detection Rules. Does it still make sense to use Atomic Threat Coverage?

Absolutely. We also have some Detection Rules which couldn't be automatically converted to SIEM/LM queries by Sigma. We still use Sigma format for such rules putting unsupported detection logic into "condition" section. Later SIEM/LM teams manually create rules based on description in this field. ATC is not only about automatic queries generation/documentation, there are still a lot of advantages for analysis. You wouldn't be able to utilise them without Detection Rules in Sigma format.

## Contacts

- Folow us on [Twitter](https://twitter.com/atc_project) for updates
- Join discussions in [Slack](https://join.slack.com/t/atomicthreatcoverage/shared_invite/enQtNTMwNDUyMjY2MTE5LTk1ZTY4NTBhYjFjNjhmN2E3OTMwYzc4MTEyNTVlMTVjMDZmMDg2OWYzMWRhMmViMjM5YmM1MjhkOWFmYjE5MjA) or [Telegram](https://t.me/atomic_threat_coverage) 

## Authors

- Daniil Yugoslavskiy, [@yugoslavskiy](https://github.com/yugoslavskiy)
- Jakob Weinzettl, [@mrblacyk](https://github.com/mrblacyk)
- Mateusz Wydra, [@sn0w0tter](https://github.com/sn0w0tter)
- Mikhail Aksenov, [@AverageS](https://github.com/AverageS)

## Thanks to

- Igor Ivanov, [@lctrcl](https://github.com/lctrcl) for collaboration on initial data types and mapping rules development
- Andrey, [Polar_Letters](https://www.behance.net/Polar_Letters) for the logo
- [Sigma](https://github.com/Neo23x0/sigma), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [TheHive](https://blog.thehive-project.org) and [Elastic Common Schema](https://github.com/elastic/ecs) projects for inspiration
- MITRE [ATT&CK](https://attack.mitre.org/) for making this possible

## TODO

- [ ] Develop TheHive Case Templates generation based on Response Playbooks
- [ ] Develop specification for custom ATC data entities (Data Needed, Logging Policies etc)
- [ ] Develop docker container for the project
- [ ] Implement "Mitigation Systems" entity
- [ ] Implement "Hardening Policies" entity
- [ ] Implement consistent Data Model (fields naming)
- [ ] Implement new entity — "Visualisation" with Kibana visualisations/dashboards stored in yaml files and option to convert them into curl commands for uploading them into Elasticsearch

## Links

[\[1\]](https://car.mitre.org) MITRE Cyber Analytics Repository  
[\[2\]](https://eqllib.readthedocs.io/en/latest/) Endgame EQL Analytics Library  
[\[3\]](https://github.com/palantir/alerting-detection-strategy-framework) Palantir Alerting and Detection Strategy Framework  
[\[4\]](https://github.com/ThreatHuntingProject/ThreatHunting) The ThreatHunting Project  

## License

See the [LICENSE](LICENSE) file.
