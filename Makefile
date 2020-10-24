.PHONY: all analytics navigator elastic setup clean visualizations thehive

all: setup_repo markdown confluence analytics navigator elastic
analytics: create_analytics_and_pivoting_csv
navigator: create_attack_navigator_profile create_attack_navigator_profile_per_customer
elastic: create_es_export
setup: setup_repo setup_confluence setup_markdown
visualizations: make_visualizations
thehive: thehive_templates

setup_repo:
	@echo "[*] Updating 3rd party repository"
	git submodule init
	git submodule update
	git submodule foreach git pull origin master
	
setup_confluence:
	@echo "[*] Setting up confluence"
	python3 main.py -C --init

setup_markdown:
	@echo "[*] Setting up markdown"
	python3 main.py -M --init

push_to_confluence:
	@echo "[*] Pushing data to confluence"
	python3 main.py -C -A

push_to_markdown:
	@echo "[*] Pushing data to markdown"
	python3 main.py -M -A

create_analytics_and_pivoting_csv:
	@echo "[*] Creating analytics.csv and pivoting.csv"
	python3 main.py -CSV

create_attack_navigator_profile:
	@echo "[*] Creating common Threat Detection ATT&CK Navigator layer"
	python3 main.py -TD-NAV

create_attack_navigator_profile_per_customer:
	@echo "[*] Creating Threat Detection ATT&CK Navigator layers per customer"
	python3 main.py -TD-NAV-CU

markdown:
	@echo "[*] Creating markdown repository and pushing data"
	python3 main.py --markdown --auto --init

mkdocs:
	@echo "[*] Creating mkdocs site"
	mkdocs build

confluence:
	@echo "[*] Creating confluence repository and pushing data"
	python3 main.py --confluence --auto --init

create_es_export:
	@echo "[*] Creating elasticsearch index"
	python3 main.py -ES

make_visualizations:
	@echo "[*] Creating visualizations.."
ifeq ($(GUI), 1)
	python3 main.py -V --vis-export-type
else
	python3 main.py -V
endif

thehive_templates:
	@echo "[*] Generating TheHive Case templates based on Response Playbooks"
	python3 main.py --thehive

# TODO: make clean works with non default paths from config
clean:
	@echo "[*] Cleaning up..."
	@rm -rf ./Atomic_Threat_Coverage
	@rm -rf ./site
	@rm -f ./analytics/generated/analytics.csv
	@rm -f ./analytics/generated/atc_es_index.json
	@rm -f ./analytics/generated/pivoting.csv
	@rm -f ./analytics/generated/thehive_templates/*.json
	@rm -f ./analytics/generated/visualizations/*.json
	@rm -f ./analytics/generated/atc_attack_navigator_profile*.json
