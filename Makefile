.PHONY: all  setup update_sigma generate_queries clean push_to_markdown

all: setup setup_confluence setup_markdown push_to_confluence push_to_markdown create_analytics_and_pivoting_csv create_attack_navigator_profile
update: push_to_confluence create_analytics_and_pivoting_csv push_to_markdown create_attack_navigator_profile
markdown: setup_markdown push_to_markdown
confluence: setup_confluence push_to_confluence
analytics: create_analytics_and_pivoting_csv
navigator: create_attack_navigator_profile

setup:
	@echo "[*] Updating 3rd party repository"
	git submodule init
	git submodule update
	git submodule foreach git pull origin master
	cp -r detection_rules/sigma/rules/windows/*/*.yml detection_rules/
	
setup_confluence:
	@echo "[*] Setting up confluecne"
	@cd scripts && python3 init_confluence.py

setup_markdown:
	@echo "[*] Setting up markdown"
	@cd scripts && bash init_markdown.sh

push_to_confluence:
	@echo "[*] Pushing data to confluecne"
	@cd scripts && python3 main.py -C -A

push_to_markdown:
	@echo "[*] Pushing data to markdown"
	@cd scripts && python3 main.py -M -A

create_analytics_and_pivoting_csv:
	@echo "[*] Creating analytics.csv and pivoting.csv"
	@cd scripts && python3 yamls2csv.py

create_attack_navigator_profile:
	@echo "[*] Creating ATT&CK Navigator profile"
	@cd scripts && python3 attack_navigator_export.py

clean:
	@echo "[*] Cleaning up..."
	@rm -rf ./Atomic_Threat_Coverage