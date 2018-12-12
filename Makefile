.PHONY: all  setup update_sigma generate_queries clean push_to_markdown

all: setup setup_confluence setup_markdown push_to_confuence push_to_markdown create_analytics_csv 
update: push_to_confuence create_analytics_csv push_to_markdown
markdown: setup_markdown push_to_markdown
confluecne: setup_confluence push_to_confuence
analytics: create_analytics_csv

setup:
	@echo "Updating 3rd party repository"
	git submodule init
	git submodule update
	
setup_confluence:
	@echo "Setting up confluecne"
	python3 scripts/init_confluence.py

setup_markdown:
	@echo "Setting up markdown"
	@cd scripts && bash init_markdown.sh

push_to_confuence:
	@echo "Pushing data to confluecne"
	@cd scripts && python3 populate_confluence.py

push_to_markdown:
	@echo "Pushing data to markdown"
	@cd scripts && python3 populate_markdown.py
	@cd scripts && bash populate_tg_markdown.sh

create_analytics_csv:
	@echo "Creating analytics.csv"
	@cd scripts && python3 yamls2csv.py

clean:
	@echo "Cleaning up..."
	@rm -rf ./Atomic_Threat_Coverage