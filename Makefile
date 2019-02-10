.PHONY: all  setup update_sigma generate_queries clean push_to_markdown

all: setup setup_markdown2 push_to_markdown2
all2: setup setup_confluence setup_markdown push_to_confuence push_to_markdown create_analytics_csv 
update: push_to_confuence create_analytics_csv push_to_markdown
markdown: setup_markdown push_to_markdown
markdown2: setup_markdown2 push_to_markdown2
confluence: setup_confluence push_to_confluence
analytics: create_analytics_csv

setup:
	@echo "Updating 3rd party repository"
	git submodule init
	git submodule update
	
setup_confluence:
	@echo "Setting up confluecne"
	@cd scripts_v2 && python3 init_confluence.py

setup_markdown:
	@echo "Setting up markdown"
	@cd scripts_v2 && bash init_markdown.sh

push_to_confluence:
	@echo "Pushing data to confluecne"
	@cd scripts_v2 && python3 main.py -C -A

push_to_markdown:
	@echo "Pushing data to markdown"
	@cd scripts_v2 && python3 main.py -M -A

create_analytics_csv:
	@echo "Creating analytics.csv"
	@cd scripts_v2 && python3 yamls2csv.py

clean:
	@echo "Cleaning up..."
	@rm -rf ./Atomic_Threat_Coverage