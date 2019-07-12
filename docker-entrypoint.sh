cd scripts
echo "[*] Setting up confluence"
python3 init_confluence.py

echo "[*] Setting up markdown"
python3 init_markdown.py

echo "[*] Pushing data to confluence"
python3 main.py -C -A

echo "[*] Pushing data to markdown"
python3 main.py -M -A

echo "[*] Creating analytics.csv and pivoting.csv"
python3 yamls2csv.py

echo "[*] Creating ATT&CK Navigator profile"
python3 attack_navigator_export.py

echo "[*] Creating ATT&CK Navigator profile"
python3 attack_navigator_per_customer_export.py

echo "[*] Creating markdown repository and pushing data"
python3 main.py --markdown --auto --init

echo "[*] Creating confluence repository and pushing data"
python3 main.py --confluence --auto --init

echo "[*] Creating elastic index"
python3 es_index_export.py

echo "[*] Creating visualizations.."
python3 main.py -V

echo "[*] Generating TheHive Case templates based on Response Playbooks"
python3 main.py --thehive

echo "Done!"
