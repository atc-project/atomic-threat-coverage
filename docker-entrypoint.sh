echo "[*] Setting up confluence"
python3 main.py -C --init

echo "[*] Setting up markdown"
python3 main.py -M --init

echo "[*] Pushing data to confluence"
python3 main.py -C -A

echo "[*] Pushing data to markdown"
python3 main.py -M -A

echo "[*] Creating analytics.csv and pivoting.csv"
python3 main.py -CSV

echo "[*] Creating ATT&CK Navigator profile"
python3 main.py -TD-NAV

echo "[*] Creating ATT&CK Navigator profile"
python3 main.py -TD-NAV-CU

echo "[*] Creating markdown repository and pushing data"
python3 main.py --markdown --auto --init

echo "[*] Creating confluence repository and pushing data"
python3 main.py --confluence --auto --init

echo "[*] Creating elastic index"
python3 main.py -ES

echo "[*] Creating visualizations.."
python3 main.py -V

echo "[*] Generating TheHive Case templates based on Response Playbooks"
python3 main.py --thehive

echo "Done!"
