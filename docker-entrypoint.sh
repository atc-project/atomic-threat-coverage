cd scripts
echo "[*] Setting up confluecne"
python3 init_confluence.py

echo "[*] Setting up markdown"
./init_markdown.sh


echo "[*] Pushing data to confluecne"
python3 main.py -C -A


echo "[*] Pushing data to markdown"
python3 main.py -M -A


echo "[*] Creating analytics.csv and pivoting.csv"
python3 yamls2csv.py


echo "[*] Creating ATT&CK Navigator profile"
python3 attack_navigator_export.py

echo "Done!"