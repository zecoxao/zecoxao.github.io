SceNKFastMalloc (Reuse/uaf?)

1 : Télécharge et place le DNG (IMGP0847.DNG) dans ton dossier

https://raw.githubusercontent.com/hunters-sec/CVE-2025-43300/main/dng_images/IMGP0847.DNG


2 : Lance le serveur HTTP (dans le dossier contenant index.html et IMGP0847.DNG) :
cmd > py -m http.server

3 : Ouvre la page POC sur la PS4 :
Sur la PS4 Browser -> entre http://<IP_DE_TON_PC>:8000 -> charge index.html -> lance le run.

4 : Démarre le receveur de dumps sur ton PC (nouveau terminal) :
py serve4dump.py

Lance plusieurs runs depuis la PS4 et surveille :

sorties console / logs du POC (CRC, SOI/EOI, signature DNG)

serve4dump.py → récups les dumps quand la corruption/crash arrive
