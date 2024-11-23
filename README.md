# 3AD
```
 ███████████            ███    █████████   ██████████  
░█░░░███░░░█           ░░░    ███░░░░░███ ░░███░░░░███ 
░   ░███  ░  ████████  ████  ░███    ░███  ░███   ░░███
    ░███    ░░███░░███░░███  ░███████████  ░███    ░███
    ░███     ░███ ░░░  ░███  ░███░░░░░███  ░███    ░███
    ░███     ░███      ░███  ░███    ░███  ░███    ███ 
    █████    █████     █████ █████   █████ ██████████  
   ░░░░░    ░░░░░     ░░░░░ ░░░░░   ░░░░░ ░░░░░░░░░░ 
   
Welcome to TriAD! Starting up...


usage: triad.py [-h] [-nogui] [-n [FILENAME]] [-csv] [-vb]

options:
  -h, --help            show this help message and exit
  -nogui                Run without GUI
  -n [FILENAME], --filename [FILENAME]
                        Specify the name of the csv file
  -csv, --onlycsv       Return only cvs file
  -vb, --verbose        Verbose mode
```  
   
pip install -r requirements.txt

basic command:
1. To run audit and export to json: triad.py -nogui
2. To run audit and export to json and csv: triad.py -nogui -n=[file_name]
3. To export only csv file: triad.py -nogui -csv