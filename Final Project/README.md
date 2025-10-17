Secret Scanner for SDEV245 Fianl
The purpose of this scanner is to scan files for basic regex patterns and print the results

How to Run:
Scan the current folder
python3 Secret_Scanner_Final_XR.py
Scan Certain File types
python3 Secret_Scanner_Final_XR.py . --ext .py .js .env .yml

What the scanner is looking for
AWS accesskeys
Google API Keys
Github Tokens
Hardcoded passwords
Private Key (PEM)

Output
Prints a header that contains the File, Line, Type, and Match
