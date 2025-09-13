# MemScanner
Basic Memory Scanner wrote for fun

## Usage
To scan a sequence of bytes:
```
.\memscanner -p 1234 -b "90 90" 
```
To scan a string:
```
.\memscanner -p 1234 -s "ciao"
```
To scan the process memory for memory areas within a specific protection
```
.\memscanner -p 1234 -q rw
```