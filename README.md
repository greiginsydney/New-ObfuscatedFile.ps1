# New-ObfuscatedFile.ps1

I have the occasional need to send log files to Microsoft and other vendors from customers who have strict IT security requirements. These customers usually require all files be de-identified before they leave the premises,  removing all host names and IP addresses.

This can be quite a tedious process, so I've created a small script file that edits a provided text file and:

- uses a "find/replace" CSV file to replace all instances of nominated text with replacement values
- obfuscates any remaining IP addresses, changing them to dummy text in the format "aa.bb.cc.nn", where the "nn" is the same number when-ever that IP address is encountered in the document. (e.g. the third IP address that's found  in the file will be renamed "aa.bb.cc.3").

At a minimum, you only need to provide an -InputFile. With only this, the script will replace all IP addresses with dummy values, then save a copy of the file with a "-new" suffix.
Command-line parameters provide some additional handling/flexibility:

- Add an "-OutputFile" and the obfuscated file will be saved with this name. If the file already exists it will be over-written.
- Add the "-Overwrite" switch and the script will over-write the InputFile with the new values.
- Specify a "-CsvReplaceFile" filename (in the format specified below) and it will perform a Find/Replace throughout the InputFile, and THEN replace any original IP addresses with the dummy aa.bb.cc.nn values.
- Specify "-SkipIp" and it will ONLY change values from the CsVReplaceFile, skipping the section that obfuscates any remaining IP addresses.

Other features:

- By using the same -CsvReplaceFile each time you run the script / send logs, all the values in the resulting log files will be changed consistently, enabling you to compare between different logs.
- The find/replace is actually RegEx, so you can get complex/complicated in your replaces. (Disclaimer: in this version I've not tested this to any degree.)
- IP addresses changed (or ignored) by the -CsvReplaceFile are skipped by the following IP address code
- If the recipient has their own copy of the -CsvReplaceFile with the values reversed, they can reconstitute the original log. (In a future version I'll add a "reverse" switch or similar to remove the need to manually reverse  the -Replacefile.)
- Batch it to feed in a whole directory (or tree?) and it will run on all the provided files. (See the example below and baked into the script).
- It's code-signed so you can run it in environments that have a restrictive Powershell ExecutionPolicy. (Thank you Digicert.)


### ReplaceFile syntax
Create the -CsvReplaceFile so it looks like this. The top line is mandatory (and the script will err if it's not there).
```powershell
"find","replace"
greiginsydney.com,contoso.com
greiginsydney.local,contoso.local
greg,Greig,Anything after a second comma is ignored
,10.10.10.0, Provide no "find" value and the script will ignore/skip the replace value in the later IP replacement code
"replace this", "with this", Wrap the text in quotes if it's to include a space or match a comma
"gre?\wg\W","Greig ", match on RegEx!!

13.66.173.252,10.10.10.1
192.168.1.,10.10.1.
```

### Batch it?
```powershell
Get-ChildItem *.xml -recurse | foreach { .\New-ObfuscatedFile.ps1 -InputFile $_.Fullname -CsvReplaceFile MyReplaceFile.csv }
```

Please take it for a test drive and let me know if you encounter any problems with it, or have any enhancement suggestions.

### Revision History
v1.0 - 21st August 2019. This is the original release.

<br>

\- G.

<br>

This script was originally published at [https://greiginsydney.com/new-obfuscatedfile-ps1/](https://greiginsydney.com/new-obfuscatedfile-ps1//).

