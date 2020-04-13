# New-ObfuscatedFile.ps1
Do you ever need to send log files to Microsoft and other vendors from customers who have strict IT security requirements? Do you need to de-identify them before they leave the premises, removing all host names and IP addresses? This script does that for you.

<p>&nbsp;</p>
<p><span style="font-size: small;">I have the occasional need to send log files to Microsoft and other vendors from customers who have strict IT security requirements. These customers usually require all files be de-identified before they leave the premises,  removing all host names and IP addresses.</span></p>
<p><span style="font-size: small;">This can be quite a tedious process, so I've created a small script file that edits a provided text file and:</span></p>
<ul>
<li><span style="font-size: small;">uses a "find/replace" CSV file to replace all instances of nominated text with replacement values</span> </li>
<li><span style="font-size: small;">obfuscates any remaining IP addresses, changing them to dummy text in the format "aa.bb.cc.nn", where the "nn" is the same number when-ever that IP address is encountered in the document. (e.g. the third IP address that's found  in the file will be renamed "aa.bb.cc.3").</span> </li>
</ul>
<p><span style="font-size: small;">At a minimum, you only need to provide an -InputFile. With only this, the script will replace all IP addresses with dummy values, then save a copy of the file with a "-new" suffix.</span></p>
<p><span style="font-size: small;">Command-line parameters provide some additional handling/flexibility:</span></p>
<ul>
<li><span style="font-size: small;">Add an "-OutputFile" and the obfuscated file will be saved with this name. If the file already exists it will be over-written.</span> </li>
<li><span style="font-size: small;">Add the "-Overwrite" switch and the script will over-write the InputFile with the new values.</span> </li>
<li><span style="font-size: small;">Specify a "-CsvReplaceFile" filename (in the format specified below) and it will perform a Find/Replace throughout the InputFile, and THEN replace any original IP addresses with the dummy aa.bb.cc.nn values.</span> </li>
<li><span style="font-size: small;">Specify "-SkipIp" and it will ONLY change values from the CsVReplaceFile, skipping the section that obfuscates any remaining IP addresses.</span> </li>
</ul>
<p><span style="font-size: small;">Other features:</span></p>
<ul>
<li><span style="font-size: small;">By using the same -CsvReplaceFile&nbsp;each time you run the script / send logs, all the values in the resulting log files will be changed consistently, enabling you to compare between different logs. </span></li>
<li><span style="font-size: small;">The find/replace is actually RegEx, so you can get complex/complicated in your replaces.&nbsp;(Disclaimer: in this version I've not tested this to any degree.)</span> </li>
<li><span style="font-size: small;">IP addresses changed (or ignored) by the -CsvReplaceFile&nbsp;are skipped by the following IP address code</span> </li>
<li><span style="font-size: small;">If the recipient has their own copy of the -CsvReplaceFile&nbsp;with the values reversed, they can reconstitute the original log. (In a future version I'll add a "reverse" switch or similar to remove the need to manually reverse  the -Replacefile.) </span></li>
<li><span style="font-size: small;">Batch it to feed in a whole directory (or tree?) and it will run on all the provided files. (See the example below and baked into the script). </span></li>
<li><span style="font-size: small;">It's code-signed so you can run it in environments that have a restrictive Powershell ExecutionPolicy. (Thank you Digicert.)</span> </li>
</ul>
<p>&nbsp;</p>
<p><span style="font-size: medium;">ReplaceFile syntax</span></p>
<p><span style="font-size: small;">Create the -CsvReplaceFile&nbsp;so it looks like this. The top line is mandatory (and the script will err if it's not there).</span></p>
<p><span style="font-size: small;">&nbsp;</span></p>
<pre><span style="font-size: small;">"find","replace"</span></pre>
<pre><span style="font-size: small;">greiginsydney.com,contoso.com</span></pre>
<pre><span style="font-size: small;">greiginsydney.local,contoso.local</span></pre>
<pre><span style="font-size: small;">greg,Greig,Anything after a second comma is ignored</span></pre>
<pre><span style="font-size: small;">,10.10.10.0, Provide no "find" value and the script will ignore/skip the replace value in the later IP replacement code</span></pre>
<pre><span style="font-size: small;">"replace this", "with this", Wrap the text in quotes if it's to include a space or match a comma</span></pre>
<pre><span style="font-size: small;">"gre?\wg\W","Greig ", match on RegEx!!<br /></span></pre>
<pre><span style="font-size: small;">13.66.173.252,10.10.10.1</span></pre>
<pre><span style="font-size: small;">192.168.1.,10.10.1.</span></pre>
<p>&nbsp;</p>
<p><span style="font-size: medium;">Batch it?</span></p>
<pre><span style="font-size: small;">Get-ChildItem *.xml -recurse | foreach { .\New-ObfuscatedFile.ps1 -InputFile $_.Fullname -CsvReplaceFile MyReplaceFile.csv }</span></pre>
<p>&nbsp;</p>
<p><span style="font-size: small;">Please take it for a test drive and let me know if you encounter any problems with it, or have any enhancement suggestions.</span></p>
<p>&nbsp;</p>
<p><span style="font-size: medium;">Revision History</span></p>
<p><span style="font-size: small;">v1.0 - 21st August 2019.&nbsp;</span><span style="font-size: small;">This is the original release.</span></p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<p><span style="font-size: small;">- Greig.</span></p>
