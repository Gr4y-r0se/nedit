# nedit.rb
### A nessus editor/parser/querior for the exasperated pentester. 
NB: Nothing to do with NEdit, the open source text editor - but the name was too good to pass up.

<pre><code>░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 
░░░░░░░░░╔═╦╗░░╔╦╦╗░░░░░░░░░░  
░░░░░░░░░║║║╠═╦╝╠╣╚╗░░░░░░░░░ 
░░░░░░░░░║║║║╩╣╬║║╔╣░░░░░░░░░ 
░░░░░░░░░╚╩═╩═╩═╩╩═╝░░░░░░░░░ 
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 
Nedit - The nessus file editor and processor
</code></pre>

## Who is Nedit for?

This tool was built in order to help PenTesters work with Nessus files. Stripping out informational findings, removing vulns alltogether or exporting to CSV nicely - it's all part of Nedit.

However, the blue side of the aisle may find this useful as well! Spreadsheet output makes reporting easier, and the edit mode means you can pass the audit even if a scan has been marked uneditable ;).

## How to use

<img src='./images/help_updated.png'>

The help pages (-h or --help) give all the details needed to properly utilise this tool.

## Flag - CSV

The CSV flag transforms your nessus file into a workable spreadsheet. Better yet, it'll now automatically detect if compliance checks have been ran, and create a separate spreadsheet for them as well!

## Flag - Scope

To use the scope functionality, load burp, navigate to the Targets tab, then Scope, then click on the cog icon and finally 'Load Options'. This will allow you to import the scope file properly.

## To install all required modules, run the following command after git cloning:

<pre><code>bundle install
</code></pre>



