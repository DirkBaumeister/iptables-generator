# iptables-generator
a simple php class to generate iptables data.

## What is this?
with this class you can generate iptables data pretty easily.

## How to use
go to your document root and execute the following:
```sh
git clone https://github.com/DirkBaumeister/iptables-generator.git
cd iptables-generator
```
#####  Direct Output Mode
To use the direct out of the class just use the following syntax:
```php
<?php
include_once("IpTablesGenerator.php");
echo IpTablesGenerator::generateIpTablesData();
```
#####  File Output Mode
if you want to generate a current and backup file just do:
```php
<?php
include_once("IpTablesGenerator.php");
IpTablesGenerator::generateIpTablesFile();
```
This will create an **iptables.save** and **iptables.backup** file.

On each following call on this method the script will check if the newly generated save iptables.save file differs from the iptables.backup file and will give you either **true** if it differs or **false** if it does not. (**perfect for cronjobs who only need to run on change**) (See notice at the end for this behaviour)

#####  Customization
Now you can simple customize the **generateIpTablesData()** method in the **IpTablesGenerator** as you like. For better instance you will find an example in it.

You can use the following methods to generate the iptables data:

| Method | Example Result | What does it do |
| ------------- | ------------- | ------------- |
| self::**getGeneratedLine**($withTimestamp = false) | # Generated by iptables-generator v1.0 on {timestamp} | Gets a comment line for generation |
| self::**getCompletedLine**($withTimestamp = false) | # Completed on {timestamp} | Gets a comment line for completion |
| self::**getTableLine**($tableName) | *raw | Gets a line for table definition |
| self::**getChainHeader**($chainName, $chainPolicy, $packetCounter = 0, $byteCounter = 0) | :PREROUTING ACCEPT [0:0] | Gets a line for a chain header with its policy and optional with packet- and byte-counter |
| self::**getCommit**() | COMMIT | Gets a commit line |
| self::**getAppendLine**($chainName, $appendCommand) | -A PREROUTING {appendCommand} | Gets an append line with the name of the chain and the command of the iptables rule |
| self::**getInsertLine**($chainName, $insertCommand) | -I PREROUTING {insertCommand} | Gets an insert line with the name of the chain and the command of the iptables rule |
| self::**getDeleteLine**($chainName, $deleteCommand) | -D PREROUTING {deleteCommand} | Gets a delete line with the name of the chain and the command of the iptables rule |
| self::**getLine**($command) | - | Gets a simple line with a line-break at the end |

## How does the iptables syntax work?
A good guide can be found here: http://www.iptables.info/en/iptables-save-restore-rules.html
## What else to know?
One important thing to know is that, if you enable timestamps on the generated and completed command you will end up if with no check if the newly generated file differs from the backup file because of different timestamps. 