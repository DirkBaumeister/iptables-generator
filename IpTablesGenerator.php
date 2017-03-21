<?php

class IpTablesGenerator {

    /** Name of the script for iptables file generated comments */
    const SCRIPT_NAME = "iptables-generator v1.0";

    /** Path to the iptables file with current conditions */
    const CURRENT_FILENAME = __DIR__ . "/iptables.save";

    /** Path to the iptables file with latest conditions */
    const BACKUP_FILENAME = __DIR__ . "/iptables.backup";

    /**
     * Generates the iptables data
     *
     * @return string
     */
    public static function generateIpTablesData() {

        /**
         * This is just example data. Just change it how you need it.
         */

        /** raw table */
        $lines = self::getGeneratedLine();
        $lines .= self::getTableLine('raw');
        $lines .= self::getChainHeader('PREROUTING', 'ACCEPT');
        $lines .= self::getChainHeader('OUTPUT', 'ACCEPT');
        $lines .= self::getCommit();
        $lines .= self::getCompletedLine();

        /** raw mangle */
        $lines .= self::getGeneratedLine();
        $lines .= self::getTableLine('mangle');
        $lines .= self::getChainHeader('PREROUTING', 'ACCEPT');
        $lines .= self::getChainHeader('INPUT', 'ACCEPT');
        $lines .= self::getChainHeader('FORWARD', 'ACCEPT');
        $lines .= self::getChainHeader('OUTPUT', 'ACCEPT');
        $lines .= self::getChainHeader('POSTROUTING', 'ACCEPT');
        $lines .= self::getCommit();
        $lines .= self::getCompletedLine();

        /** filter table */
        $lines .= self::getGeneratedLine();
        $lines .= self::getTableLine('filter');
        $lines .= self::getChainHeader('INPUT', 'ACCEPT');
        $lines .= self::getChainHeader('FORWARD', 'ACCEPT');
        $lines .= self::getChainHeader('OUTPUT', 'ACCEPT');
        $lines .= self::getCommit();
        $lines .= self::getCompletedLine();

        /** nat table */
        $lines .= self::getGeneratedLine();
        $lines .= self::getTableLine('nat');
        $lines .= self::getChainHeader('PREROUTING', 'ACCEPT');
        $lines .= self::getChainHeader('POSTROUTING', 'ACCEPT');
        $lines .= self::getChainHeader('OUTPUT', 'ACCEPT');

        $lines .= self::getCommit();
        $lines .= self::getCompletedLine();

        return $lines;
    }

    /**
     * ===============================================================
     * = Do not change code below unless you know what you are doing =
     * ===============================================================
     */

    /**
     * Generates the iptables current and backup file
     *
     * @return bool
     */
    public static function generateIpTablesFile() {

        $lines = self::generateIpTablesData();

        self::createCurrentFile($lines);

        if(self::getMd5OfCurrentFile() !== self::getMd5OfBackupFile()) {
            self::createBackupFile($lines);
            return true;
        }

        return false;
    }

    /**
     * Creates the iptables file with current conditions (and the backup file if it does not exist)
     *
     * @param string $content
     * @return bool
     */
    private static function createCurrentFile($content) {
        if(!file_exists(self::BACKUP_FILENAME)) {
            self::createBackupFile($content);
        }
        return self::createFile(self::CURRENT_FILENAME, $content);
    }

    /**
     * Creates the iptables file with backup conditions
     *
     * @param string $content
     * @return bool
     */
    private static function createBackupFile($content) {
        return self::createFile(self::BACKUP_FILENAME, $content);
    }

    /**
     * Creates the iptables file
     *
     * @param string $filePath
     * @param string $content
     * @return bool
     */
    private static function createFile($filePath, $content) {
        $file = fopen($filePath, 'w');
        fwrite($file, $content);
        fclose($file);

        return true;
    }

    /**
     * Gets the content of the iptables file with current conditions
     *
     * @return string
     */
    private static function getCurrentFile() {
        return file_get_contents(self::CURRENT_FILENAME);
    }

    /**
     * Gets the content of the iptables file with backup conditions
     *
     * @return string
     */
    private static function getBackupFile() {
        return file_get_contents(self::BACKUP_FILENAME);
    }

    /**
     * Gets the md5 hash of the iptables file with current conditions
     *
     * @return string
     */
    private static function getMd5OfCurrentFile() {
        return md5(self::getCurrentFile());
    }

    /**
     * Gets the md5 hash of the iptables file with backup conditions
     *
     * @return string
     */
    private static function getMd5OfBackupFile() {
        return md5(self::getBackupFile());
    }

    /**
     * Gets the generated comment line for the iptables data
     *
     * @param bool $withTimestamp
     * @return string
     */
    private static function getGeneratedLine($withTimestamp = false) {
        if($withTimestamp) {
            return self::getLine("# Generated by " . self::SCRIPT_NAME . " on " . date("D M j H:i:s Y"));
        } else {
            return self::getLine("# Generated by " . self::SCRIPT_NAME);
        }
    }

    /**
     * Gets the completed comment line for the iptables data
     *
     * @param bool $withTimestamp
     * @return string
     */
    private static function getCompletedLine($withTimestamp = false) {
        if($withTimestamp) {
            return self::getLine("# Completed on " . date("D M j H:i:s Y"));
        } else {
            return self::getLine("# Completed");
        }
    }

    /**
     * Gets the table definition line for iptables data
     *
     * @param $tableName
     * @return string
     */
    private static function getTableLine($tableName) {
        return self::getLine("*" . $tableName);
    }

    /**
     * Gets the chain header for iptables data
     *
     * @param string $chainName
     * @param string $chainPolicy
     * @param int $packetCounter
     * @param int $byteCounter
     * @return string
     */
    private static function getChainHeader($chainName, $chainPolicy, $packetCounter = 0, $byteCounter = 0) {
        return self::getLine(":" . $chainName . " " . $chainPolicy . " [" . $packetCounter . ":" . $byteCounter . "]");
    }

    /**
     * Gets the commit line for iptables data
     *
     * @return string
     */
    private static function getCommit() {
        return self::getLine("COMMIT");
    }

    /**
     * Gets an append line for iptables data
     *
     * @param string $chainName
     * @param string $appendCommand
     * @return string
     */
    private static function getAppendLine($chainName, $appendCommand) {
        return self::getLine("-A " . $chainName . " " . $appendCommand);
    }

    /**
     * Gets an insert line for iptables data
     *
     * @param string $chainName
     * @param string $insertCommand
     * @return string
     */
    private static function getInsertLine($chainName, $insertCommand) {
        return self::getLine("-I " . $chainName . " " . $insertCommand);
    }

    /**
     * Gets a delete line for iptables data
     *
     * @param string $chainName
     * @param string $deleteCommand
     * @return string
     */
    private static function getDeleteLine($chainName, $deleteCommand) {
        return self::getLine("-D " . $chainName . " " . $deleteCommand);
    }

    /**
     * Gets a line for iptables data
     *
     * @param string $command
     * @return string
     */
    private static function getLine($command) {
        return $command . "\n";
    }

}
