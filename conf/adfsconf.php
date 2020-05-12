<?php

/**
 * Adfs Configuration.
 */
class AdfsConf {
    
    public $adfsUrl = 'https://adfsdemo2.com/adfs/ls/';
    
    public $spIdentifier = 'urn:federation:php.interop.schakra.com-adfsdemo';
    
    /**
     * PEM Certificate with Private KEY included location
     */
    
    
    protected static $_instance = NULL;

    /**
     * Prevent direct object creation
     */
    final private function  __construct() { }

    /**
     * Prevent object cloning
     */
    final private function  __clone() { }

    /**
     * Returns new or existing Singleton instance
     * @return Singleton
     */
    final public static function getInstance(){
        if(null !== self::$_instance){
            return self::$_instance;
        }
        self::$_instance = new AdfsConf();
        return self::$_instance;
    }
}
?>
