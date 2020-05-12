<?php
/**
 * Utilities
 */
include_once("SAML/Utils.php");
use SAML2\Utils as SAMLUtils;

class Utils {
	
	/**
     * Check to verify that the current time is between
     * the specified start and end boundary
     *
     * @param string $start time in SAML2 format
     * @param string $end time in SAML2 format
     * @return boolean
     */
    function checkCurrentTime($start=NULL, $end=NULL) {
        $currentTime = time();

        if (!empty($start)) {
			$startTime = SAMLUtils::xsDateTimeToTimestamp($start);
            /* Allow for a 10 minute difference in Time */
            if (($startTime < 0) || (($startTime - 600) > $currentTime)) {
              return FALSE;
            }
        }
        if (!empty($end)) {
            $endTime = SAMLUtils::xsDateTimeToTimestamp($end);
            if (($endTime < 0) || ($endTime <= $currentTime)) {
              return FALSE;
            }
        }
        return TRUE;
    }

	/**
     * Opens a file at given path location.
	 * Throws Exception if unable.
     *
     * @param string $filePath the File path to open
     * @return file content
     */
	function readFileContent($filePath) {
		$fileContent = file_get_contents($filePath);
		if($fileContent === FALSE) {
			throw new Exception('Unable to load file \'' . $filePath . '\'.');
		}
		return $fileContent;
	}
	
	/**
     * Decrypts a given SAML Token received
	 * with the given certification private key
	 * Throws Exception if unable.
     *
     * @param string $encryptionCertPath PEM certificate file containing Private Key
     * @param string $encryptionCertPassword passphrase needed to open private key
     * @param string $wresult the token to be decrypted
     * @return decrypted token
     */
	function decryptToken($encryptionCertPath, $encryptionCertPassword, $wresult) {
	
		// Load Certificate
		$encryptionCertData = Utils::readFileContent($encryptionCertPath);

		// Accommodate for MS-ADFS escaped quotes
		$wresult = str_replace('\"', '"', $wresult);
		$wresult = str_replace ("\r", "", $wresult);
    
        // Load and parse the XML.
		$dom = new DOMDocument();
		$dom->loadXML($wresult);
		$xpath = new DOMXpath($dom);
		$xpath->registerNamespace('wst', 'http://schemas.xmlsoap.org/ws/2005/02/trust');
		$xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:1.0:assertion');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
       
        // Decrypts the xmlToken if it is encrypted, using the private key specified in the configuration.
        $decryptedToken = '';
        $decryptionFailed = false;
        $rootElement = $xpath->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/xenc:EncryptedData');
        $rootElement = $rootElement->item(0);
        if (preg_match('/EncryptedData/i', $rootElement->nodeName) > 0) {
            $topNode = $rootElement->firstChild;
            if (preg_match('/EncryptionMethod/i', $topNode->nodeName) > 0) {
                if ($blockAlgorithm=$topNode->getAttribute("Algorithm") ) {
                    switch ($blockAlgorithm) {
                        case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
                            $mcrypt_mode = 'AES-256-CBC';
                            $iv_length = 16;
                            break;
                        case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
                            $mcrypt_mode = 'AES-128-CBC';
                            $iv_length = 16;
                            break;
                        default:
                            throw new Exception("Unknown encryption blockAlgorithm: ".$blockAlgorithm.".");
                            break;
                    }
                    
                    # Alg. has been determined, check to make sure an error hasn't been thrown, and proceed.
                    if($decryptionFailed == false) {
                        $topNode = $topNode->nextSibling;
                        if(preg_match('/KeyInfo/i', $topNode->nodeName) > 0) {
                            $encryptionMethods = $topNode->getElementsByTagname("EncryptionMethod");
                            $encryptionMethod = $encryptionMethods->item(0);
                            $keyWrapAlgorithm = $encryptionMethod->getAttribute("Algorithm");
                            switch ($keyWrapAlgorithm) {
                                case "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p":
                                    $ssl_padding = OPENSSL_PKCS1_OAEP_PADDING;
                                    break;
                                case "http://www.w3.org/2001/04/xmlenc#rsa-1_5":
                                    $ssl_padding = OPENSSL_NO_PADDING;
                                    break;
                                default:
                                    throw new Exception("Unrecognized keyWrapAlgorithm: ".$keyWrapAlgorithm.".");
                                    break;
                            }
                            if ($decryptionFailed == false) {
                                if ($cipherValueNodes = $topNode->getElementsByTagname("CipherValue") ) {
                                    $cipherValueNode = $cipherValueNodes->item(0);
                                    $keyWrapCipher = $cipherValueNode->nodeValue;
                                    $keyWrapCipher = base64_decode($keyWrapCipher);
                                    $private_key=openssl_pkey_get_private($encryptionCertData, $encryptionCertPassword);
                                    if (!$private_key) {
                                        throw new Exception("Unable to load private key for decryption.");
                                    } else {
                                        if (openssl_private_decrypt($keyWrapCipher, $blockCipherKey, $private_key, $ssl_padding) ) {
                                            openssl_free_key($private_key);
                                            switch ($keyWrapAlgorithm) {
                                                case "http://www.w3.org/2001/04/xmlenc#rsa-1_5":
                                                    $blockCipherKey = substr($blockCipherKey, 2);
                                                    $keystart = strpos($blockCipherKey, 0) + 1;
                                                    $blockCipherKey = substr($blockCipherKey, $keystart);
                                                    break;
                                                default:
                                                    break;
                                            }
                                            $topNode = $topNode->nextSibling;
                                            if (preg_match('/CipherData/i', $topNode->nodeName) > 0) {
                                                if (!$cipherValueNodes = $topNode->getElementsByTagname("CipherValue")) {
                                                    throw new Exception("No block cipher data found.");
                                                } else {
                                                    $cipherValueNode = $cipherValueNodes->item(0);
                                                    $blockCipher = $cipherValueNode->nodeValue;
                                                    $blockCipher = base64_decode($blockCipher);

                                                    if ($iv_length > 0) {
                                                        $mcrypt_iv = substr($blockCipher, 0, $iv_length);
                                                        $blockCipher = substr($blockCipher, $iv_length);
                                                    }
                                                    // Decrypt and get the token.
                                                    //$decryptedToken = mcrypt_decrypt($mcrypt_cipher, $blockCipherKey, $blockCipher, $mcrypt_mode, $mcrypt_iv);
                                                    $decryptedToken = openssl_decrypt($blockCipher, $mcrypt_mode, $blockCipherKey, OPENSSL_RAW_DATA, $mcrypt_iv);
                                                    if (!$decryptedToken) {
                                                        throw new Exception("Decryption of token failed.");
                                                    }
                                                }
                                            } else {
                                                throw new Exception("Unable to locate cipher data.");
                                            }
                                        } else {
                                            throw new Exception("Unable to decrypt token, check private key configuration.");
                                        }
                                    }
                                } else {
                                    throw new Exception("No wrapping cipher found.");
                                }
                            }
                        } else {
                            throw new Exception("Unable to continue, keyInfo is not present.");
                        }
                    }
                } else {
                    throw new Exception("Encryption method BlockAlgorithm not specified.");
                }
            } else {
                throw new Exception("Unable to determine Encryption method.");
            }
        } else {
            if(isset($encryptionCertData)) {
                throw new Exception("Unable to find encrypted data.");
            }
        }
		
		return $decryptedToken;
	}
}
?>
