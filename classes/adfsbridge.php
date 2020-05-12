<?php
/**
 * Handles the ADFS SignIn/SignOut/PRP handling.
 *  
 * @license http://www.gnu.org/licenses/gpl-2.0.html
 */
include_once("classes/utils.php");

class AdfsBridge {

	function getAdfsSignInResponse($adfsConf, $wa, $wresult, $wctx) {        
	
		$decryptedToken = Utils::decryptToken($adfsConf->encryptionCertPath,
									          $adfsConf->encryptionCertPassword,
									          $wresult);

        // Get saml:Assertion element
        if ($decryptedToken != '') {
            $decryptedToken_dom = new DOMDocument();
            $decryptedToken = str_replace('\"', '"', $decryptedToken);
            $decryptedToken = str_replace ("\r", "", $decryptedToken);   
            $xml_end_index = strrpos($decryptedToken, ">");
            $decryptedToken = substr($decryptedToken, 0, $xml_end_index + 1);
            $decryptedToken_dom->loadXML($decryptedToken);

            // Change the Xpath.
            $xpath = new DOMXpath($decryptedToken_dom);
            $xpath->registerNamespace('wst', 'http://schemas.xmlsoap.org/ws/2005/02/trust');
            $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:1.0:assertion');
            $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
            $assertion = $decryptedToken_dom->documentElement;
        } else {
            // Find the saml:Assertion element in the response.
            $assertions = $xpath->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion');
            if ($assertions->length === 0) {
                throw new Exception('Received an ADFS response without an assertion.');
            }
            if ($assertions->length > 1) {
                throw new Exception('The WS-Fed PRP handler currently only supports a single assertion in a response.');
            }
            $assertion = $assertions->item(0);    
        }
        
		// Check time constraints of contitions (if present).
		foreach($xpath->query('./saml:Conditions', $assertion) as $condition) {
            $notBefore = $condition->getAttribute('NotBefore');
            $notOnOrAfter = $condition->getAttribute('NotOnOrAfter');
            if(!Utils::checkCurrentTime($notBefore, $notOnOrAfter)) {
                throw new Exception('The WS-Fed response has expired.');
            }
		}

        // Create the user details response object.
		$userDetails = array();

		// Extract the name identifier from the response.
		$nameid = $xpath->query('./saml:AuthenticationStatement/saml:Subject/saml:NameIdentifier', $assertion);
		if ($nameid->length === 0) {
            throw new Exception('Could not find the name identifier in the response from the WS-Fed.');
		}
       $userDetails['nameIdentifier'] = $nameid->item(0)->textContent;
       $userDetails['nameIdentifierFormat'] = $nameid->item(0)->getAttribute('Format');

		// Extract the attributes from the response.
		$userDetails['attributes'] = array();
		$attributeValues = $xpath->query('./saml:AttributeStatement/saml:Attribute/saml:AttributeValue', $assertion);
		foreach($attributeValues as $attribute) {
            $name = $attribute->parentNode->getAttribute('AttributeName');
            $value = $attribute->textContent;
            if(!array_key_exists($name, $userDetails['attributes'])) {
                $userDetails['attributes'][$name] = array();
            }
            array_push($userDetails['attributes'][$name], $value);
		}

        return $userDetails;
    }
}
?>
